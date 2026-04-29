"""Kentik BGP Monitoring → Google Chronicle SecOps Integration.

Polls the Kentik BGP Monitoring API for reachability and path-change metrics
across all active monitors, converts each data point into a Chronicle UDM
event (NETWORK_UNCATEGORIZED), and ingests them into Google SecOps.

BGP hijacking and route-leak events are a recognised attack vector. This
integration surfaces those signals directly in Chronicle where they can be
correlated with other security events and drive YARA-L detections.

Credentials (all via environment variables):
  Kentik:
    KENTIK_API_EMAIL      - your Kentik account email
    KENTIK_API_TOKEN      - your Kentik API token

  Chronicle / SecOps (choose one auth method):
    GOOGLE_APPLICATION_CREDENTIALS - path to a GCP service account JSON key
      OR: run `gcloud auth application-default login` beforehand

  Chronicle instance:
    CHRONICLE_CUSTOMER_ID - your Chronicle instance ID (UUID)
    CHRONICLE_PROJECT_ID  - your GCP project ID
    CHRONICLE_REGION      - Chronicle API region, e.g. "us" (default: "us")

Usage:
    # Sync last hour of BGP metrics
    python bgp_to_chronicle.py

    # Sync last 6 hours
    python bgp_to_chronicle.py --hours 6

    # Incremental + daemon mode (recommended for production)
    python bgp_to_chronicle.py --daemon --interval 300 \
        --state-file /var/lib/kentik_bgp_state.json

    # Reachability threshold: only emit events when reachability < N %
    python bgp_to_chronicle.py --reachability-threshold 90

    # Dry run — print UDM events without ingesting
    python bgp_to_chronicle.py --dry-run
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from kentik_api import KentikClient
from secops import SecOpsClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# Chronicle metric types → readable names
_METRIC_LABELS = {
    "BGP_METRIC_TYPE_REACHABILITY": "BGP_REACHABILITY",
    "BGP_METRIC_TYPE_PATH_CHANGES": "BGP_PATH_CHANGES",
    1: "BGP_REACHABILITY",
    2: "BGP_PATH_CHANGES",
}

# RPKI status → human label
_RPKI_LABELS = {
    "RPKI_STATUS_UNKNOWN": "Unknown",
    "RPKI_STATUS_VALID": "Valid",
    "RPKI_STATUS_INVALID": "Invalid",
    "RPKI_STATUS_NOT_FOUND": "NotFound",
    0: "Unknown",
    1: "Valid",
    2: "Invalid",
    3: "NotFound",
}


def _ts_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_z(ts: str | None) -> str:
    if not ts:
        return _ts_now_z()
    if ts.endswith("Z"):
        return ts
    if ts.endswith("+00:00"):
        return ts[:-6] + "Z"
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ts + "Z"


def _extract_prefix(nlri: dict) -> str:
    """Extract a human-readable CIDR string from an Nlri dict."""
    if not nlri:
        return ""
    # Format: {"afi": "...", "value": {"prefix": "10.0.0.0/24"}} or a flat {"prefix": "..."}
    if "value" in nlri and isinstance(nlri["value"], dict):
        return nlri["value"].get("prefix", "")
    if "prefix" in nlri:
        return nlri["prefix"]
    # Fallback: join all string values
    return str(nlri)


def _reachability_severity(value: float, threshold: float) -> str:
    """Map a reachability percentage to UDM severity."""
    if value < threshold * 0.5:
        return "CRITICAL"
    if value < threshold * 0.75:
        return "HIGH"
    if value < threshold:
        return "MEDIUM"
    return "INFORMATIONAL"


def metric_to_udm(
    metric: dict,
    monitor_name: str,
    monitor_id: str,
    reachability_threshold: float,
) -> dict:
    """Convert a raw BgpMetric dict to a Chronicle UDM event."""
    metric_ts = metric.get("timestamp") or _ts_now_z()
    nlri = metric.get("nlri") or {}
    prefix = _extract_prefix(nlri)
    raw_type = metric.get("metricType") or metric.get("metric_type") or ""
    metric_label = _METRIC_LABELS.get(raw_type, str(raw_type))
    value = float(metric.get("value") or 0)

    # Severity
    if metric_label == "BGP_REACHABILITY":
        severity = _reachability_severity(value, reachability_threshold)
    else:
        # PATH_CHANGES: > 10 = MEDIUM, > 50 = HIGH, > 200 = CRITICAL
        if value > 200:
            severity = "CRITICAL"
        elif value > 50:
            severity = "HIGH"
        elif value > 10:
            severity = "MEDIUM"
        else:
            severity = "INFORMATIONAL"

    description = (
        f"Kentik BGP {metric_label}: prefix={prefix or 'unknown'} "
        f"value={value:.2f} monitor={monitor_name}"
    )

    return {
        "metadata": {
            "id": str(uuid.uuid4()),
            "event_timestamp": _to_z(metric_ts),
            "event_type": "NETWORK_UNCATEGORIZED",
            "vendor_name": "Kentik",
            "product_name": "Kentik BGP Monitoring",
            "product_event_type": metric_label,
            "description": description,
            "ingestion_labels": [{"key": "source", "value": "kentik-bgp-monitoring"}],
        },
        "target": {
            "resource": {
                "name": prefix,
                "resource_type": "IP_RANGE",
                "attribute": {
                    "labels": [
                        {"key": "afi", "value": str(nlri.get("afi", ""))},
                    ]
                },
            }
        },
        "security_result": [
            {
                "severity": severity,
                "summary": description,
                "rule_labels": [
                    {"key": "metric_type", "value": metric_label},
                    {"key": "metric_value", "value": f"{value:.4f}"},
                    {"key": "reachability_threshold", "value": str(reachability_threshold)},
                ],
            }
        ],
        "additional": {
            "fields": [
                {"key": "kentik_monitor_id", "value": {"string_value": monitor_id}},
                {"key": "kentik_monitor_name", "value": {"string_value": monitor_name}},
                {"key": "bgp_prefix", "value": {"string_value": prefix}},
                {"key": "bgp_metric_type", "value": {"string_value": metric_label}},
                {"key": "bgp_metric_value", "value": {"string_value": f"{value:.4f}"}},
            ]
        },
    }


def route_to_udm(route: dict, monitor_name: str, monitor_id: str) -> dict:
    """Convert a raw RouteInfo dict to a Chronicle UDM event."""
    nlri = route.get("nlri") or {}
    prefix = _extract_prefix(nlri)
    origin_asn = route.get("originAsn") or route.get("origin_asn") or 0
    as_path = route.get("asPath") or route.get("as_path") or []
    nexthop = route.get("nexthop") or ""
    rpki_raw = route.get("rpkiStatus") or route.get("rpki_status") or ""
    rpki_label = _RPKI_LABELS.get(rpki_raw, str(rpki_raw))

    # A route with RPKI_INVALID is a high-severity signal
    if rpki_raw in ("RPKI_STATUS_INVALID", 2):
        severity = "HIGH"
    elif rpki_raw in ("RPKI_STATUS_NOT_FOUND", 3):
        severity = "LOW"
    else:
        severity = "INFORMATIONAL"

    description = (
        f"Kentik BGP route snapshot: prefix={prefix} origin_asn={origin_asn} "
        f"rpki={rpki_label} monitor={monitor_name}"
    )

    fields = [
        {"key": "kentik_monitor_id", "value": {"string_value": monitor_id}},
        {"key": "kentik_monitor_name", "value": {"string_value": monitor_name}},
        {"key": "bgp_prefix", "value": {"string_value": prefix}},
        {"key": "bgp_origin_asn", "value": {"string_value": str(origin_asn)}},
        {"key": "bgp_nexthop", "value": {"string_value": nexthop}},
        {"key": "bgp_rpki_status", "value": {"string_value": rpki_label}},
    ]
    if as_path:
        fields.append({"key": "bgp_as_path", "value": {"string_value": " ".join(str(a) for a in as_path)}})

    return {
        "metadata": {
            "id": str(uuid.uuid4()),
            "event_timestamp": _ts_now_z(),
            "event_type": "NETWORK_UNCATEGORIZED",
            "vendor_name": "Kentik",
            "product_name": "Kentik BGP Monitoring",
            "product_event_type": "BGP_ROUTE_SNAPSHOT",
            "description": description,
            "ingestion_labels": [{"key": "source", "value": "kentik-bgp-monitoring"}],
        },
        "target": {
            "resource": {
                "name": prefix,
                "resource_type": "IP_RANGE",
            },
            "ip": [nexthop] if nexthop else [],
        },
        "network": {
            "asn": int(origin_asn) if origin_asn else None,
        },
        "security_result": [
            {
                "severity": severity,
                "summary": description,
                "rule_labels": [
                    {"key": "rpki_status", "value": rpki_label},
                    {"key": "origin_asn", "value": str(origin_asn)},
                ],
            }
        ],
        "additional": {"fields": fields},
    }


# ── State file ──

class SyncState:
    def __init__(self, path: str | None) -> None:
        self._path = Path(path) if path else None
        self._data: dict[str, Any] = {}
        if self._path and self._path.exists():
            try:
                self._data = json.loads(self._path.read_text())
            except Exception as exc:
                log.warning("Could not read state file %s: %s", self._path, exc)

    @property
    def last_synced(self) -> datetime | None:
        ts = self._data.get("last_synced_utc")
        if ts:
            try:
                return datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return None

    def update(self, synced_at: datetime) -> None:
        self._data["last_synced_utc"] = synced_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        if self._path:
            try:
                self._path.write_text(json.dumps(self._data, indent=2))
            except Exception as exc:
                log.warning("Could not write state file: %s", exc)


# ── Chronicle client ──

def _get_chronicle() -> Any:
    customer_id = os.environ.get("CHRONICLE_CUSTOMER_ID", "")
    project_id = os.environ.get("CHRONICLE_PROJECT_ID", "")
    region = os.environ.get("CHRONICLE_REGION", "us")
    if not customer_id or not project_id:
        log.error("CHRONICLE_CUSTOMER_ID and CHRONICLE_PROJECT_ID must be set.")
        sys.exit(1)
    return SecOpsClient().chronicle(
        customer_id=customer_id, project_id=project_id, region=region
    )


# ── Main sync ──

def sync_once(
    *,
    since: datetime,
    until: datetime,
    reachability_threshold: float,
    include_routes: bool,
    dry_run: bool,
) -> None:
    start_z = since.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_z = until.strftime("%Y-%m-%dT%H:%M:%SZ")

    log.info(
        "Fetching BGP metrics  since=%s  until=%s  threshold=%.1f%%",
        start_z, end_z, reachability_threshold,
    )

    chronicle = None if dry_run else _get_chronicle()
    total_events = 0

    with KentikClient() as kentik:
        monitors = kentik.bgp_monitoring.list()
        log.info("Found %d BGP monitors", len(monitors))

        for monitor in monitors:
            monitor_id = str(monitor.id or "")
            monitor_name = monitor.name or monitor_id
            targets = monitor.targets or []

            if not targets:
                log.debug("Monitor %s has no targets, skipping", monitor_name)
                continue

            for target in targets:
                prefix = _extract_prefix(target) if isinstance(target, dict) else str(target)
                log.debug("  Monitor=%s  prefix=%s", monitor_name, prefix)

                udm_events: list[dict] = []

                # ── Metrics ──
                try:
                    result = kentik.bgp_monitoring.get_metrics(
                        start_time=start_z,
                        end_time=end_z,
                        target=target,
                        metrics=[
                            "BGP_METRIC_TYPE_REACHABILITY",
                            "BGP_METRIC_TYPE_PATH_CHANGES",
                        ],
                    )
                    metrics = result.get("metrics") or []
                    log.debug("    %d metric points", len(metrics))
                    for m in metrics:
                        try:
                            udm_events.append(
                                metric_to_udm(m, monitor_name, monitor_id, reachability_threshold)
                            )
                        except Exception as exc:
                            log.warning("Failed to convert metric: %s", exc)
                except Exception as exc:
                    log.warning("Failed to fetch metrics for %s/%s: %s", monitor_name, prefix, exc)

                # ── Routes (snapshot at end of window) ──
                if include_routes:
                    try:
                        result = kentik.bgp_monitoring.get_routes(
                            start_time=end_z,
                            end_time=end_z,
                            target=target,
                        )
                        routes = result.get("routes") or []
                        for r in routes:
                            try:
                                udm_events.append(route_to_udm(r, monitor_name, monitor_id))
                            except Exception as exc:
                                log.warning("Failed to convert route: %s", exc)
                    except Exception as exc:
                        log.warning("Failed to fetch routes for %s/%s: %s", monitor_name, prefix, exc)

                if not udm_events:
                    continue

                if dry_run:
                    print(json.dumps(udm_events, indent=2))
                    log.info("[DRY RUN] Would ingest %d events for %s/%s", len(udm_events), monitor_name, prefix)
                else:
                    try:
                        chronicle.ingest_udm(udm_events=udm_events)
                        log.info("  Ingested %d events for %s/%s", len(udm_events), monitor_name, prefix)
                    except Exception as exc:
                        log.error("Chronicle ingestion failed for %s/%s: %s", monitor_name, prefix, exc)
                        raise

                total_events += len(udm_events)

    log.info("BGP sync complete. Total UDM events: %d", total_events)


# ── CLI ──

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sync Kentik BGP Monitoring metrics to Google Chronicle SecOps",
    )
    p.add_argument("--hours", type=float, default=1.0,
                   help="Look-back window in hours (default: 1). Overridden by --state-file.")
    p.add_argument("--reachability-threshold", type=float, default=80.0, metavar="PCT",
                   help="Reachability %% below which a MEDIUM severity event is emitted (default: 80)")
    p.add_argument("--include-routes", action="store_true",
                   help="Also ingest route snapshots (prefix, origin ASN, AS path, RPKI status)")
    p.add_argument("--state-file", default=None, metavar="PATH",
                   help="JSON file to persist the last-synced timestamp for incremental runs.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print UDM events as JSON; skip Chronicle ingestion.")
    p.add_argument("--daemon", action="store_true",
                   help="Run continuously, polling on --interval seconds.")
    p.add_argument("--interval", type=int, default=300,
                   help="Poll interval in seconds for --daemon mode (default: 300).")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    logging.getLogger().setLevel(args.log_level)
    sync_state = SyncState(args.state_file)

    def _run_once() -> None:
        now = datetime.now(timezone.utc)
        since = sync_state.last_synced or (now - timedelta(hours=args.hours))
        try:
            sync_once(
                since=since,
                until=now,
                reachability_threshold=args.reachability_threshold,
                include_routes=args.include_routes,
                dry_run=args.dry_run,
            )
            sync_state.update(now)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            log.error("Sync failed: %s", exc, exc_info=args.log_level == "DEBUG")

    if args.daemon:
        log.info("Starting daemon mode (interval=%ds)", args.interval)
        while True:
            try:
                _run_once()
            except KeyboardInterrupt:
                log.info("Interrupted; exiting.")
                break
            log.info("Sleeping %d seconds ...", args.interval)
            time.sleep(args.interval)
    else:
        _run_once()


if __name__ == "__main__":
    main()
