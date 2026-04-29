"""Kentik Alerting → Google Chronicle SecOps Integration.

Polls the Kentik Alerting API for active/recent alerts, converts each alert
to a Chronicle UDM event, and ingests them into Google SecOps via the
Chronicle Ingestion API.

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
    # One-shot: sync alerts from the last hour
    python kentik_to_chronicle.py

    # Sync alerts from the last N hours
    python kentik_to_chronicle.py --hours 4

    # Continuous polling every 5 minutes
    python kentik_to_chronicle.py --daemon --interval 300

    # Only active alerts
    python kentik_to_chronicle.py --state active

    # Use a state file to track what's been ingested (incremental mode)
    python kentik_to_chronicle.py --state-file /var/lib/kentik_chronicle_state.json

    # Dry run — print UDM events without ingesting
    python kentik_to_chronicle.py --dry-run
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

# ── Kentik SDK ──
from kentik_api import KentikClient
from kentik_api.models.alerting import Alert

# ── SecOps SDK ──
from secops import SecOpsClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# Chronicle log type used for Kentik alerts.
KENTIK_LOG_TYPE = "GENERIC_EVENT"

# ── Severity mappings ──
_SEVERITY_MAP: dict[str, str] = {
    "SEVERITY_CRITICAL": "CRITICAL",
    "SEVERITY_SEVERE": "HIGH",
    "SEVERITY_MAJOR": "HIGH",
    "SEVERITY_WARNING": "MEDIUM",
    "SEVERITY_MINOR": "LOW",
    "SEVERITY_CLEAR": "INFORMATIONAL",
    "SEVERITY_UNSPECIFIED": "SEVERITY_UNKNOWN",
}

# ── Alert state → UDM security result action ──
_STATE_MAP: dict[str, str] = {
    "ALERT_STATE_ACTIVE": "ALERTING",
    "ALERT_STATE_CLEAR": "NO_ACTION",
    "ALERT_STATE_UNSPECIFIED": "UNKNOWN_ACTION",
}


# ── UDM Conversion ──

def _severity_to_udm(kentik_severity: str) -> str:
    """Map a Kentik severity string to a UDM severity string."""
    return _SEVERITY_MAP.get(kentik_severity, "SEVERITY_UNKNOWN")


def _parse_timestamp(ts: str | None) -> str:
    """Return *ts* as a UTC ISO-8601 string ending in 'Z', or now if empty."""
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Normalise to a UTC ISO-8601 string ending in 'Z'
    if ts.endswith("Z"):
        return ts
    if ts.endswith("+00:00"):
        return ts[:-6] + "Z"
    # Attempt to parse and re-format
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return ts + "Z"


def _build_flow_network(flow: Any) -> dict:
    """Extract network fields from a FlowContext, if present."""
    network: dict[str, Any] = {}
    details = getattr(flow, "alert_key_details", None) or {}
    if isinstance(details, dict):
        if src_ip := details.get("src_ip") or details.get("srcIp"):
            network["source_ip"] = src_ip
        if dst_ip := details.get("dst_ip") or details.get("dstIp"):
            network["destination_ip"] = dst_ip
        if proto := details.get("proto") or details.get("protocol"):
            network["ip_protocol"] = str(proto).upper()
    return network


def alert_to_udm(alert: Alert) -> dict:
    """Convert a Kentik Alert object to a Chronicle UDM event dict.

    The UDM schema reference:
    https://cloud.google.com/chronicle/docs/reference/udm-field-list
    """
    alert_id = alert.id or str(uuid.uuid4())
    event_ts = _parse_timestamp(alert.start_time_at or alert.event_start_time_at)

    # --- security_result ---
    udm_severity = _severity_to_udm(alert.severity)
    alert_state_str = _STATE_MAP.get(alert.state, "UNKNOWN_ACTION")

    policy_type = ""
    policy_id = ""
    if alert.source:
        policy_type = alert.source.policy_type or ""
        policy_id = alert.source.id or ""

    summary_parts = [f"Kentik alert {alert_id}"]
    if policy_type:
        summary_parts.append(f"policy_type={policy_type}")
    if alert.severity and alert.severity != "SEVERITY_UNSPECIFIED":
        summary_parts.append(f"severity={alert.severity}")
    if alert.state:
        summary_parts.append(f"state={alert.state}")
    summary = " | ".join(summary_parts)

    security_result: dict[str, Any] = {
        "severity": udm_severity,
        "severity_details": alert.severity,
        "alert_state": alert_state_str,
        "summary": summary,
    }

    if alert.acknowledgement:
        ack_state = getattr(alert.acknowledgement, "state", "")
        if ack_state:
            security_result["rule_labels"] = [
                {"key": "ack_state", "value": ack_state}
            ]

    # --- additional.fields (extra Kentik context) ---
    additional_fields: list[dict] = [
        {"key": "kentik_alert_id", "value": {"string_value": alert_id}},
        {"key": "kentik_policy_type", "value": {"string_value": policy_type}},
        {"key": "kentik_policy_id", "value": {"string_value": policy_id}},
        {"key": "kentik_alert_state", "value": {"string_value": alert.state or ""}},
        {"key": "kentik_severity", "value": {"string_value": alert.severity or ""}},
        {"key": "kentik_highest_severity", "value": {"string_value": alert.highest_severity or ""}},
    ]

    if alert.end_time_at:
        additional_fields.append(
            {"key": "kentik_end_time", "value": {"string_value": _parse_timestamp(alert.end_time_at)}}
        )

    # Flow context details
    if alert.flow:
        flow = alert.flow
        for mv in getattr(flow, "metric_values", []) or []:
            name = getattr(mv, "name", None)
            value = getattr(mv, "value", None)
            if name:
                additional_fields.append(
                    {"key": f"flow_{name}", "value": {"string_value": str(value)}}
                )
        if getattr(flow, "baseline_value", None):
            additional_fields.append(
                {"key": "flow_baseline", "value": {"string_value": str(flow.baseline_value)}}
            )

    # NMS context details
    if alert.nms:
        nms = alert.nms
        device = getattr(nms, "device", None) or {}
        if isinstance(device, dict):
            if dev_name := device.get("name") or device.get("deviceName"):
                additional_fields.append(
                    {"key": "nms_device_name", "value": {"string_value": dev_name}}
                )
            if dev_id := device.get("id") or device.get("deviceId"):
                additional_fields.append(
                    {"key": "nms_device_id", "value": {"string_value": str(dev_id)}}
                )

    # --- Determine event_type ---
    # Use NETWORK_CONNECTION for traffic/flow policies, GENERIC_EVENT otherwise
    if policy_type in ("POLICY_TYPE_TRAFFIC", "POLICY_TYPE_CLOUD") and alert.flow:
        event_type = "NETWORK_CONNECTION"
    else:
        event_type = "GENERIC_EVENT"

    # --- Assemble the UDM event ---
    udm_event: dict[str, Any] = {
        "metadata": {
            "id": alert_id,
            "event_timestamp": event_ts,
            "event_type": event_type,
            "vendor_name": "Kentik",
            "product_name": "Kentik Network Observability",
            "product_event_type": policy_type or "ALERT",
            "description": summary,
            "ingestion_labels": [
                {"key": "source", "value": "kentik-alerting"},
            ],
        },
        "security_result": [security_result],
        "additional": {"fields": additional_fields},
    }

    # Add network context for flow alerts
    if alert.flow:
        network_fields = _build_flow_network(alert.flow)
        if network_fields:
            udm_event["network"] = network_fields

    return udm_event


# ── State file (incremental sync) ──

class SyncState:
    """Persists the last-synced timestamp to a JSON file for incremental runs."""

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
                log.warning("Could not write state file %s: %s", self._path, exc)


# ── Main sync logic ──

def _get_chronicle_client() -> Any:
    """Build and return a configured Chronicle client."""
    customer_id = os.environ.get("CHRONICLE_CUSTOMER_ID", "")
    project_id = os.environ.get("CHRONICLE_PROJECT_ID", "")
    region = os.environ.get("CHRONICLE_REGION", "us")

    if not customer_id or not project_id:
        log.error(
            "CHRONICLE_CUSTOMER_ID and CHRONICLE_PROJECT_ID must be set."
        )
        sys.exit(1)

    secops_client = SecOpsClient()
    return secops_client.chronicle(
        customer_id=customer_id,
        project_id=project_id,
        region=region,
    )


def sync_once(
    *,
    since: datetime,
    until: datetime,
    states: list[str] | None,
    dry_run: bool,
    batch_size: int,
) -> int:
    """Fetch Kentik alerts and ingest them into Chronicle.

    Returns the number of alerts processed.
    """
    filters: dict[str, Any] = {
        "started_at": {
            "start": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end": until.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    }
    if states:
        filters["states"] = states

    log.info(
        "Fetching Kentik alerts  since=%s  until=%s  states=%s",
        since.isoformat(),
        until.isoformat(),
        states or "all",
    )

    chronicle = None if dry_run else _get_chronicle_client()

    total_processed = 0
    offset = 0

    with KentikClient() as kentik:
        while True:
            alerts = kentik.alerting.list(
                filters=filters,
                pagination={"limit": batch_size, "offset": offset},
                sorting={"fields": [{"by": "BY_START_TIME", "order": "ORDER_ASCENDING"}]},
            )

            if not alerts:
                break

            log.info("  Fetched %d alerts (offset=%d)", len(alerts), offset)

            # Convert to UDM
            udm_events: list[dict] = []
            for alert in alerts:
                try:
                    udm_events.append(alert_to_udm(alert))
                except Exception as exc:
                    log.warning("Failed to convert alert %s to UDM: %s", alert.id, exc)

            if udm_events:
                if dry_run:
                    print(json.dumps(udm_events, indent=2))
                    log.info("  [DRY RUN] Would ingest %d UDM events", len(udm_events))
                else:
                    try:
                        # Chronicle ingest_udm accepts a list of UDM event dicts
                        chronicle.ingest_udm(udm_events=udm_events)
                        log.info("  Ingested %d UDM events into Chronicle", len(udm_events))
                    except Exception as exc:
                        log.error("Chronicle ingestion failed: %s", exc)
                        raise

            total_processed += len(alerts)

            if len(alerts) < batch_size:
                break
            offset += batch_size

    log.info("Sync complete. Total alerts processed: %d", total_processed)
    return total_processed


# ── CLI ──

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sync Kentik alerts to Google Chronicle SecOps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--hours",
        type=float,
        default=1.0,
        help="Look back this many hours for alerts (default: 1). "
             "Overridden by --state-file on subsequent runs.",
    )
    p.add_argument(
        "--state",
        choices=["active", "clear", "all"],
        default="all",
        help="Filter by alert state (default: all)",
    )
    p.add_argument(
        "--state-file",
        default=None,
        metavar="PATH",
        help="JSON file to persist the last-synced timestamp for incremental runs.",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Alerts per API page (default: 100)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Print UDM events as JSON; do not ingest into Chronicle.",
    )
    p.add_argument(
        "--daemon",
        action="store_true",
        help="Run continuously, polling on --interval seconds.",
    )
    p.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Poll interval in seconds for --daemon mode (default: 300).",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    logging.getLogger().setLevel(args.log_level)

    state_map = {
        "active": ["ALERT_STATE_ACTIVE"],
        "clear": ["ALERT_STATE_CLEAR"],
        "all": None,
    }
    states = state_map[args.state]
    sync_state = SyncState(args.state_file)

    def _run_once() -> None:
        now = datetime.now(timezone.utc)

        # Determine the look-back window
        if sync_state.last_synced:
            since = sync_state.last_synced
            log.info("Resuming from last synced time: %s", since.isoformat())
        else:
            since = now - timedelta(hours=args.hours)

        try:
            sync_once(
                since=since,
                until=now,
                states=states,
                dry_run=args.dry_run,
                batch_size=args.batch_size,
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
            log.info("Sleeping %d seconds until next poll ...", args.interval)
            time.sleep(args.interval)
    else:
        _run_once()


if __name__ == "__main__":
    main()
