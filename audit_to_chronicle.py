"""Kentik Audit Log → Google Chronicle SecOps Integration.

Fetches Kentik API audit events (every API call made against the Kentik
portal — user, IP, HTTP method, path, timestamp) and ingests them into
Google Chronicle as UDM USER_RESOURCE_ACCESS events.

Use case: detect insider threats, credential compromise, and unauthorized
configuration changes (e.g., someone disabling a BGP monitor, deleting a
device, or modifying alerting policies at an unexpected time or from an
unexpected IP).

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
    # One-shot: sync all available audit events
    python audit_to_chronicle.py

    # Incremental + daemon mode (recommended for production)
    python audit_to_chronicle.py --daemon --interval 600 \
        --state-file /var/lib/kentik_audit_state.json

    # Only emit events for write operations (POST, PUT, PATCH, DELETE)
    python audit_to_chronicle.py --writes-only

    # Dry run — print UDM events without ingesting
    python audit_to_chronicle.py --dry-run
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
from kentik_api.models.audit import AuditEvent
from secops import SecOpsClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# HTTP methods considered write operations
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# High-risk API paths — elevate severity when matched
_HIGH_RISK_PATTERNS = (
    "/alerts/",
    "/suppression",
    "/silence",
    "/ack",
    "/policies/",
    "/devices/",
    "/users/",
    "/credentials",
    "/vault",
    "/notification",
)


def _ts_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ctime_to_z(ctime: str | None) -> str:
    """Normalise a Kentik ctime string to UTC ISO-8601 with Z suffix."""
    if not ctime:
        return _ts_now_z()
    try:
        # ctime is typically a Unix epoch milliseconds string or ISO-8601
        ts_ms = int(ctime)
        dt = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        pass
    try:
        dt = datetime.fromisoformat(ctime.rstrip("Z"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return _ts_now_z()


def _ctime_to_dt(ctime: str | None) -> datetime | None:
    """Convert a ctime string to a timezone-aware datetime, or None."""
    if not ctime:
        return None
    try:
        ts_ms = int(ctime)
        return datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
    except (ValueError, TypeError):
        pass
    try:
        dt = datetime.fromisoformat(ctime.rstrip("Z"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    except ValueError:
        return None


def _severity_for_event(event: AuditEvent) -> str:
    """Derive a UDM severity from the HTTP method and API path."""
    method = (event.api_method or "").upper()
    path = event.api_path or ""

    if method == "DELETE":
        return "HIGH"

    is_write = method in _WRITE_METHODS
    is_sensitive = any(pat in path for pat in _HIGH_RISK_PATTERNS)

    if is_write and is_sensitive:
        return "MEDIUM"
    if is_write:
        return "LOW"
    return "INFORMATIONAL"


def audit_event_to_udm(event: AuditEvent) -> dict:
    """Convert a Kentik AuditEvent to a Chronicle UDM event dict."""
    event_id = event.id or str(uuid.uuid4())
    event_ts = _ctime_to_z(event.ctime)
    method = (event.api_method or "GET").upper()
    path = event.api_path or ""
    user_id = event.user_id or event.kentik_user_id or ""
    ip = event.ip_address or ""

    description = f"Kentik API {method} {path} by user={user_id or 'unknown'} from ip={ip or 'unknown'}"
    severity = _severity_for_event(event)

    # HTTP method → UDM verb
    http_verb_map = {
        "GET": "READ",
        "POST": "CREATE",
        "PUT": "UPDATE",
        "PATCH": "UPDATE",
        "DELETE": "DELETE",
    }
    verb = http_verb_map.get(method, "VIEW")

    udm_event: dict[str, Any] = {
        "metadata": {
            "id": event_id,
            "event_timestamp": event_ts,
            "event_type": "USER_RESOURCE_ACCESS",
            "vendor_name": "Kentik",
            "product_name": "Kentik Network Observability Platform",
            "product_event_type": f"AUDIT_{method}",
            "description": description,
            "ingestion_labels": [{"key": "source", "value": "kentik-audit"}],
        },
        "principal": {
            "user": {
                "userid": user_id,
            },
        },
        "target": {
            "resource": {
                "name": path,
                "resource_type": "API_ENDPOINT",
                "attribute": {
                    "labels": [
                        {"key": "http_method", "value": method},
                        {"key": "authority", "value": event.authority or ""},
                    ]
                },
            }
        },
        "security_result": [
            {
                "severity": severity,
                "summary": description,
                "rule_labels": [
                    {"key": "http_method", "value": method},
                    {"key": "verb", "value": verb},
                ],
            }
        ],
        "additional": {
            "fields": [
                {"key": "kentik_event_id", "value": {"string_value": event_id}},
                {"key": "kentik_user_id", "value": {"string_value": user_id}},
                {"key": "kentik_user_id_v2", "value": {"string_value": event.kentik_user_id or ""}},
                {"key": "api_method", "value": {"string_value": method}},
                {"key": "api_path", "value": {"string_value": path}},
                {"key": "authority", "value": {"string_value": event.authority or ""}},
            ]
        },
    }

    # Add source IP to both principal and network
    if ip:
        udm_event["principal"]["ip"] = [ip]
        udm_event["network"] = {"http": {"method": method}}

    return udm_event


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
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    @property
    def last_event_id(self) -> str:
        return self._data.get("last_event_id", "")

    def update(self, synced_at: datetime, last_id: str = "") -> None:
        self._data["last_synced_utc"] = synced_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        if last_id:
            self._data["last_event_id"] = last_id
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
    since: datetime | None,
    writes_only: bool,
    batch_size: int,
    dry_run: bool,
    last_event_id: str,
) -> tuple[int, str]:
    """Fetch Kentik audit events and ingest into Chronicle.

    Returns (total_processed, last_ingested_event_id).
    """
    log.info(
        "Fetching Kentik audit events  since=%s  writes_only=%s",
        since.isoformat() if since else "beginning",
        writes_only,
    )

    chronicle = None if dry_run else _get_chronicle()
    total = 0
    new_last_id = last_event_id

    with KentikClient() as kentik:
        events: list[AuditEvent] = kentik.audit.list()
        log.info("Fetched %d audit events total", len(events))

        # Filter by time window
        if since:
            events = [
                e for e in events
                if (dt := _ctime_to_dt(e.ctime)) is not None and dt >= since
            ]
            log.info("  %d events after time filter", len(events))

        # Skip already-ingested events (by the last seen event ID)
        if last_event_id:
            seen_ids = {last_event_id}
            new_events = []
            for e in events:
                if e.id and e.id in seen_ids:
                    continue
                new_events.append(e)
            events = new_events
            log.info("  %d events after dedup filter", len(events))

        # Optionally filter to write operations only
        if writes_only:
            events = [e for e in events if (e.api_method or "").upper() in _WRITE_METHODS]
            log.info("  %d events after writes-only filter", len(events))

        # Sort by ctime ascending so state tracking is correct
        events.sort(key=lambda e: int(e.ctime or 0) if e.ctime and e.ctime.isdigit() else 0)

        # Process in batches
        for i in range(0, len(events), batch_size):
            batch = events[i : i + batch_size]
            udm_events: list[dict] = []
            for event in batch:
                try:
                    udm_events.append(audit_event_to_udm(event))
                    if event.id:
                        new_last_id = event.id
                except Exception as exc:
                    log.warning("Failed to convert audit event %s: %s", event.id, exc)

            if not udm_events:
                continue

            if dry_run:
                print(json.dumps(udm_events, indent=2))
                log.info("[DRY RUN] Would ingest %d audit UDM events", len(udm_events))
            else:
                try:
                    chronicle.ingest_udm(udm_events=udm_events)
                    log.info("Ingested %d audit UDM events (batch %d)", len(udm_events), i // batch_size + 1)
                except Exception as exc:
                    log.error("Chronicle ingestion failed: %s", exc)
                    raise

            total += len(udm_events)

    log.info("Audit sync complete. Total events ingested: %d", total)
    return total, new_last_id


# ── CLI ──

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Sync Kentik audit logs to Google Chronicle SecOps",
    )
    p.add_argument("--hours", type=float, default=24.0,
                   help="Look-back window in hours (default: 24). Overridden by --state-file.")
    p.add_argument("--writes-only", action="store_true",
                   help="Only ingest write operations (POST, PUT, PATCH, DELETE).")
    p.add_argument("--batch-size", type=int, default=200,
                   help="UDM events per Chronicle ingestion call (default: 200).")
    p.add_argument("--state-file", default=None, metavar="PATH",
                   help="JSON file to persist last-synced timestamp for incremental runs.")
    p.add_argument("--dry-run", action="store_true",
                   help="Print UDM events as JSON; skip Chronicle ingestion.")
    p.add_argument("--daemon", action="store_true",
                   help="Run continuously, polling on --interval seconds.")
    p.add_argument("--interval", type=int, default=600,
                   help="Poll interval in seconds for --daemon mode (default: 600).")
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
            _, last_id = sync_once(
                since=since,
                writes_only=args.writes_only,
                batch_size=args.batch_size,
                dry_run=args.dry_run,
                last_event_id=sync_state.last_event_id,
            )
            sync_state.update(now, last_id)
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
