"""Kentik Device & Interface Inventory → Google Chronicle SecOps Entities.

Imports the Kentik network device and interface inventory into Google
Chronicle as ASSET entities. Once imported, Chronicle's investigation UI can
look up any IP address that appears in an alert or UDM event and show the
matching Kentik-managed device: its name, site, labels, interfaces, and BGP
configuration.

Run this on a schedule (daily is typically sufficient) to keep the Chronicle
entity graph in sync with your Kentik inventory.

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
    # Full sync of device + interface inventory
    python inventory_to_chronicle.py

    # Devices only (skip interface lookup)
    python inventory_to_chronicle.py --devices-only

    # Set tag on ingested entities for easy Chronicle filtering
    python inventory_to_chronicle.py --label prod

    # Dry run — print entity JSON without importing
    python inventory_to_chronicle.py --dry-run

    # Daemon mode (daily refresh)
    python inventory_to_chronicle.py --daemon --interval 86400
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from kentik_api import KentikClient
from kentik_api.models.devices import Device
from kentik_api.models.interfaces import Interface
from secops import SecOpsClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


def _ts_now_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def device_to_entity(device: Device, extra_label: str = "") -> dict:
    """Convert a Kentik Device to a Chronicle entity (ASSET type)."""
    now = _ts_now_z()
    device_id = str(device.id or "")

    # Collect all IPs associated with this device
    ips: list[str] = list({ip for ip in (device.sending_ips or []) if ip})
    if device.snmp_ip:
        ips.append(device.snmp_ip)
    if device.bgp_neighbor_ip:
        ips.append(device.bgp_neighbor_ip)
    if device.bgp_neighbor_ip6:
        ips.append(device.bgp_neighbor_ip6)
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_ips: list[str] = []
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            unique_ips.append(ip)

    # Hostname: prefer alias, fall back to name
    hostname = device.alias or device.name or device_id

    # Site name
    site_name = ""
    if device.site and device.site.site_name:
        site_name = device.site.site_name

    # Labels
    label_names = [lbl.name for lbl in (device.labels or []) if lbl.name]
    if extra_label:
        label_names.append(extra_label)
    label_names.append("kentik-managed")

    # Metadata labels (key/value pairs Chronicle stores on the entity)
    entity_labels: list[dict] = [
        {"key": "kentik_device_id", "value": device_id},
        {"key": "kentik_device_type", "value": device.device_type or ""},
        {"key": "kentik_device_subtype", "value": device.subtype or ""},
        {"key": "kentik_device_status", "value": device.status or ""},
        {"key": "kentik_flow_type", "value": device.flow_type or ""},
        {"key": "source", "value": "kentik-inventory"},
    ]
    if site_name:
        entity_labels.append({"key": "site", "value": site_name})
    if device.bgp_type:
        entity_labels.append({"key": "bgp_type", "value": device.bgp_type})
    if device.bgp_neighbor_asn:
        entity_labels.append({"key": "bgp_neighbor_asn", "value": str(device.bgp_neighbor_asn)})
    for lbl_name in label_names:
        entity_labels.append({"key": "label", "value": lbl_name})

    asset: dict[str, Any] = {
        "hostname": hostname,
    }
    if unique_ips:
        asset["ip"] = unique_ips

    entity: dict[str, Any] = {
        "metadata": {
            "collected_timestamp": now,
            "vendor_name": "Kentik",
            "product_name": "Kentik Network Observability",
            "entity_type": "ASSET",
        },
        "entity": {
            "asset": asset,
            "labels": entity_labels,
        },
    }

    # Add location if available
    if device.site and (device.site.lat or device.site.lon):
        entity["entity"]["asset"]["location"] = {
            "name": site_name,
            "country_or_region": "",  # Chronicle can geo-resolve from lat/lon
        }

    return entity


def interface_to_entity(iface: Interface, device_name: str, extra_label: str = "") -> dict | None:
    """Convert a Kentik Interface to a Chronicle ASSET entity.

    Returns None if there is no meaningful IP or identifier to associate.
    """
    if not iface.interface_ip and not iface.snmp_alias and not iface.interface_description:
        return None

    now = _ts_now_z()
    iface_id = str(iface.id or "")

    hostname = (
        iface.snmp_alias
        or iface.interface_description
        or f"{device_name}:{iface.snmp_id}"
    )

    entity_labels: list[dict] = [
        {"key": "kentik_interface_id", "value": iface_id},
        {"key": "kentik_device_id", "value": iface.device_id or ""},
        {"key": "kentik_device_name", "value": device_name},
        {"key": "snmp_id", "value": iface.snmp_id or ""},
        {"key": "snmp_speed_mbps", "value": str(iface.snmp_speed)},
        {"key": "connectivity_type", "value": iface.connectivity_type or ""},
        {"key": "network_boundary", "value": iface.network_boundary or ""},
        {"key": "provider", "value": iface.provider or ""},
        {"key": "source", "value": "kentik-inventory"},
        {"key": "label", "value": "kentik-interface"},
    ]
    if extra_label:
        entity_labels.append({"key": "label", "value": extra_label})

    asset: dict[str, Any] = {"hostname": hostname}
    if iface.interface_ip:
        asset["ip"] = [iface.interface_ip]

    return {
        "metadata": {
            "collected_timestamp": now,
            "vendor_name": "Kentik",
            "product_name": "Kentik Network Observability",
            "entity_type": "ASSET",
        },
        "entity": {
            "asset": asset,
            "labels": entity_labels,
        },
    }


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
    devices_only: bool,
    extra_label: str,
    batch_size: int,
    dry_run: bool,
) -> None:
    log.info("Starting Kentik inventory → Chronicle entity import")
    chronicle = None if dry_run else _get_chronicle()

    all_entities: list[dict] = []

    with KentikClient() as kentik:
        devices = kentik.devices.list()
        log.info("Fetched %d devices", len(devices))

        # Also fetch all interfaces upfront (one call) if not devices_only
        iface_map: dict[str, list[Interface]] = {}
        if not devices_only:
            try:
                interfaces = kentik.interfaces.list()
                log.info("Fetched %d interfaces", len(interfaces))
                for iface in interfaces:
                    iface_map.setdefault(iface.device_id or "", []).append(iface)
            except Exception as exc:
                log.warning("Failed to fetch interfaces: %s — skipping interface entities", exc)

        for device in devices:
            try:
                entity = device_to_entity(device, extra_label)
                all_entities.append(entity)
            except Exception as exc:
                log.warning("Failed to convert device %s: %s", device.id, exc)

            if not devices_only:
                device_id_str = str(device.id or "")
                for iface in iface_map.get(device_id_str, []):
                    try:
                        iface_entity = interface_to_entity(
                            iface, device.name or device_id_str, extra_label
                        )
                        if iface_entity:
                            all_entities.append(iface_entity)
                    except Exception as exc:
                        log.warning("Failed to convert interface %s: %s", iface.id, exc)

    log.info("Total entities to import: %d", len(all_entities))

    # Ingest in batches
    for i in range(0, len(all_entities), batch_size):
        batch = all_entities[i : i + batch_size]
        if dry_run:
            print(json.dumps(batch, indent=2))
            log.info("[DRY RUN] Would import %d entities (batch %d)", len(batch), i // batch_size + 1)
        else:
            try:
                # import_entities accepts a list or single entity dict + a log_type label
                chronicle.import_entities(entities=batch, log_type="KENTIK_INVENTORY")
                log.info("Imported %d entities (batch %d)", len(batch), i // batch_size + 1)
            except Exception as exc:
                log.error("Entity import failed on batch %d: %s", i // batch_size + 1, exc)
                raise

    log.info("Inventory import complete.")


# ── CLI ──

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Import Kentik device/interface inventory into Google Chronicle as entities",
    )
    p.add_argument("--devices-only", action="store_true",
                   help="Import device entities only; skip interface entities.")
    p.add_argument("--label", default="", metavar="TAG",
                   help="Extra label tag to attach to all imported entities (e.g. 'prod').")
    p.add_argument("--batch-size", type=int, default=500,
                   help="Entities per Chronicle import call (default: 500).")
    p.add_argument("--dry-run", action="store_true",
                   help="Print entity JSON; skip Chronicle import.")
    p.add_argument("--daemon", action="store_true",
                   help="Run continuously, re-syncing on --interval seconds.")
    p.add_argument("--interval", type=int, default=86400,
                   help="Re-sync interval in seconds for --daemon mode (default: 86400 = 1 day).")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    logging.getLogger().setLevel(args.log_level)

    def _run_once() -> None:
        try:
            sync_once(
                devices_only=args.devices_only,
                extra_label=args.label,
                batch_size=args.batch_size,
                dry_run=args.dry_run,
            )
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
            log.info("Sleeping %d seconds until next refresh ...", args.interval)
            time.sleep(args.interval)
    else:
        _run_once()


if __name__ == "__main__":
    main()
