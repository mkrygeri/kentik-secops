# kentik-secops

> Sync [Kentik](https://www.kentik.com) network observability data into [Google Chronicle SecOps](https://cloud.google.com/chronicle) — alerts, BGP events, audit logs, and device inventory.

---

## Overview

This repository contains four integration scripts that bridge the **Kentik Network Observability Platform** and the **Google Chronicle SecOps Ingestion API**:

| Script | Data source | Chronicle API | UDM type |
|---|---|---|---|
| `kentik_to_chronicle.py` | Alerting API | `ingest_udm` | `NETWORK_CONNECTION` / `GENERIC_EVENT` |
| `bgp_to_chronicle.py` | BGP Monitoring API | `ingest_udm` | `NETWORK_UNCATEGORIZED` |
| `audit_to_chronicle.py` | Audit Log API | `ingest_udm` | `USER_RESOURCE_ACCESS` |
| `inventory_to_chronicle.py` | Device + Interface API | `import_entities` | ASSET entities |

Each script is independent and can be deployed on its own schedule.

---

## Integration 1: Alerts (`kentik_to_chronicle.py`)

Polls the Kentik Alerting API for active or historical network alerts, converts them to Chronicle UDM events, and ingests them for detection, investigation, and case management.

### Alert → UDM mapping

| Kentik field | UDM field |
|---|---|
| `id` | `metadata.id` |
| `startTimeAt` | `metadata.event_timestamp` |
| `source.policyType` = `TRAFFIC`/`CLOUD` with flow context | `metadata.event_type` = `NETWORK_CONNECTION` |
| All other policy types | `metadata.event_type` = `GENERIC_EVENT` |
| `severity` | `security_result[].severity` (CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL) |
| `state` = `ACTIVE` | `security_result[].alert_state` = `ALERTING` |
| `state` = `CLEAR` | `security_result[].alert_state` = `NO_ACTION` |
| `flow.alertKeyDetails.srcIp` | `network.source_ip` |
| `flow.alertKeyDetails.dstIp` | `network.destination_ip` |
| `flow.metricValues` | `additional.fields[flow_<name>]` |
| `nms.device.name` | `additional.fields[nms_device_name]` |
| All Kentik IDs & state | `additional.fields[kentik_*]` |

---

## Integration 2: BGP Monitoring (`bgp_to_chronicle.py`)

Fetches BGP reachability and path-change metrics for all of your Kentik BGP monitors, converts them to `NETWORK_UNCATEGORIZED` UDM events, and ingests them into Chronicle.  Optionally also ingests route snapshots carrying origin ASN, AS-path, nexthop, and RPKI validity status — surfacing potential BGP hijacking or route-leak events directly in Chronicle investigations.

### BGP metric → UDM mapping

| Kentik field | UDM field |
|---|---|
| `timestamp` | `metadata.event_timestamp` |
| `nlri` (CIDR prefix) | `target.resource.name` + `additional.fields[bgp_prefix]` |
| `metricType` | `metadata.product_event_type` (`BGP_REACHABILITY` / `BGP_PATH_CHANGES`) |
| `value` (reachability %) | `security_result[].severity` — see table below |
| Monitor name | `additional.fields[kentik_monitor_name]` |
| Monitor ID | `additional.fields[kentik_monitor_id]` |

### BGP route snapshot → UDM mapping

| Kentik field | UDM field |
|---|---|
| `nlri` (CIDR prefix) | `target.resource.name` |
| `nexthop` | `target.ip[]` |
| `originAsn` | `network.asn` + `additional.fields[bgp_origin_asn]` |
| `asPath` | `additional.fields[bgp_as_path]` |
| `rpkiStatus = INVALID` | `security_result[].severity` = `HIGH` |
| `rpkiStatus = NOT_FOUND` | `security_result[].severity` = `LOW` |

### Reachability severity mapping

| Reachability % (vs threshold) | Severity |
|---|---|
| < 50 % of threshold | `CRITICAL` |
| 50–75 % of threshold | `HIGH` |
| 75–100 % of threshold | `MEDIUM` |
| ≥ threshold | `INFORMATIONAL` |

Default threshold: 80 %. Override with `--reachability-threshold`.

### BGP usage

```bash
source .env

# Default: last 1 hour of metrics from all monitors
python bgp_to_chronicle.py

# Last 6 hours, including route snapshots
python bgp_to_chronicle.py --hours 6 --include-routes

# Alert when reachability drops below 95 %
python bgp_to_chronicle.py --reachability-threshold 95

# Incremental daemon (recommended)
python bgp_to_chronicle.py --daemon --interval 300 \
    --state-file /var/lib/kentik_bgp_state.json

# Dry run
python bgp_to_chronicle.py --dry-run --include-routes
```

### BGP options

```
--hours FLOAT               Look-back window (default: 1)
--reachability-threshold    Reachability % threshold for MEDIUM severity (default: 80)
--include-routes            Also ingest AS-path / RPKI route snapshots
--state-file PATH           Persist last-synced timestamp for incremental runs
--dry-run                   Print UDM JSON; skip ingestion
--daemon                    Run continuously at --interval seconds
--interval SECONDS          Poll interval for --daemon mode (default: 300)
```

---

## Integration 3: Audit Logs (`audit_to_chronicle.py`)

Fetches every Kentik API call recorded in the audit trail (user, IP address, HTTP method, API path, timestamp) and ingests them as `USER_RESOURCE_ACCESS` UDM events.  Use this to detect insider threats, credential compromise, or suspicious configuration changes — for example, someone deleting an alert policy outside business hours or from an unrecognised IP address.

### Audit event → UDM mapping

| Kentik field | UDM field |
|---|---|
| `id` | `metadata.id` |
| `ctime` | `metadata.event_timestamp` |
| `api_method` | `metadata.product_event_type` (`AUDIT_GET`, `AUDIT_POST`, …) |
| `api_path` | `target.resource.name` |
| `user_id` | `principal.user.userid` |
| `ip_address` | `principal.ip[]` |
| `authority` | `target.resource.attribute.labels[authority]` |

### Audit severity mapping

| Condition | Severity |
|---|---|
| `DELETE` on any path | `HIGH` |
| `POST`/`PUT`/`PATCH` to sensitive path (alerts, devices, users …) | `MEDIUM` |
| Any other write | `LOW` |
| Read-only (`GET`) | `INFORMATIONAL` |

### Audit usage

```bash
source .env

# One-shot: all events from the last 24 hours
python audit_to_chronicle.py

# Only write operations (POST, PUT, PATCH, DELETE)
python audit_to_chronicle.py --writes-only

# Incremental daemon
python audit_to_chronicle.py --daemon --interval 600 \
    --state-file /var/lib/kentik_audit_state.json

# Dry run
python audit_to_chronicle.py --dry-run --writes-only
```

### Audit options

```
--hours FLOAT       Look-back window (default: 24)
--writes-only       Only ingest write operations
--batch-size INT    Events per Chronicle call (default: 200)
--state-file PATH   Persist last-synced timestamp for incremental runs
--dry-run           Print UDM JSON; skip ingestion
--daemon            Run continuously at --interval seconds
--interval SECONDS  Poll interval for --daemon mode (default: 600)
```

---

## Integration 4: Device & Interface Inventory (`inventory_to_chronicle.py`)

Imports the Kentik network device and interface inventory into Chronicle as **ASSET entities**.  Once imported, the Chronicle investigation UI can look up any IP address and display the matching Kentik-managed device — including its name, site, labels, interfaces, and BGP configuration — enriching any UDM event that touches that IP.

Run this on a daily schedule (or use `--daemon --interval 86400`).

### Device → Chronicle entity mapping

| Kentik field | Chronicle entity field |
|---|---|
| `alias` / `name` | `entity.asset.hostname` |
| `sending_ips`, `snmp_ip`, BGP IPs | `entity.asset.ip[]` |
| `device_type`, `subtype`, `status` | `entity.labels[kentik_device_type …]` |
| `site.site_name` | `entity.labels[site]` |
| `bgp_neighbor_asn` | `entity.labels[bgp_neighbor_asn]` |
| Kentik labels (list) | `entity.labels[label]` (multi-valued) |

### Interface → Chronicle entity mapping

| Kentik field | Chronicle entity field |
|---|---|
| `snmp_alias` / `interface_description` | `entity.asset.hostname` |
| `interface_ip` | `entity.asset.ip[]` |
| `connectivity_type`, `network_boundary`, `provider` | `entity.labels[…]` |
| `device_id` | `entity.labels[kentik_device_id]` |

### Inventory usage

```bash
source .env

# Full sync of devices and interfaces
python inventory_to_chronicle.py

# Devices only
python inventory_to_chronicle.py --devices-only

# Tag all imported entities with 'prod'
python inventory_to_chronicle.py --label prod

# Daily daemon
python inventory_to_chronicle.py --daemon --interval 86400

# Dry run (prints entity JSON)
python inventory_to_chronicle.py --dry-run
```

### Inventory options

```
--devices-only      Import device entities only; skip interfaces
--label TAG         Extra label to attach to all entities (e.g. 'prod')
--batch-size INT    Entities per Chronicle import call (default: 500)
--dry-run           Print entity JSON; skip import
--daemon            Run continuously at --interval seconds
--interval SECONDS  Re-sync interval for --daemon mode (default: 86400)
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.10 + | Tested on 3.12 |
| Kentik account | API key with `admin.alerting:read` scope |
| Google Cloud project | Linked to your Chronicle instance |
| Chronicle API enabled | `roles/chronicle.admin` on the GCP service account |

---

## Installation

```bash
# 1. Clone this repo
git clone https://github.com/kentik/kentik-secops.git
cd kentik-secops

# 2. Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

> **kentik-api** is the Kentik Python SDK. Install it from its repository:
> ```bash
> pip install git+https://github.com/kentik/kentik-pyapi.git
> ```

---

## Configuration

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
$EDITOR .env
```

```dotenv
# Kentik
KENTIK_API_EMAIL=you@yourcompany.com
KENTIK_API_TOKEN=your_kentik_api_token

# Chronicle
CHRONICLE_CUSTOMER_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CHRONICLE_PROJECT_ID=your-gcp-project-id
CHRONICLE_REGION=us           # us | europe | asia

# Google auth — one of:
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
# or run: gcloud auth application-default login
```

> **Security note:** `.env` is in `.gitignore`. Never commit credentials. The
> service account JSON key should also remain outside of version control.

### Kentik credentials

1. Log in to the [Kentik portal](https://portal.kentik.com)
2. Go to **Account Settings → API Tokens**
3. Create a token with the `admin.alerting:read` scope (add `admin.alerting:write` if you want future ack/clear features)

### Chronicle credentials

1. Follow [Configure a Google Cloud project for Google SecOps](https://cloud.google.com/chronicle/docs/onboard/configure-cloud-project)
2. Create a service account with the `roles/chronicle.admin` role
3. Download the JSON key and set `GOOGLE_APPLICATION_CREDENTIALS`

---

## Usage (Alerts)

```bash
source .env   # load credentials into the shell

# Sync alerts from the last hour (default)
python kentik_to_chronicle.py

# Sync alerts from a longer window
python kentik_to_chronicle.py --hours 24

# Only fetch active alerts
python kentik_to_chronicle.py --state active

# Incremental mode — remember the last sync time across runs
python kentik_to_chronicle.py --state-file /var/lib/kentik_chronicle_state.json

# Continuous polling every 5 minutes
python kentik_to_chronicle.py --daemon --interval 300 \
    --state-file /var/lib/kentik_chronicle_state.json

# Dry run — print UDM JSON without ingesting anything
python kentik_to_chronicle.py --dry-run --hours 2
```

### All options (Alerts)

```
usage: kentik_to_chronicle.py [-h] [--hours HOURS]
                              [--state {active,clear,all}]
                              [--state-file PATH]
                              [--batch-size BATCH_SIZE]
                              [--dry-run] [--daemon]
                              [--interval INTERVAL]
                              [--log-level {DEBUG,INFO,WARNING,ERROR}]

options:
  --hours HOURS         Look back this many hours for alerts (default: 1).
                        Overridden by --state-file on subsequent runs.
  --state               Filter: active | clear | all  (default: all)
  --state-file PATH     JSON file to persist last-synced timestamp.
  --batch-size INT      Alerts per API page (default: 100)
  --dry-run             Print UDM JSON; skip Chronicle ingestion.
  --daemon              Run continuously, polling every --interval seconds.
  --interval SECONDS    Poll interval for --daemon mode (default: 300).
  --log-level           DEBUG | INFO | WARNING | ERROR  (default: INFO)
```

---

## Running as a service (systemd)

Create `/etc/systemd/system/kentik-secops.service`:

```ini
[Unit]
Description=Kentik → Chronicle SecOps alert sync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
EnvironmentFile=/etc/kentik-secops/env
WorkingDirectory=/opt/kentik-secops
ExecStart=/opt/kentik-secops/.venv/bin/python /opt/kentik-secops/kentik_to_chronicle.py \
    --daemon \
    --interval 300 \
    --state-file /var/lib/kentik-secops/state.json
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now kentik-secops
sudo journalctl -u kentik-secops -f
```

---

## Running in Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install git+https://github.com/kentik/kentik-pyapi.git
COPY kentik_to_chronicle.py bgp_to_chronicle.py \
     audit_to_chronicle.py inventory_to_chronicle.py ./
# Default: run the alerts sync in daemon mode
CMD ["python", "kentik_to_chronicle.py", "--daemon", "--interval", "300", \
     "--state-file", "/data/state.json"]
```

```bash
docker build -t kentik-secops .
docker run -d \
  --env-file .env \
  -v kentik-secops-data:/data \
  kentik-secops
```

---

## Development

```bash
# Install dev extras
pip install pytest pytest-cov ruff

# Lint
ruff check kentik_to_chronicle.py

# Unit tests (uses mock Kentik alerts — no live credentials needed)
pytest tests/
```

---

## How it works

```
Kentik APIs                   Converters                  Chronicle
────────────────────────────────────────────────────────────────────────
Alerting API  ──▶  kentik_to_chronicle.py   ──▶  ingest_udm()
                   (alert_to_udm)                NETWORK_CONNECTION
                                                 GENERIC_EVENT

BGP Monitoring ──▶  bgp_to_chronicle.py     ──▶  ingest_udm()
API                 (metric_to_udm,              NETWORK_UNCATEGORIZED
                     route_to_udm)

Audit Log API ──▶  audit_to_chronicle.py    ──▶  ingest_udm()
                   (audit_event_to_udm)          USER_RESOURCE_ACCESS

Device &      ──▶  inventory_to_chronicle.py ──▶  import_entities()
Interface API       (device_to_entity,            ASSET entities
                     interface_to_entity)
```

All scripts share the same credential model:
- Kentik: `KENTIK_API_EMAIL` + `KENTIK_API_TOKEN` environment variables
- Chronicle: Google ADC (`GOOGLE_APPLICATION_CREDENTIALS` or `gcloud auth application-default login`)
- Chronicle instance: `CHRONICLE_CUSTOMER_ID`, `CHRONICLE_PROJECT_ID`, `CHRONICLE_REGION`

### State file

When `--state-file` is provided, the script writes the UTC timestamp of each
successful sync to a JSON file:

```json
{ "last_synced_utc": "2026-04-29T14:00:00Z" }
```

On the next run it uses this as the `started_at` filter lower bound, ensuring
every alert is ingested exactly once regardless of how often the script runs.

### Severity mapping

| Kentik | Chronicle UDM |
|---|---|
| `SEVERITY_CRITICAL` | `CRITICAL` |
| `SEVERITY_SEVERE` | `HIGH` |
| `SEVERITY_MAJOR` | `HIGH` |
| `SEVERITY_WARNING` | `MEDIUM` |
| `SEVERITY_MINOR` | `LOW` |
| `SEVERITY_CLEAR` | `INFORMATIONAL` |
| `SEVERITY_UNSPECIFIED` | `SEVERITY_UNKNOWN` |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a pull request

Please run `ruff check` and ensure all tests pass before submitting.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

---

## Related

- [Kentik API documentation](https://kb.kentik.com/docs/api)
- [Kentik Python API SDK (kentik-pyapi)](https://github.com/kentik/kentik-pyapi)
- [Google SecOps Python SDK](https://pypi.org/project/secops/)
- [Chronicle UDM field reference](https://cloud.google.com/chronicle/docs/reference/udm-field-list)
- [Chronicle Ingestion API](https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.logTypes/import)
