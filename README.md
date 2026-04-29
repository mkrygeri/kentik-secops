# kentik-secops

> Sync [Kentik](https://www.kentik.com) network alerts into [Google Chronicle SecOps](https://cloud.google.com/chronicle) as UDM events.

---

## Overview

`kentik_to_chronicle.py` bridges the **Kentik Alerting API** and the **Google Chronicle SecOps Ingestion API**. It:

1. Polls Kentik for active or historical network alerts via the [Kentik Alerting API](https://kb.kentik.com/docs/alerting) (`v202505`)
2. Converts each alert to a [Chronicle Unified Data Model (UDM)](https://cloud.google.com/chronicle/docs/reference/udm-field-list) event
3. Ingests the UDM events into Chronicle for detection, investigation, and case management

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

## Usage

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

### All options

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
COPY kentik_to_chronicle.py .
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
┌──────────────────────────────────────────────────────────┐
│                    kentik_to_chronicle.py                │
│                                                          │
│  ┌─────────────┐      ┌──────────────┐      ┌─────────┐ │
│  │ KentikClient│─────▶│ alert_to_udm │─────▶│Chronicle│ │
│  │ (kentik-api)│      │  converter   │      │  SDK    │ │
│  └─────────────┘      └──────────────┘      └─────────┘ │
│         │                                        │       │
│         │  GET /v202505/alerts                   │       │
│         │  (paginated, with filters)             │       │
│         │                                        │       │
│         │                           ingest_udm() │       │
│         ▼                                        ▼       │
│  ┌──────────────┐                    ┌──────────────────┐│
│  │ Kentik API   │                    │ Chronicle UDM    ││
│  │ (grpc.api.   │                    │ Ingestion API    ││
│  │  kentik.com) │                    │ (secops SDK)     ││
│  └──────────────┘                    └──────────────────┘│
└──────────────────────────────────────────────────────────┘
```

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
