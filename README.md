<div align="center">

# LogNorm

 Log Source Normalizer — Sysmon / WEL / Wazuh / syslog / CEF → ECS-lite schema

Part of the **Nebula Forge** detection engineering platform. LogNorm is the normalization gateway for the pipeline: its ECS-lite JSON output is the shared data currency accepted by DriftWatch, ClusterIQ, AtomicLoop, and HuntForge.

![version](https://img.shields.io/badge/version-v1.0.0-blueviolet?style=flat-square) ![port](https://img.shields.io/badge/port-5006-5d5d5d?style=flat-square) ![python](https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python) ![framework](https://img.shields.io/badge/framework-Flask-000000?style=flat-square&logo=flask) ![part%20of](https://img.shields.io/badge/part%20of-Nebula%20Forge-7c3aed?style=flat-square) ![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)


</div>


## What it does

LogNorm ingests raw log files from five source types and normalizes every record to a consistent **ECS-lite** JSON schema. Normalized events are stored in SQLite and can be exported as JSON or CSV. The Flask web UI provides an upload → normalize → view → export workflow; the CLI handles file-based automation.


---

## Pipeline Position

![Nebula Forge pipeline — LogNorm highlighted](docs/pipeline.svg)

> **purple-loop:** `AtomicLoop → LogNorm → ClusterIQ → DriftWatch → HuntForge → repeat`

---

## Screenshots

### Dashboard

![LogNorm Dashboard](docs/LogNorm-Dashboard.png)


### Upload

![LogNorm Upload](docs/LogNorm-upload.png)



---

## Source adapters

| Key | Source | Input format | Coverage |
|-----|--------|-------------|---------|
| `sysmon` | Microsoft Sysmon | XML (wevtutil export) | EventIDs 1–29 (process, network, file, registry, DNS, WMI, pipes) |
| `wel` | Windows Event Log | CSV (Get-WinEvent / EndpointTriage Security.csv) | 4624/4625 logon, 4688 process, 4698 tasks, 4720/4726 accounts, 4740 lockout, 7045 service |
| `wazuh` | Wazuh alerts | NDJSON / JSON array / single object | All rule-based alerts; Windows `data.win.*`, `syscheck`, `audit` blocks |
| `syslog` | Linux auth.log / syslog | Text (RFC 3164 / RFC 5424 / journald) | SSH, sudo, PAM, cron, useradd, su, systemd |
| `cef` | CEF / Generic JSON | `CEF:0|...|extensions` or any flat JSON | Vendor-agnostic best-effort field mapping |

---

## Quick start

```bash
# Install
pip install flask pyyaml

# Copy config
cp config.example.yaml config.yaml

# Run web app (default port 5006)
python app.py

# Or specify port
python app.py --port 5006
```

Open `http://127.0.0.1:5006`

---

## CLI

```bash
# Normalize Sysmon XML to JSON (stdout)
python cli.py --input sysmon.xml --source sysmon --pretty

# Normalize WEL CSV to output file
python cli.py --input security.csv --source wel --output normalized.json

# Normalize Wazuh alerts to CSV
python cli.py --input alerts.json --source wazuh --output out.csv --format csv

# Normalize auth.log (strip original_log to reduce size)
python cli.py --input /var/log/auth.log --source syslog --no-original-log

# Read from stdin
cat sysmon.xml | python cli.py --source sysmon --stdin

# All options
python cli.py --help
```

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/api/health` | Health check — `{"status":"ok","tool":"lognorm","version":"1.0.0"}` |
| `GET`  | `/api/sources` | List supported source types and descriptions |
| `POST` | `/api/normalize` | Normalize single record (JSON body) |
| `POST` | `/api/normalize/batch` | Normalize file (multipart) or record list (JSON) |
| `GET`  | `/api/records` | List stored events (pagination + filters) |
| `GET`  | `/api/record/<id>` | Fetch single stored event by UUID |
| `GET`  | `/api/sessions` | List normalization sessions |
| `GET`  | `/api/export` | Export as JSON or CSV (`?format=json|csv&session_id=...`) |
| `DELETE` | `/api/records` | Clear all stored records |

### POST /api/normalize
```json
POST /api/normalize
{"source_type": "sysmon", "raw": "<Event>...</Event>"}

→ {"success": true, "event": {<ECS-lite>}, "session_id": "uuid"}
```

### POST /api/normalize/batch
```json
// JSON body
POST /api/normalize/batch
{"source_type": "wazuh", "raw": "...full file content..."}
{"source_type": "syslog", "records": ["Apr 3 ...", "Apr 3 ..."]}

// File upload (multipart/form-data)
POST /api/normalize/batch
  file=<binary>  source_type=sysmon

→ {"success": true, "events": [{<ECS-lite>}, ...], "failed": 0,
   "total": 45, "session_id": "uuid", "filename": "sysmon.xml"}
```

---

## ECS-lite schema reference

**Schema version: 1.0** — Required fields are `event.id`, `event.created`, `event.source_type`, `log.source_type`. All other fields are optional and omitted when empty.

### Top-level

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | yes | Always `"1.0"` |
| `tags` | array | yes | Free-form tags (e.g. `T1059.001`, `atomic-test`) |

### event

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `event.id` | string | **yes** | UUID v4 — unique identifier for this normalized event |
| `event.created` | ISO8601 | **yes** | Timestamp the event was created (UTC) |
| `event.source_type` | string | **yes** | Adapter: `sysmon` \| `wel` \| `wazuh` \| `syslog` \| `cef` |
| `event.category` | array | no | ECS category: `process` \| `network` \| `file` \| `registry` \| `authentication` \| `iam` \| `driver` |
| `event.type` | array | no | ECS type: `start` \| `end` \| `creation` \| `deletion` \| `access` \| `change` \| `connection` \| `protocol` |
| `event.action` | string | no | Human-readable action from the source log |
| `event.outcome` | string | no | `success` \| `failure` \| `unknown` |
| `event.severity` | integer | no | Normalized 0–100 severity |
| `event.original_event_id` | string | no | EventID from source (e.g. `1`, `4624`) |

### host

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `host.name` | string | no | Hostname of the originating endpoint |
| `host.hostname` | string | no | Same as `host.name` |
| `host.ip` | array | no | IP addresses associated with the host |
| `host.os.type` | string | no | `windows` \| `linux` \| `macos` |
| `host.os.name` | string | no | Full OS name |

### process

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `process.pid` | integer | no | Process ID |
| `process.ppid` | integer | no | Parent process ID |
| `process.name` | string | no | Image name (e.g. `powershell.exe`) |
| `process.executable` | string | no | Full path to executable |
| `process.command_line` | string | no | Full command line including arguments |
| `process.hash.md5` | string | no | MD5 of process image (lowercase hex) |
| `process.hash.sha256` | string | no | SHA-256 of process image (lowercase hex) |
| `process.parent.pid` | integer | no | Parent PID |
| `process.parent.name` | string | no | Parent image name |
| `process.parent.executable` | string | no | Full path to parent executable |
| `process.parent.command_line` | string | no | Parent command line |

### network

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `network.direction` | string | no | `ingress` \| `egress` \| `internal` |
| `network.transport` | string | no | `tcp` \| `udp` \| `icmp` |
| `network.destination.ip` | string | no | Destination IP |
| `network.destination.port` | integer | no | Destination port |
| `network.destination.domain` | string | no | Destination hostname / domain |
| `network.source.ip` | string | no | Source IP |
| `network.source.port` | integer | no | Source port |

### file

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file.path` | string | no | Full file path |
| `file.name` | string | no | Filename without directory |
| `file.extension` | string | no | Extension without leading dot |
| `file.hash.md5` | string | no | MD5 (lowercase hex) |
| `file.hash.sha256` | string | no | SHA-256 (lowercase hex) |
| `file.size` | integer | no | Size in bytes |

### registry

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `registry.path` | string | no | Full registry path |
| `registry.key` | string | no | Registry key name |
| `registry.value.name` | string | no | Value name |
| `registry.value.type` | string | no | Value type (`REG_SZ`, `REG_DWORD`, …) |
| `registry.value.data` | string | no | Value data |

### user

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user.name` | string | no | Account username |
| `user.domain` | string | no | Domain or workgroup |
| `user.id` | string | no | SID or UID |

### log

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `log.source_type` | string | **yes** | Adapter used |
| `log.source_tool` | string | no | Tool that generated the original log |
| `log.original_event_id` | string | no | Original event identifier |
| `log.original_log` | object | no | Raw source record preserved verbatim |

---

## Nebula-Forge integration

**nebula-dashboard config.yaml** — add to the `tools:` block:
```yaml
lognorm:
  label:       "LogNorm"
  url:         "http://127.0.0.1:5006"
  health_path: "/api/health"
  description: "Log source normalizer — Sysmon / WEL / Wazuh / syslog / CEF → ECS-lite"
  category:    "Normalize"
```

**detection-pipeline / purple-loop config.yaml:**
```yaml
lognorm_url: "http://127.0.0.1:5006"
```

---

## Architecture

```
LogNorm/
├── app.py                  Flask web app + all API endpoints
├── cli.py                  Standalone CLI
├── config.example.yaml     Configuration template
├── adapters/
│   ├── base.py             BaseAdapter — parse() + parse_file()
│   ├── sysmon.py           Sysmon XML (EventIDs 1–29)
│   ├── wel.py              Windows Event Log CSV
│   ├── wazuh.py            Wazuh JSON / NDJSON
│   ├── syslog.py           Linux auth.log / syslog / journald
│   └── cef.py              CEF + generic JSON
├── core/
│   ├── engine.py           NormalizationEngine — dispatch + fallback
│   ├── models.py           make_ecs_event() factory + helpers
│   ├── schema.py           Field reference + source descriptions
│   └── storage.py          SQLite — sessions + events tables
├── static/css/style.css    Nebula Forge dark theme
├── static/js/main.js       Upload, normalize, render, pagination
└── templates/
    ├── base.html           Sidebar layout
    ├── index.html          Upload + normalize UI
    ├── records.html        Browse stored events
    └── schema.html         ECS-lite field reference
```

**Fallback pattern** (consistent with detection-pipeline / ir-chain): if the SQLite write fails, the normalized events are saved to `./output/fallback_<source>_<timestamp>_<session>.json` so no data is lost.

---

## Home lab

Validated against:
- **Wazuh** 4.14.4 at `<wazuh-host>` — Wazuh adapter targets this alert format
- **Windows Agent** — Sysmon (SwiftOnSecurity config) + EndpointTriage Security.csv
- **Linux Agent** — auth.log / journald output
- **Splunk on Linux Agent** — WEL CSV exports

---
## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.


<div align="center">

Built by [Rootless-Ghost](https://github.com/Rootless-Ghost) 

Part of the **Nebula Forge** security tools suite.

</div>


