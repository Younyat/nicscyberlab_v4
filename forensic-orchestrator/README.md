# forensic-orchestrator (standalone)

Standalone module to perform headless forensic analysis from a Wazuh Manager node.
It reads Wazuh evidence files (primarily alerts.json), builds a timeline, produces a forensic case folder,
and generates reports without using the Wazuh Dashboard.

Forensic Orchestrator

Centralized Headless Forensic Analysis using Wazuh

## Project Structure (Actual)
```
forensic-orchestrator/
├── config/
├── deployment/
│   ├── monitoring/
│   │   └── setup_wazuh_manager_forensics.sh
│   └── victim/
│       ├── agent.env
│       └── install_wazuh_agent.sh
├── src/forensic_orchestrator/
│   ├── application/
│   ├── domain/
│   ├── infrastructure/
│   └── presentation/
│       ├── controllers/
│       ├── dtos/
│       │   └── run_request.py
│       └── cli.py
├── pyproject.toml
└── README.md
```

## Prerequisites

Monitoring Node

Linux (Ubuntu 22.04 / 24.04)

Wazuh Manager installed and running

Evidence files available:

/var/ossec/logs/alerts/alerts.json
/var/ossec/logs/archives/archives.json   (optional)

Python >= 3.10

Victim Node

Linux system

Network connectivity to monitoring node

Wazuh agent installed and configured (see below)

## Victim Setup (Mandatory)

The victim instance must run a Wazuh agent.
This project assumes the agent installation logic is already provided.

From the victim instance, install and configure the agent using the provided deployment scripts:

```bash
cd deployment/victim
sudo bash install_wazuh_agent.sh agent.env
```

Where agent.env contains:

```
WAZUH_MANAGER_IP=<monitoring_ip>
```

## Verification (Victim)
```bash
sudo systemctl status wazuh-agent
```

The agent must be active and connected to the manager.

## Monitoring Setup (One-Time)

From the monitoring instance, prepare Wazuh for forensic analysis:

```bash
cd deployment/monitoring
sudo bash setup_wazuh_manager_forensics.sh
```

This ensures:

JSON evidence generation (alerts.json, archives.json)

Proper logging for offline forensic analysis

## Installation (Forensic Orchestrator)

On the monitoring node:

```bash
cd forensic-orchestrator
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Execution

Run the forensic analysis from the monitoring node:

```bash
forensic-orchestrator --agent victim-01
```

Optional filters:

```bash
forensic-orchestrator \
  --agent victim-01 \
  --since "2025-12-27T00:00:00Z" \
  --until "2025-12-27T23:59:59Z" \
  --min-level 10
```

## Verification (Monitoring)
1) Case creation

```bash
ls cases/
```

Expected:

CASE-YYYYMMDD-HHMMSS-victim-01

2) Evidence extraction

```bash
ls cases/CASE-*/evidence/
```

Expected:

alerts.filtered.jsonl
archives.filtered.jsonl   (if available)

3) Timeline generation

```bash
head cases/CASE-*/derived/timeline.csv
```

4) Report generation

```bash
less cases/CASE-*/report/report.txt
```

5) Integrity verification

```bash
sha256sum -c cases/CASE-*/integrity/manifest.sha256
```

All entries must return OK.

## Internal Execution (Very Brief)

When running forensic-orchestrator:

Reads Wazuh evidence (alerts.json, archives.json)

Filters events by agent, time, and severity

Builds a chronological timeline

Creates a forensic case directory

Generates reports and integrity hashes

Updates chain of custody

No interaction with the victim occurs during analysis.

## Key Properties

Passive (non-intrusive)

Centralized analysis

Dashboard-independent

Forensically sound

Clean Architecture compliant

## One-Line Summary

Transforms Wazuh Manager JSON logs into a complete, verifiable forensic case — centrally and offline.

## What it does
- Reads Wazuh alerts JSON lines (alerts.json)
- Filters by agent name and/or time range and/or minimum level
- Copies evidence into a case folder
- Builds a timeline CSV
- Generates a TXT report
- Computes SHA256 manifest (integrity)
- Writes a simple chain of custody log

## Requirements
- Run on the Monitoring instance (where Wazuh Manager writes logs)
- Wazuh Manager should produce:
  - /var/ossec/logs/alerts/alerts.json
  - /var/ossec/logs/archives/archives.json (optional)

## Install
From repository root:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

## Configure

Edit config/defaults.yaml (or pass a custom config path to CLI).

## Run

Basic:

```bash
forensic-orchestrator --agent victim-01
```

Custom output directory:

```bash
forensic-orchestrator --agent victim-01 --out ./cases
```

With time range:

```bash
forensic-orchestrator --agent victim-01 --since "2025-12-27T00:00:00Z" --until "2025-12-27T23:59:59Z"
```

With minimum rule level:

```bash
forensic-orchestrator --agent victim-01 --min-level 10
```

Case structure output:

```
cases/CASE-YYYYMMDD-HHMMSS-<agent>/
metadata.json
chain_of_custody.log
evidence/
alerts.json (filtered)
archives.json (optional, filtered)
derived/
timeline.csv
stats.json
report/
report.txt
integrity/
manifest.sha256
```

## Notes
- This is intentionally "best-effort" and robust: missing archives.json is OK.
- It does not modify Wazuh configs; it only reads and copies evidence.
