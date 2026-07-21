# Scenario Snapshot Module

**Module path**: `app_core/infrastructure/scenario_snapshot/`  
**Frontend**: `app_core/static/scenario_snapshot.html` + `app_core/static/js/scenario_snapshot.js`  
**Storage**: `runtime/scenario_snapshots/{SNAPSHOT_ID}/snapshot_manifest.json`

---

## Purpose

The Scenario Snapshot module captures a **complete, reproducible, point-in-time record** of the
experimental cybersecurity scenario. It is the authoritative source for:

- **Scenario reconstruction** — everything needed to rebuild the experiment from scratch
- **Scientific reproducibility** — Level A / B / C comparison and audit
- **Forensic traceability** — chain of custody, case analysis, and evidence integrity
- **Infrastructure-as-data** — OpenStack nodes, network topology, OT components, tools, rules

> **Key principle:** Snapshots are **never** automatically deleted when the scenario is destroyed.
> They are the only blueprint for Level C redeployment.

---

## Architecture

```
scenario_snapshot/
├── __init__.py           Empty package marker
├── service.py            All collection, validation and persistence logic
├── api.py                Flask blueprint — 10 REST endpoints
└── README.md             This file

runtime/scenario_snapshots/
└── SS-YYYYMMDD-HHMMSS-XXXX/
    └── snapshot_manifest.json    Complete snapshot (JSON, ~500 KB–5 MB)
```

No writes to existing data sources — pure aggregation only.

---

## What the Snapshot Contains

### 1. Scenario Definition (`scenario`)
- Source: `scenario/scenario_file.json` + `industrial-scenario/scenarios/industrial_industrial_file.json`
- IT nodes (monitor, attack, victim) + OT nodes (PLC, SCADA)
- Topology edges, node properties (image, flavor, network, IP)
- SHA-256 of source files

### 2. OpenStack Infrastructure (`infrastructure`)
- Live instance inventory: IDs, IPs (private + floating), status, image, flavor
- Logical node → runtime instance mapping with confidence level
- Source: OpenStack Compute API (`conn.compute.servers()`)

### 3. Network Configuration (`network_config`)
- Networks, subnets with CIDRs and gateway IPs
- Routers with external gateway info
- Security groups with full rule tables (direction, protocol, port range)
- Floating IP assignments
- Source: OpenStack Network API

### 4. Tool State (`tools`)
- Per-node tool installation history (tool name, install date, status)
- Status: `INSTALLED | FAILED | PENDING | UNRESOLVED`
- Sources: `tools-installer/installed/{instance_id}.json` + `tools-installer-tmp/{name}_tools.json`

### 5. Node Verification (`node_verification`)
- **Cached**: OS identity, kernel, services state (suricata, wazuh-agent, docker, openplc)
- **Live (after "Verify Nodes")**: actual tool presence, versions, Suricata rule files and parsed rules, Wazuh FIM paths and local rules
- Source: `runtime/node_health/probe_cache/` + on-demand SSH tooling probe

### 6. Attack Catalog (`attacks.profiles`)
- All registered attack profiles: MITRE ID/technique, severity, expected alerts/artifacts
- Source: `app_core/infrastructure/attack/catalog.py`

### 7. Attack Executions (`attacks.executions`)
- All executed attacks: timing, target IP/role, exit code, parameters
- Links to forensic case (case_dir)
- Source: `app_core/infrastructure/attack/outputs/*/execution_result.json`

### 8. Forensic Cases (`forensics`)
- All CASE-* directories: creation date, trigger alert, acquisition types, artifact count
- Full forensic analysis report content (summary, findings, conclusion)
- Network findings
- Chain of custody log (last 100 lines)
- Sealed status + lightweight bundle presence
- Source: `app_core/infrastructure/forensics/evidence_store/CASE-*/`

### 9. Campaigns (`campaigns`)

#### Level A — Ground Truth
- Single controlled execution establishing the baseline
- Scenario fingerprint + topology fingerprint

#### Level B — Statistical Repetitions
- Up to 10+ executions of the same attack in the same environment
- Per-execution: CPR (Forensic Continuity Ratio), WCPR (Weighted CPR)
- Scientific degradation flags per execution
- Comparison matrix (ΔWCPR allowed)
- Aggregate statistics: CPR mean/min/max, WCPR mean

#### Level C — Scenario Redeployment (planned)
- Full redeployment from snapshot blueprint in a clean environment
- Validates that the scenario is fully reproducible without shared state
- Status: `NOT_IMPLEMENTED` — infrastructure prepared, execution pending

### 10. FOC Reconstruction (`foc`)
- FOC manifest, scenario BOM, tools BOM
- All attestations: attack, detection, acquisition profile, forensic intervention
- Quality status + completeness score + reproducibility score
- Paper repetition results from `scientific_memory/result_registry/`
- Source: `foc-reconstruction/`

### 11. Relationships (`relationships`)
- Attack execution → forensic case chains
- Campaign → execution → case linkage
- Match confidence: `CONFIRMED | AMBIGUOUS | MISSING`

### 12. Reconstruction Procedures (`procedures`)
- **IT scenario construction**: exact script paths, steps, OpenStack parameters
- **OT node mounting**: PLC (OpenPLC) and SCADA (FUXA) cloud-init templates and steps
- **Detection system configuration**: Suricata Ansible playbook, Wazuh agent installer
- **Tool management**: install/uninstall script paths for each tool
- **Scenario destruction**: what gets destroyed vs what is preserved
- **Level C redeployment**: planned steps for full scenario rebuild from snapshot

### 13. Validation (`validation`)
- 13+ readiness checks across 8 domains
- Readiness flags: `snapshot_capture_ready`, `incident_replay_ready`, `dfir_replay_ready`, `campaign_replay_ready`, `paper_traceability_ready`, `scenario_redeployment_ready`, `overall_reproduction_ready`
- Per-check: status, reason, impact, recommended action

### 14. Provenance (`provenance`)
- All sources consulted
- Warnings and errors from each collector
- SHA-256 of all key files + SHA-256 of the entire snapshot

---

## UI Tabs

| Tab | Contents |
|-----|----------|
| **Overview** | Metrics grid: snapshot ID, status, scenario name, counts |
| **Readiness** | Reproduction readiness flags + validation check table |
| **Scenario** | IT/OT node declarations, topology edges |
| **Infrastructure** | OpenStack instances, node mapping (logical→runtime) |
| **Network** | Subnets/CIDRs, security group rules, floating IPs |
| **Tools** | Per-node tool installation state |
| **Node Verification** | Service states (cached) + live tool/Suricata/Wazuh verification |
| **Attacks** | Attack catalog + executed attacks |
| **Alert → Case Chain** | Attack execution → forensic case linkage |
| **Forensics** | All cases with full analysis, custody log, analysis report |
| **Campaigns** | Level A/B/C with per-execution CPR/WCPR, comparison matrix |
| **FOC** | FOC quality, attestations, paper repetition results |
| **Procedures** | Complete reconstruction playbook |
| **Audit** | Integrity, reproducibility assessment, custody audit, Level B metrics |
| **Provenance** | Data sources, warnings/errors, key file hashes |

---

## API Endpoints

| Method | URL | Description |
|--------|-----|-------------|
| `POST` | `/api/scenario-snapshot/capture` | Start background capture → 202 |
| `GET` | `/api/scenario-snapshot/status` | Poll capture status (`COLLECTING \| IDLE`) |
| `GET` | `/api/scenario-snapshot/snapshots` | List all snapshots (summary) |
| `GET` | `/api/scenario-snapshot/current` | Get the most recent snapshot |
| `GET` | `/api/scenario-snapshot/snapshots/{id}` | Get full snapshot by ID |
| `DELETE` | `/api/scenario-snapshot/snapshots/{id}` | Delete snapshot (`?force=true` for sealed) |
| `POST` | `/api/scenario-snapshot/snapshots/{id}/seal` | Seal snapshot (immutable) |
| `POST` | `/api/scenario-snapshot/snapshots/{id}/validate` | Re-run validation checks |
| `POST` | `/api/scenario-snapshot/snapshots/{id}/verify-nodes` | Trigger live SSH node verification |
| `GET` | `/api/scenario-snapshot/snapshots/{id}/export` | Download as JSON attachment |
| `GET` | `/api/scenario-snapshot/snapshots/{id}/diff?compare_with={id2}` | Diff two snapshots |

---

## Snapshot Lifecycle

```
[Capture]
    │
    ▼
  CAPTURED  ──► background collectors run
    │
    ▼
  COMPLETED / COMPLETED_WITH_WARNINGS / INCOMPLETE
    │
    ▼  (optional: verify-nodes button)
  node_verification.live_verified = true
    │
    ▼  (optional: seal button)
  SEALED  ──► snapshot_hash recomputed, sealed_at_utc set
```

Snapshots in `SEALED` state require `?force=true` to delete.

---

## Snapshot ID Format

```
SS-YYYYMMDD-HHMMSS-XXXX
│   │         │       └── 4-char random hex suffix
│   │         └────────── capture time (UTC)
│   └──────────────────── capture date (UTC)
└──────────────────────── prefix
```

Example: `SS-20260711-143022-A3F1`

---

## Reconstruction Procedures Summary

### Step 1 — IT Scenario Construction
```bash
source admin-openrc.sh
bash app_core/infrastructure/redeployment_module/deploy_scenario_from_json.sh
# Input: scenario/scenario_file.json
# Creates: networks, subnets, security groups, key pair, VMs
```

### Step 2 — OT Node Mounting
- **PLC**: Create OpenStack instance with `industrial-scenario/PLC/cloud_init_plc.yaml` → OpenPLC auto-installs
- **SCADA**: Create OpenStack instance with `industrial-scenario/FUXA/cloud_init_fuxa.yaml` → FUXA auto-installs

### Step 3 — Detection System Configuration
```bash
# Suricata:
ansible-playbook ansible/suricata-auto/playbooks/suricata-aio.yml
# Wazuh:
ansible-playbook ansible/wazuh-agent-pro/install_agent.yml
```

### Step 4 — Tool Installation
- Via platform UI: Tools view → select node → select tool
- Scripts in `tools-installer/scripts-host/install_*.sh`

### Step 5 — Scenario Destruction (after experiments)
```bash
bash scenario/destroy_scenario_openstack_mejorado.sh
# Destroys: VMs, networks, FIPs, security groups
# Preserves: evidence_store/, campaigns/, foc-reconstruction/, scenario_snapshots/
```

---

## Scientific Metrics

### CPR — Forensic Continuity Ratio
Measures the ratio of forensic evidence layers that were consistently captured across Level B
repetitions. Range: 0.0–1.0. Values ≥ 0.7 indicate good reproducibility.

### WCPR — Weighted CPR
Weighted variant of CPR that penalizes gaps in high-importance evidence layers.

### Level B Aggregate Statistics
The snapshot includes: `cpr_mean`, `cpr_min`, `cpr_max`, `wcpr_mean`, `execution_count`
across all Level B executions for the scenario.

### Level C Comparison (planned)
Compare Level C (redeployed scenario) results with Level B baseline using the same
CPR/WCPR framework to validate full reproducibility.

---

## Sentinel Values

| Value | Meaning |
|-------|---------|
| `AVAILABLE` | Data was found and collected successfully |
| `NOT_AVAILABLE` | Source does not exist (directory/file missing) |
| `NOT_CREATED` | Expected artifact was never created |
| `NOT_EXECUTED` | Action was not performed in this scenario run |
| `NOT_IMPLEMENTED` | Feature not yet implemented (Level C) |
| `NOT_RECORDED` | Action happened but was not logged |
| `NOT_VERIFIED` | Cannot verify without live probe |
| `UNRESOLVED` | Status ambiguous — needs investigation |
| `COLLECTION_FAILED` | Collector threw an exception |

---

## Preservation Policy

> **Snapshots are never automatically deleted during scenario destruction.**
> They are the sole reconstruction blueprint.
> Only explicit user action via the "Delete Snapshot" button (with confirmation dialogs)
> can remove a snapshot. Sealed snapshots require double confirmation + `force=true` flag.

---

## Known Issues Fixed

### 2026-07-17 — Forensic Cases tab showed "Analysis: NO" / empty Alert / empty Severity for cases that genuinely had both

`_collect_forensics()` in `service.py` was reading four per-case files from the wrong path — all present
under `CASE-*/` but not where the code looked, so every real case silently produced empty/default values
without ever raising an error (`_load_json(...) or {}` swallows the missing file):

| Field shown as empty | Code was reading | Real file |
|---|---|---|
| `Analysis: NO` | `CASE-*/forensic_analysis_report.json` | `CASE-*/analysis/forensic_analysis_report.json` |
| `Alert: —`, `Severity: —` | `CASE-*/trigger_alert.json` | `CASE-*/metadata/trigger_alert_binding.json` |
| (acquisition detail) | `CASE-*/acquisition_metadata.json` | `CASE-*/metadata/acquisition_profile.json` |
| `Execution: —` | `manifest.json["execution_id"]` (field doesn't exist there) | also falls back to `trigger_alert_binding.json["execution_id"]` now |

Also widened the field-name fallbacks to match `trigger_alert_binding.json`'s real schema
(`attack_profile_id`, `trigger_alert_id`, `original_sensor`/`collector`) instead of only the
guessed names (`attack_id`, `alert_id`/`event_id`, `source`) that file never actually has.

Verified live against `CASE-20260717-000242` / `CASE-20260717-025938` — both now correctly show
`analysis_present: True`, `severity: HIGH`, the real alert signature, and the real `execution_id`.

**Still unresolved, not guessed at**: `Campaign: —` and `Status: NOT_RECORDED` — `manifest.json`
for these cases genuinely has no `campaign_id`/`status` keys (`_load_json` returns only
`case_dir`/`created_at`/`artifacts`). No other file was found with confident campaign linkage for
this case-creation path; left as-is rather than wiring a guessed path that might be wrong for a
different case-creation flow. If you need this fixed, find where `campaign_id` for a
Level-B-generated case is actually recorded first (candidates: `case_digest.json` if regenerated,
or resolving via `trigger_alert_binding.json["execution_id"]` → execution → campaign lookup).
