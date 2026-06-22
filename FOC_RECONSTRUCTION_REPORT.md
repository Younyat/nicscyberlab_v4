# FOC Reconstruction Report

## Scope

This report analyzes the current frontend and backend surfaces of NICS CyberLab from the perspective of a future passive reconstruction layer named **`foc_reconstruction`**.

The analysis is strictly observational. It does not propose replacing or modifying the existing scenario, industrial, tools, attack, monitoring, or forensics workflows. Its purpose is to identify:

- which views exist
- which backend routes they call
- which payloads they emit
- which files, logs, and state objects they generate or modify
- which of those artifacts can be reused to build a scientifically rigorous **Forensic Observational Context Reconstruction**

The intended output of that future module is a **FOC Reconstruction Manifest**, rooted in a single `scenario_id`, and referencing the experiment lifecycle without duplicating the original artifacts.

---

## 1. Reconstruction objective

The reconstruction objective is to answer, with traceable evidence:

1. What scenario existed.
2. Which IT and OT components it contained.
3. Which tools and configuration profiles were associated with each node.
4. Which tools were actually installed.
5. Which attacks or operational actions were executed.
6. Which detections and alerts were produced.
7. Which evidence acquisition and preservation steps were performed.
8. Which forensic analyses were executed.
9. Which outputs, manifests, and timelines were generated.

In that sense, the future module acts as a **scientific reconstruction layer**, not as a workflow engine.

---

## 2. Design constraints for `foc_reconstruction`

The module should be treated as an **independent observer**:

- it should not alter the behavior of the current system
- it should not replace existing JSON, logs, or status files
- it should consume the existing state passively
- it should derive normalized references, hashes, timestamps, relationships, and reconstruction events

This makes it compatible with the current architecture, where the system already generates a large number of useful artifacts, but in a distributed, view-specific, and subsystem-specific way.

---

## 3. Core reconstruction sources already present

The following existing sources are the main candidates for reconstruction:

### Scenario and deployment

- `scenario/scenario_file.json`
- `scenario/deployment_status.json`
- `scenario/destroy_status.json`
- `last_deployment.pid`
- `tf_out/`

### Industrial extension and OT state

- `industrial-scenario/scenarios/industrial_industrial_file.json`
- `industrial-scenario/state/industrial_state.json`
- `industrial-scenario/logs/plc/deploy_*.log`
- `industrial-scenario/logs/scada/deploy_*.log`

### Node tools and configuration state

- `tools-installer-tmp/*.json`
- `tools-installer/installed/*.json`
- `tools-installer/logs/*.log`
- `logs/host_manage.log`

### Attack execution and experimental outputs

- `app_core/infrastructure/attack/outputs/*/result.json`

### Alerts, detections, and triage

- `app_core/infrastructure/forensics/alerts_store/ALERTS-*/alerts.jsonl`
- `app_core/infrastructure/forensics/alerts_store/ALERTS-*/triage.jsonl`
- `app_core/infrastructure/forensics/alerts_store/ALERTS-*/session.json`

### Forensic evidence and analysis

- `app_core/infrastructure/forensics/evidence_store/CASE-*`
- `app_core/infrastructure/forensics/evidence_store/_active_case.txt`
- per-case `manifest.json`
- per-case `chain_of_custody.log`
- per-case `metadata/pipeline_events.jsonl`
- per-case `metadata/time_sync.json`
- per-case `metadata/case_digest.json`
- per-case `metadata/ir/ir_snapshot.json`
- per-case `metadata/fsr/fsr_eval_<run_id>.json`
- per-case `network/`, `disk/`, `memory/`, `industrial/`, `analysis/`, and `derived/` trees

These are already enough to justify a full reconstruction layer.

---

## 4. View-by-view artifact analysis

The views below are organized in three classes:

- **primary state-generating views**
- **secondary observational views**
- **specialized acquisition, detection, and reporting views**

The primary class is the most important for initial implementation of `foc_reconstruction`.

---

## 5. Primary state-generating views

### 5.1 `index-scenario.html`

Purpose:

- IT scenario modeling and deployment.

Frontend controller:

- `app_core/static/js/script.js`

Main user actions:

- create scenario
- load scenario
- destroy scenario
- request console URL

Backend routes used:

- `POST /api/create_scenario`
- `GET /api/deployment_status`
- `GET /api/get_scenario/file`
- `POST /api/destroy_scenario`
- `GET /api/destroy_status`
- `POST /api/console_url`

Payload semantics:

- the scenario editor sends a structured scenario with:
  - `scenario_name`
  - `nodes`
  - `edges`
  - per-node properties such as network, subnet, flavor, image, security group, keypair

Backend processing:

- `create_scenario()` in `app_core/presentation/api.py`
- `get_scenario_by_name()`
- `deployment_status()`
- `destroy_scenario()`
- `destroy_status()`

Internal artifacts created or modified:

- `scenario/scenario_file.json`
- `scenario/deployment_status.json`
- `scenario/destroy_status.json`
- `last_deployment.pid`
- `tf_out/`

Reconstruction value:

- this is the canonical source for the **base IT scenario**
- it provides the first candidate for:
  - `scenario_id`
  - scenario name
  - node list
  - node types
  - node deployment properties
  - edge topology

FOC relevance:

- this view should trigger the creation of the initial FOC Manifest
- it is the main source for a future **Scenario BOM**

### 5.2 `industrial.html`

Purpose:

- OT extension of the active scenario with industrial PLC and SCADA nodes.

Frontend controller:

- `app_core/static/js/industrial.js`

Main user actions:

- load active scenario
- activate PLC mode
- activate SCADA mode
- add industrial component linked to a base node
- save industrial scenario
- delete industrial scenario
- register OT tool by node type
- deploy PLC/OpenPLC
- deploy SCADA/FUXA
- inspect industrial state

Backend routes used:

- `GET /api/get_active_scenario`
- `POST /api/save_industrial_scenario`
- `DELETE /api/delete_industrial_scenario`
- `POST /api/add_industrial_tool`
- `GET /api/industrial/tools_for_node`
- `POST /api/industrial/deploy`
- `GET /api/industrial/state`

Payload semantics:

- industrial scenario payload includes:
  - `scenario_name`
  - `base_scenario`
  - OT nodes
  - OT edges
  - `linked_to`
  - OT installation intent
  - deployment intent for `plc_instance` and `scada_instance`

- industrial tool registration payload includes:
  - `instance`
  - `node_type`
  - `tool`

- industrial deploy payload includes:
  - `component: plc | scada`

Backend processing:

- `save_industrial_scenario()`
- `get_active_scenario()`
- `delete_industrial_scenario()`
- `add_industrial_tool()`
- `get_tools_for_industrial_node()`
- `deploy_industrial_component()`
- `load_industrial_state()` and `save_industrial_state()`

Internal artifacts created or modified:

- `industrial-scenario/scenarios/industrial_industrial_file.json`
- `industrial-scenario/state/industrial_state.json`
- `tools-installer-tmp/<instance>_tools.json` for OT-native tools
- `industrial-scenario/logs/plc/deploy_*.log`
- `industrial-scenario/logs/scada/deploy_*.log`

Reconstruction value:

- this is the canonical source for the **IT/OT extension**
- it provides:
  - OT node declarations
  - OT-to-IT structural relationships
  - deployment intention
  - actual industrial component state

FOC relevance:

- this view is the main source for enriching the **Scenario BOM** from IT-only to IT/OT
- it also provides the first OT-specific lifecycle transitions for the future timeline

### 5.3 `index-tools.html`

Purpose:

- node-level tool assignment, installation, removal, uninstall, and host-side tool management.

Frontend controller:

- `app_core/static/js/index-tools.js`

Main user actions:

- load current instances
- select an instance
- inspect configured tools
- add tool to node
- read tool configuration files
- launch node installation
- remove tool from desired set
- uninstall installed tool
- query host inventory
- query host tool version
- install or uninstall host-side tools

Backend routes used:

- `GET /api/openstack/instances`
- `GET /api/get_tools_for_instance`
- `POST /api/add_tool_to_instance`
- `GET /api/read_tools_configs`
- `POST /api/install_tools`
- `POST /api/uninstall_tool_from_instance`
- `GET /api/host/inventory`
- `GET /api/host/version/<tool_id>`
- `GET /api/host/install/<tool_id>`
- `GET /api/host/uninstall/<tool_id>`

Related host-forensic surface:

- `GET /api/host/forensic/tools`
- `POST /api/host/forensic/install`

Payload semantics:

- desired node tools are sent as an object under `tools`
- installation is launched with:
  - `instance`
  - `instance_id`
  - `tools`
- uninstall includes:
  - `instance`
  - `instance_id`
  - `ip_private`
  - `ip_floating`
  - `tool`

Backend processing:

- `add_tool_to_instance()`
- `read_tools_configs()`
- `install_tools()`
- `get_tools_for_instance()`
- `api_uninstall_tool()`
- `save_as_installed()`
- `merge_tools_state()`
- host-side processing in `host_tools_installer_manager.py`

Internal artifacts created or modified:

- `tools-installer-tmp/<instance>_tools.json`
- `tools-installer/installed/<instance_id>.json`
- `tools-installer/logs/<instance>_<tool>.log`
- `logs/host_manage.log`

Supporting install executors:

- `tools-installer/tools_install_master.sh`
- `tools-installer/scripts/*.sh`
- `tools-installer/scripts-host/*.sh`
- `tools_uninstall_manager/uninstall_scripts-host/*.sh`
- `forensic-host/*.sh`

Reconstruction value:

- this is the canonical source for:
  - desired tools by node
  - actual tools installed by node
  - installation timestamps
  - installation logs
  - host-side tool inventory

FOC relevance:

- this view is the main source for a future **Tools BOM**
- it should contribute both:
  - desired configuration state
  - realized operational state

---

## 6. Secondary scenario and inventory views

These views are mostly observational, but they expose useful correlations and can be consumed as secondary evidence sources.

### 6.1 `inventory.html`

Purpose:

- consolidated OpenStack inventory view.

Frontend controller:

- `app_core/static/js/inventory.js`

Main backend routes:

- `GET /api/openstack/instances/full`
- `GET /api/instance_roles`
- `GET /api/openstack/flavors`
- `GET /api/openstack/networks`
- `GET /api/openstack/security-groups`
- `GET /api/openstack/keypairs`
- `GET /api/openstack/hypervisor-stats`
- `GET /api/host/inventory`
- `GET /api/openstack/traffic/<vm_id>`

Reconstruction value:

- authoritative inventory merge surface
- useful for enriching node metadata:
  - instance UUID
  - IPs
  - flavor
  - networks
  - security groups
  - attached volumes
  - merged tool state

FOC relevance:

- secondary enrichment source for `Scenario BOM`
- useful as a consistency check against `scenario_file.json`

### 6.2 `dashboard.html`

Purpose:

- operational tool access and role-based control actions.

Routes observed:

- `/api/console_url`
- `/api/instance_roles`
- `/api/check_wazuh`
- `/api/change_password`
- `/api/change_keyboard_layout`
- `/api/run_tool_version`

Reconstruction value:

- operational actions rather than structural state
- useful for later reconstruction of operator interaction or administrative changes

FOC relevance:

- possible future `Operator Action Record`
- lower priority than scenario, OT, tools, attack, and forensics

### 6.3 `index.html`

Purpose:

- operational portal with monitoring hooks, AI assistant, and DFIR orchestration stream.

Routes observed:

- `/hud/instances`
- `/api/ai/ask`
- `/api/ai/status`
- `/api/dfir/orchestrator/auto/stream`

Reconstruction value:

- higher-level operational activity
- automatic DFIR orchestration entry point for incident-driven evidence acquisition
- bridge between alert handling and formal case creation

FOC relevance:

- candidate future source for:
  - AI interaction references
  - orchestrated DFIR session references
  - alert-to-case transition records

DFIR-specific observations:

- the frontend opens an SSE stream through `/api/dfir/orchestrator/auto/stream`
- the backend resolves the SSH key, creates a forensic case, anchors an alert timestamp, resolves target VMs, captures traffic, acquires memory, acquires disk, and finalizes case metadata
- the orchestration writes lifecycle events such as:
  - `dfir_orchestration_start`
  - `dfir_orchestration_done`
- the resulting case directory is returned to the frontend and can be reused as the principal case reference in `foc_reconstruction`

FOC implication:

- `index.html` is not only an operational dashboard; it is already a forensic escalation trigger that converts a live alert context into a persistent `CASE-*` evidence structure

### 6.4 `dashboard_especial.html`

Purpose:

- tactical cyber operations dashboard.

Routes observed:

- `/api/hud/instances`
- `/api/openstack/instances/full`
- `/api/get_tools_for_instance`
- `/api/hud/attack/catalog`
- `/api/hud/attack/execute`
- `/api/hud/attack/launch`
- `/api/hud/live_wazuh_stream`
- `/api/hud/monitor/live_wazuh_stream`
- `/api/hud/victim/install_detector`
- `/api/hud/monitor/start_listener`
- `/api/hud/monitor/stop_listener`
- `/api/hud/action`

Internal artifacts already generated:

- `app_core/infrastructure/attack/outputs/*/result.json`

Reconstruction value:

- this is the strongest source for:
  - attack attestations
  - attack timing
  - target role
  - attack metadata
  - expected detections
  - expected artifacts
  - attack execution logs and exit codes

FOC relevance:

- main source for future **Attack Attestation** records
- should be linked to:
  - `scenario_id`
  - target `instance_id`
  - attack profile
  - corresponding alerts

### 6.5 `ot_gui.html` and `ot_gui_f35.html`

Purpose:

- OT-oriented HUD and industrial tactical view.

Routes observed:

- `/api/hud/instances`
- `/api/hud/action`
- `/api/hud/attack/launch`
- `/api/hud/victim/install_detector`
- `/api/hud/monitor/start_listener`
- `/api/hud/monitor/stop_listener`

Reconstruction value:

- similar to `dashboard_especial.html`, but OT-centered

FOC relevance:

- secondary source for OT-side attack and monitoring interaction

### 6.6 `modbus_traffic.html`

Purpose:

- live traffic view for OpenStack instances and host tools.

Routes observed:

- `/api/openstack/instances/full`
- `/api/openstack/traffic/<vm_id>`
- `/api/host/inventory`

Reconstruction value:

- useful for linking traffic observations with instances and selected protocols

FOC relevance:

- candidate source for:
  - network observation references
  - preserved traffic context

---

## 7. Specialized acquisition, reporting, and analysis views

These views are especially relevant for the later phases of `foc_reconstruction`.

### 7.1 `forensics.html`

Frontend controller:

- `app_core/static/js/forensics.js`

Observed routes:

- `/api/openstack/instances/full`
- `/api/openstack/traffic/<vm_id>`
- `/api/forensics/case/create`
- `/api/forensics/case/list`
- `/api/forensics/case/manifest`
- `/api/forensics/case/download`
- `/api/forensics/traffic/preserve/stream`
- `/api/forensics/acquire/disk_kolla/stream`
- `/api/forensics/acquire/memory_lime/stream`
- `/api/forensics/analyze/memory_vol3`
- `/api/forensics/vol3/symbols/generate/stream`
- `/api/forensics/analyze/disk_tsk/stream`
- `/api/forensics/case/memory/list`

Reconstruction value:

- primary source for:
  - acquisition manifests
  - evidence preservation
  - case directories
  - chain-of-custody
  - forensic analysis outputs

Detailed evidence flow:

1. `POST /api/forensics/case/create`
   - creates `app_core/infrastructure/forensics/evidence_store/CASE-<timestamp>`
   - creates the standard case layout:
     - `metadata/`
     - `metadata/ir/`
     - `metadata/ir/inputs/`
     - `metadata/fsr/`
     - `metadata/fsr/inputs/`
     - `network/`
     - `disk/`
     - `memory/`
     - `industrial/`
     - `analysis/`
     - `derived/`
   - creates or updates:
     - `manifest.json`
     - `chain_of_custody.log`
     - `metadata/pipeline_events.jsonl`
     - `metadata/time_sync.json`
     - `metadata/case_digest.json`
     - `metadata/ir/ir_snapshot.json`
     - `metadata/fsr/fsr_eval_<run_id>.json`
   - updates `app_core/infrastructure/forensics/evidence_store/_active_case.txt`

2. IR input preservation at case creation
   - the backend copies existing experiment-defining inputs into the case:
     - `scenario/scenario_file.json`
     - `tools-installer/installed/*.json`
     - `tools-installer-tmp/*.json`
   - preserved copies are stored under:
     - `metadata/ir/inputs/scenario/`
     - `metadata/ir/inputs/tools-installer/installed/`
     - `metadata/ir/inputs/tools-installer-tmp/`
   - these are registered in the case manifest as `ir_input`
   - the snapshot summary itself is registered as `ir_snapshot`

3. Traffic preservation
   - `GET /api/forensics/traffic/preserve/stream`
   - appends pipeline events such as:
     - `pcap_start`
     - `traffic_preserve_start`
     - `pcap_preserved` or `pcap_failed`
     - `traffic_preserve_done` or `traffic_preserve_failed`
   - preserved captures are stored below:
     - `network/traffic_preserved/full_scenario_captures/`
   - all `*.pcap` under that tree are indexed into `manifest.json` as `network_pcap`

4. Memory acquisition
   - `GET /api/forensics/acquire/memory_lime/stream`
   - stores LiME-style memory dumps inside the case memory tree
   - later exposed through:
     - `GET /api/forensics/case/memory/list`
   - dump listings include:
     - relative path
     - size
     - modification time
     - SHA-256 when available

5. Disk acquisition
   - `GET /api/forensics/acquire/disk_kolla/stream`
   - preserves raw disk evidence under the case disk tree
   - successful acquisitions are registered in `manifest.json`
   - pipeline events record `disk_preserved` or `disk_failed`

6. Memory analysis
   - `POST /api/forensics/analyze/memory_vol3`
   - executes `analyze_memory_vol3.sh`
   - writes outputs under:
     - `analysis/vol3/<vm_id>/`
   - registers the output directory in `manifest.json` as `vol3_output_dir`

7. Disk analysis
   - `GET /api/forensics/analyze/disk_tsk/stream`
   - executes `analyze_disk_tsk.sh`
   - writes outputs under:
     - `analysis/tsk/<run_id>/<disk_stem>/`
   - registers the output directory in `manifest.json` as `tsk_output_dir`
   - appends events:
     - `disk_analysis_start`
     - `disk_analysis_done` or `disk_analysis_failed`

8. Reporting layer
   - the reporting API reads:
     - `manifest.json`
     - `chain_of_custody.log`
     - `metadata/pipeline_events.jsonl`
     - `metadata/case_digest.json`
     - `metadata/time_sync.json`
   - it enriches artifacts with:
     - family classification
     - inferred target
     - acquisition method
     - forensic value

What this means for `foc_reconstruction`:

- `forensics.html` already exposes the exact transition from case creation to acquisition to analysis
- the future module does not need to reconstruct low-level evidence collection logic; it mainly needs to observe:
  - which case was created
  - which inputs were snapshotted
  - which artifacts were indexed
  - which analyses generated output
  - which custody and pipeline events were appended

FOC relevance:

- foundational for:
  - `acquisition_manifests`
  - `preservation_manifests`
  - `chain_of_custody`
  - `forensic_analysis_reports`
  - `ir_input_snapshots`
  - `case_integrity_digests`
  - `alert_to_case_escalation_records`

### 7.2 `forensic_report_analysis.html`

Frontend controller:

- `app_core/static/js/forensic_report_analysis.js`

Observed routes:

- `/api/forensics/report/cases`
- `/api/forensics/report/summary`
- `/api/forensics/report/manifest`
- `/api/forensics/report/chain-of-custody`
- `/api/forensics/report/pipeline-events`
- `/api/forensics/case/download`

Reconstruction value:

- derived reporting layer over already-preserved cases

FOC relevance:

- excellent source for:
  - normalized summary references
  - timeline extraction
  - semantic post-processing references

### 7.3 `forensic_inventory.html`

Frontend controller:

- `app_core/static/js/forensic_inventory.js`

Observed routes:

- `/api/host/forensic/tools`
- `/api/host/forensic/install`
- `/api/openstack/flavors`
- `/api/openstack/networks`
- `/api/openstack/security-groups`
- `/api/openstack/keypairs`
- `/api/openstack/instances/full`
- `/api/openstack/hypervisor-stats`
- `/api/host/inventory`

Reconstruction value:

- host forensic capability surface
- infrastructure context enrichment

FOC relevance:

- useful for:
  - host-side analysis readiness
  - environment capability attestation

### 7.4 `forensic.html`

Frontend controller:

- `app_core/static/js/forensic.js`

Observed routes:

- `/api/openstack/instances`
- `/api/get_tools_for_instance`

Reconstruction value:

- instance capability summary for forensic preparation

FOC relevance:

- secondary enrichment source for node forensic readiness

---

## 8. Other views with lower immediate relevance

These views are real parts of the system, but they are lower priority for the first version of `foc_reconstruction`.

### `initial.html`

- environment bootstrap and initial generator
- relevant routes:
  - `/api/run_initial_environment_setup`
  - `/api/run-initial-generator-stream`
  - `/api/destroy_initial_environment_setup`

FOC value:

- could be treated as pre-scenario environment provenance

### `adv_detection.html`

- advanced detection logic
- route usage found in `adv_detection.js`

FOC value:

- possible future detection enrichment layer

### `ai_module.html`

- AI deployment and status
- routes:
  - `/api/ai/logs`
  - `/api/ai/status`
  - `/api/ai/deploy`

FOC value:

- AI subsystem provenance

### `ai`, `etc_lab`, `honeyv`, `ciberia_lab`, `nicscyberlab_dashboard`, `terminal`, `ssh_terminal`

FOC value:

- useful only if the reconstruction layer is later extended to operator-assistance, Windows exchange, ETC deployment, or terminal session provenance

For the first scientific version of `foc_reconstruction`, they are not mandatory.

---

## 9. Artifact classes already present

The existing project already produces enough artifacts to support a formal reconstruction model. The following classification is recommended.

### 9.1 Structural artifacts

Describe what the scenario is.

- `scenario/scenario_file.json`
- `industrial-scenario/scenarios/industrial_industrial_file.json`

### 9.2 Lifecycle state artifacts

Describe what phase the scenario or subsystem is in.

- `scenario/deployment_status.json`
- `scenario/destroy_status.json`
- `industrial-scenario/state/industrial_state.json`

### 9.3 Desired configuration artifacts

Describe what is intended or requested.

- `tools-installer-tmp/*.json`

### 9.4 Realized configuration artifacts

Describe what was actually installed or completed.

- `tools-installer/installed/*.json`
- `industrial_state.json`

### 9.5 Execution log artifacts

Describe what scripts executed and their textual output.

- `tools-installer/logs/*.log`
- `industrial-scenario/logs/*/*.log`
- `logs/host_manage.log`

### 9.6 Attack execution artifacts

Describe ATT&CK-aligned or tactical attack runs.

- `app_core/infrastructure/attack/outputs/*/result.json`

### 9.7 Detection and alert artifacts

Describe what was detected.

- `alerts.jsonl`
- `triage.jsonl`
- `session.json`

### 9.8 Evidence acquisition and preservation artifacts

Describe what was acquired and preserved.

- `app_core/infrastructure/forensics/evidence_store/CASE-*/manifest.json`
- `app_core/infrastructure/forensics/evidence_store/CASE-*/chain_of_custody.log`
- `app_core/infrastructure/forensics/evidence_store/CASE-*/metadata/pipeline_events.jsonl`
- `app_core/infrastructure/forensics/evidence_store/CASE-*/metadata/time_sync.json`
- `app_core/infrastructure/forensics/evidence_store/CASE-*/metadata/case_digest.json`
- `app_core/infrastructure/forensics/evidence_store/CASE-*/metadata/ir/ir_snapshot.json`
- `app_core/infrastructure/forensics/evidence_store/CASE-*/metadata/ir/inputs/**`
- `app_core/infrastructure/forensics/evidence_store/CASE-*/metadata/fsr/fsr_eval_<run_id>.json`
- `app_core/infrastructure/forensics/evidence_store/CASE-*/network/traffic_preserved/full_scenario_captures/**/*.pcap`
- disk artifacts under `CASE-*/disk/`
- memory artifacts under `CASE-*/memory/`
- OT-derived or protocol-context artifacts under `CASE-*/industrial/`

### 9.9 Analysis artifacts

Describe the interpretation layer.

- Volatility outputs under `CASE-*/analysis/vol3/<vm_id>/`
- TSK outputs under `CASE-*/analysis/tsk/<run_id>/<disk_stem>/`
- report summaries exposed by `/api/forensics/report/summary`
- enriched manifest view exposed by `/api/forensics/report/manifest`
- custody view exposed by `/api/forensics/report/chain-of-custody`
- pipeline view exposed by `/api/forensics/report/pipeline-events`
- derived OT exports and semantic summaries when present under `CASE-*/derived/` or `CASE-*/industrial/`

---

## 10. Reuse for `Scenario BOM`

The future `Scenario BOM` should be constructed from:

### Primary sources

- `scenario/scenario_file.json`
- `industrial-scenario/scenarios/industrial_industrial_file.json`

### Secondary enrichment

- `/api/openstack/instances/full`
- `industrial-scenario/state/industrial_state.json`

### Expected Scenario BOM fields

- `scenario_id`
- `scenario_name`
- `base_scenario_path`
- `created_at`
- `nodes`
- `edges`
- `node_roles`
- `node_types`
- `deployment_properties`
- `ot_extensions`
- `industrial_linkages`
- `node_instance_bindings`
- `scenario_state`

### Scientific utility

This produces a formal description of the composition of the experiment:

- what was modeled
- what was added as OT
- what was deployed
- what relationships existed between components

---

## 11. Reuse for `Tools BOM`

The future `Tools BOM` should be constructed from:

### Primary sources

- `tools-installer-tmp/*.json`
- `tools-installer/installed/*.json`

### Secondary enrichment

- `merge_tools_state()` logic in `app_core/presentation/api.py`
- `/api/openstack/instances/full`
- host inventories

### Expected Tools BOM fields

- `scenario_id`
- `instance_id`
- `instance_name`
- `node_type`
- `desired_tools`
- `desired_profiles`
- `installed_tools`
- `installation_timestamps`
- `installation_logs`
- `host_tool_inventory`
- `industrial_allowed_tools`
- `state_resolution`

### Scientific utility

This produces a precise distinction between:

- requested tooling
- successfully installed tooling
- node-local configuration profiles
- host-side analysis capabilities

---

## 12. Reuse for future FOC object classes

The artifacts already present support the following reconstruction classes.

### 12.1 Scenario Attestation

Sources:

- scenario JSON
- industrial scenario JSON
- deployment status

### 12.2 Tools Attestation

Sources:

- tools tmp JSON
- installed JSON
- installation logs

### 12.3 Attack Attestation

Sources:

- `attack/outputs/*/result.json`
- tactical dashboards

### 12.4 Detection Attestation

Sources:

- alert store JSONL
- triage JSONL
- monitoring streams when captured externally

### 12.5 Acquisition Manifest

Sources:

- forensics case creation
- preserve traffic stream
- disk and memory acquisition streams

Important concrete inputs:

- `manifest.json`
- `metadata/pipeline_events.jsonl`
- `metadata/time_sync.json`
- `metadata/case_digest.json`
- `network/traffic_preserved/full_scenario_captures/**/*.pcap`
- `disk/`
- `memory/`

### 12.6 Preservation Manifest

Sources:

- case manifest
- artifact registration
- custody appenders

Important concrete inputs:

- `manifest.json`
- `chain_of_custody.log`
- artifact index entries for:
  - `network_pcap`
  - disk-preservation artifacts
  - memory-preservation artifacts
  - `ir_input`
  - `ir_snapshot`
  - `custody_log`
  - `time_sync`
  - `fsr_eval`

### 12.7 Chain of Custody

Sources:

- existing forensics custody files
- attack result chain-of-custody embedded in `result.json`

Important concrete inputs:

- `CASE-*/chain_of_custody.log`
- case digest references in `CASE-*/metadata/case_digest.json`
- pipeline-to-custody correlation using shared `run_id`

### 12.8 Forensic Analysis Report

Sources:

- Volatility analysis outputs
- TSK outputs
- report summary endpoints

Important concrete inputs:

- `CASE-*/analysis/vol3/<vm_id>/`
- `CASE-*/analysis/tsk/<run_id>/<disk_stem>/`
- `/api/forensics/report/summary`
- `/api/forensics/report/manifest`
- `/api/forensics/report/chain-of-custody`
- `/api/forensics/report/pipeline-events`

### 12.9 Semantic Observation Report

Sources:

- report analysis surfaces
- OT exports
- summarized cases

### 12.10 Timeline

Sources:

- deployment status timestamps
- installed tool timestamps
- attack output timestamps
- alert session timestamps
- custody events
- pipeline events

Additional high-value forensic anchors:

- automatic DFIR start from `/api/dfir/orchestrator/auto/stream`
- `case_created`
- `ir_inputs_preserved`
- `time_sync_exported`
- `fsr_eval_written`
- `pcap_start` / `pcap_preserved`
- memory acquisition completion
- `disk_preserved`
- `disk_analysis_start` / `disk_analysis_done`
- `dfir_orchestration_start` / `dfir_orchestration_done`

---

## 13. Recommended passive update triggers

The future module should update itself when the following events occur:

1. `scenario/scenario_file.json` changes
2. `industrial-scenario/scenarios/industrial_industrial_file.json` changes
3. `industrial-scenario/state/industrial_state.json` changes
4. any `tools-installer-tmp/*.json` changes
5. any `tools-installer/installed/*.json` changes
6. any `tools-installer/logs/*.log` changes
7. any `industrial-scenario/logs/*/*.log` changes
8. any `attack/outputs/*/result.json` changes
9. any new `alerts_store/ALERTS-*` session appears
10. any case directory or manifest changes in the forensics subsystem

These triggers can be implemented with:

- filesystem polling
- inotify-based watchers
- explicit regeneration endpoint
- startup rescan and consistency rebuild

For reliability, the first implementation should support both:

- passive scan on demand
- explicit `POST /api/foc/regenerate`

---

## 14. Recommended independent root-level structure

The user requirement is to keep the module independent and root-level. A compatible design would be:

```text
foc-reconstruction/
├── foc_manifest.json
├── scenario_bom.json
├── tools_bom.json
├── indexes/
├── cache/
├── reports/
└── hashes/
```

## Volatility 3 symbols generation (new)

The analysis pipeline now includes a symbol-management and generation helper for Volatility 3 Linux symbols.

- Symbols are stored under `/opt/nics-vol3-symbols/linux` and a `symbols_manifest.json` is maintained next to it.
- The analysis preflight will attempt to match captured kernel banners to local symbol files. If no symbol is found, the system will:
  1. Attempt to generate a JSON symbol using a local `vmlinux` (if present inside the case evidence) via `dwarf2json`.
  2. If the above fails and SSH credentials are available, run `generate_vol3_symbols_ssh.sh` to fetch debug packages from the captured VM and generate symbols.

Usage (API): `POST /api/foc/cases/<case_id>/symbols/generate` with optional JSON body: `{"dump_id": "<id>", "ssh_user": "ubuntu", "ssh_key": "/path/to/key", "vm_ip": "10.0.2.5"}`.

There is a smoke-test helper at: `app_core/infrastructure/forensics/scripts/test_vol3_symbol_generation.py` which attempts generation for the first available case.


This root-level artifact directory can be managed by a backend module implemented under:

```text
app_core/infrastructure/foc_reconstruction/
├── __init__.py
├── foc_manifest_manager.py
├── foc_sources.py
├── foc_bom_builder.py
├── foc_hashing.py
├── foc_events.py
├── foc_schema.py
└── foc_endpoints.py
```

That split preserves a good separation between:

- code under `app_core/infrastructure`
- generated reconstruction outputs at project root

---

## 15. Minimum internal identifiers and relationships

The future manifest should normalize the following identifiers:

- `foc_id`
- `scenario_id`
- `node_id`
- `instance_id`
- `tool_id`
- `attack_id`
- `alert_id`
- `evidence_id`
- `case_id`
- `artifact_id`
- `timeline_event_id`

Relationship edges should capture:

- `scenario_id -> node_id`
- `node_id -> instance_id`
- `node_id -> desired_tool`
- `node_id -> installed_tool`
- `node_id -> attack_execution`
- `attack_execution -> alert`
- `alert -> triage`
- `node_id -> evidence`
- `evidence -> preservation`
- `evidence -> analysis`
- `case_id -> artifact`

---

## 16. Scientific interpretation

The strongest scientific value of `foc_reconstruction` is not in introducing new attack or forensic logic. Its value lies in making the experiment **reconstructible**:

- structurally
- operationally
- evidentially
- analytically

The current platform already generates the necessary raw material, but in a distributed and subsystem-specific manner. A reconstruction layer can convert that into a single, verifiable, and reference-oriented manifest.

In scientific terms, the future module would support claims such as:

- which infrastructure composition existed during an experiment
- which ATT&CK-aligned actions were executed
- which instrumentation was present on each node
- which sensor families produced detections
- which evidence was collected and preserved
- which analyses were performed
- how the resulting conclusions can be traced back to the original artifacts

---

## 17. Final conclusion

The existing system already contains the main data sources needed for a first-class **Forensic Observational Context Reconstruction** layer.

The most important inputs are:

- `scenario/scenario_file.json`
- `industrial-scenario/scenarios/industrial_industrial_file.json`
- `industrial-scenario/state/industrial_state.json`
- `tools-installer-tmp/*.json`
- `tools-installer/installed/*.json`
- `tools-installer/logs/*.log`
- `app_core/infrastructure/attack/outputs/*/result.json`
- `app_core/infrastructure/forensics/alerts_store/ALERTS-*/*`
- forensic case manifests, custody files, pipeline events, and analysis outputs

The first version of `foc_reconstruction` should therefore focus on:

1. passive source ingestion
2. stable ID normalization
3. Scenario BOM generation
4. Tools BOM generation
5. attack, detection, and evidence reference indexing
6. timeline reconstruction
7. FOC Manifest generation with paths, hashes, timestamps, states, and relationships

This can be achieved without altering the current operational workflows, making the module suitable as an independent, parallel, scientifically defensible reconstruction layer.
