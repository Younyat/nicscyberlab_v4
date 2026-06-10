![Fondos_INCIBE](Images_readme/logo_fondos_incibe.png)

This repository is part of 
- The project "CiberIA: Investigación e Innovación para la Integración de Ciberseguridad e Inteligencia Artificial" (Proyecto C079/23), financed by "European Union NextGeneration-EU, the Recovery Plan, Transformation and Resilience", through INCIBE.
- The Programa Global de Innovación en Seguridad for the promotion of Cátedras de Ciberseguridad en España, funded by the European Union NextGeneration-EU Funds, through the Instituto Nacional de Ciberseguridad (INCIBE).




---

# NICS CyberLab

NICS CyberLab is a reproducible cybersecurity experimentation and training platform for **IT and hybrid IT/OT environments**. It combines automated infrastructure deployment, visual scenario construction, node-level tool installation, role-oriented operational access, attack-and-detection exercises, and forensic acquisition, preservation, analysis, and reporting inside a single workflow.

The platform is designed to support both **educational use** and **professional experimentation**. A user can deploy the environment, build a scenario, prepare the required tools, execute attacks and monitoring actions, preserve evidence when incident severity justifies forensic escalation, and review the resulting case through a dedicated forensic reporting surface.

---

## 1. Infrastructure deployment

This is the first step and the most important requirement before using the rest of the platform.

### Baseline host requirements

Use the following baseline for a stable deployment:

- **Ubuntu 24.04 LTS**
- **8 CPU cores**
- **48 GB RAM**
- **500 GB of free disk space**
- **Hardware virtualization enabled**

If the platform is executed inside **VirtualBox** or **VMware**, virtualization must be enabled in the BIOS or UEFI and exposed to the guest. In practice, this means enabling **nested virtualization**. Without it, the OpenStack environment may fail to deploy correctly or may behave unreliably.

A full OpenStack deployment typically takes **around 30 minutes** under these baseline conditions.

### Deploy the OpenStack environment

Run the installer from the project root:

```bash
bash openstack-installer/openstack-installer.sh
```

After the deployment completes:

- the OpenStack virtual environment is created automatically at:

```bash
openstack-installer/openstack_venv
```

- the OpenStack credentials file is generated automatically at:

```bash
admin-openrc.sh
```

### Start the platform UI

To launch the platform dashboards, run:

```bash
bash start_dashboard.sh
```

This script is located in the project root.

On the **first launch**, startup may take longer because dependencies need to be installed.

### Recover OpenStack services after disk-related failures

If OpenStack services stop because the host ran out of disk space, first recover free space and then restart the services with:

```bash
bash restart_openstack.sh
```

This script is also located in the project root.

---

## 2. Platform workflow

NICS CyberLab follows a progressive workflow:

1. **Deploy the OpenStack infrastructure**
2. **Start the platform dashboards**
3. **Create the base IT scenario**
4. **Extend the scenario with industrial components when needed**
5. **Install the required tools on the deployed nodes**
6. **Access the installed tools through the operational portal**
7. **Execute attack-and-detection exercises**
8. **Preserve and analyze evidence when incidents require forensic escalation**
9. **Review the preserved case, artifact inventory, manifest, chain of custody, and pipeline events**
10. **Validate reconstruction completeness, traceability, and reproducibility through the FOC layer**

This design allows the user to move from infrastructure provisioning to full cybersecurity experimentation and case-centered forensic review without leaving the platform.

---

## 3. Main platform services

## IT Scenario Editor

The **IT Scenario Editor** is the service used to create and deploy the base IT scenario on the virtualized infrastructure.

It allows the user to:

- create nodes with roles such as **monitor**, **attack**, and **victim**
- connect nodes visually through an editable topology
- configure deployment parameters per node
- load, deploy, and destroy scenarios from the same interface

Each node can be configured with deployment-related fields such as:

- primary network
- primary subnetwork
- image
- flavor
- security group
- SSH key

For a basic three-node IT scenario, deployment typically takes **around eight minutes**, depending on infrastructure load and resource availability.

![IT Scenario Editor](Images_readme/it_scenario_editor.png)

### Why it matters

This service reduces the gap between conceptual topology design and real OpenStack deployment. Instead of manually preparing instances, networks, and deployment parameters, the user can model the scenario visually and launch it directly.

---

## Industrial Scenario Editor

The **Industrial Scenario Editor** extends the base IT scenario with OT-oriented components and makes it possible to build hybrid **IT/OT** environments.

It allows the user to:

- load the base scenario
- add industrial components such as **PLC** and **SCADA**
- connect industrial nodes to the existing topology
- save or remove the industrial extension
- open the industrial application after deployment

Once an industrial component is available, the user can continue practical configuration tasks. For example, a deployed PLC can be opened in **OpenPLC** for control logic setup.

The project also includes prepared industrial examples, including:

```bash
PLC/plc_programs/TankControl.st
```

![Industrial Scenario Editor](Images_readme/industrial_scenario_editor.png)

### Why it matters

This service transforms a conventional IT scenario into a hybrid IT/OT environment without forcing the user into a separate workflow. The industrial stack becomes part of the same scenario model, which improves continuity, usability, and reuse.

---

## Instance Tools Manager

The **Instance Tools Manager** prepares the deployed scenario for practical use by installing the required tools on each node.

It allows the user to:

- inspect the currently deployed instances
- select a target node
- view the node in the current topology
- choose tools from a predefined catalog
- launch automated installation workflows
- observe live terminal feedback
- inspect host-side tools on the control node

The node-side installation catalog exposed by this service includes the following prepared entries:

- **Security analytics and endpoint telemetry**
  - Wazuh
  - Wazuh Agent
- **Network and protocol sensors**
  - Suricata
  - Snort
  - TCPDump
  - Zeek
- **Offensive and assessment tooling**
  - Nmap
  - MITRE Caldera
  - MITRE Caldera Agent
- **OT / ICS experiment tooling**
  - Caldera OT Plugins
  - mbpoll

The same node-level catalog also exposes prepared configuration-oriented entries associated with detection workflows:

- **Wazuh-oriented configuration profile**
  - Wazuh FIM Realtime
- **Rollback / restoration profiles**
  - Wazuh + Suricata Integration Rollback
  - Suricata ICMP Rule Rollback

At the industrial node layer, the project also defines a restricted installation policy for native OT services:

- **Industrial PLC nodes**
  - OpenPLC
- **Industrial SCADA nodes**
  - FUXA

This means the installation surface is not limited to generic tools only. It includes:

- executable security tooling
- detection sensor deployment
- OT protocol utilities
- prepared configuration profiles
- controlled rollback entries

At the host level, the control node inventory service exposes prepared install and uninstall workflows for:

- The Sleuth Kit (TSK)
- Tcpdump
- Tshark
- Termshark
- Volatility 3
- Scapy
- mbpoll

In addition, the forensic host API defines a dedicated host-side forensic installation surface for:

- Volatility 3
- Autopsy
- The Sleuth Kit (TSK)
- Tcpdump
- Tshark
- Termshark

Installation output is shown in the interface and preserved in backend logs for troubleshooting, auditability, and later review.

Scientifically, this separation is important because it distinguishes between:

- **node-level operational tooling**, deployed inside workload instances
- **node-level detection configuration entries**, used to prepare or restore telemetry behavior
- **industrial node constraints**, which restrict the allowed OT software set by node type
- **host-level analysis tooling**, installed on the control or forensic host rather than inside scenario workloads

![Instance Tools Manager](Images_readme/instance_tools_manager.png)

### Why it matters

This service turns a deployed scenario into an experiment-ready environment. Instead of manually connecting to each instance and installing tools one by one, the user can prepare the nodes centrally and consistently.

---

## Security Training and Tools Portal

The **Security Training and Tools Portal** is the service that gives the user direct access to the tools already installed on the scenario nodes.

It organizes the environment into role-based panels such as:

- **Attacker Node**
- **Central Monitor**
- **Victim Node**

From these panels, the user can:

- open the real dashboard or access point of the installed tool
- check whether a node is active
- open the remote instance console
- perform auxiliary management actions
- observe operational feedback in the activity area

This service is designed for both **training** and **professional practice**. The user works with real tools inside the deployed scenario rather than simplified mock interfaces.

![Security Training and Tools Portal](Images_readme/security_training_portal.png)

### Why it matters

This is the point where the platform becomes a true hands-on training environment. The user moves from deployment and installation into direct operational use of professional cybersecurity tooling.

---

## Tactical Cyber Operations Dashboard

The **Tactical Cyber Operations Dashboard** unifies attack execution, monitoring, contextual awareness, and feedback inside a single operational interface.

Its main capabilities include:

- an interactive battlefield map
- target locking through node selection
- attack launch from the attacker side
- contextual node intelligence
- dual-terminal feedback
- live monitoring output
- quick access to offensive and defensive tooling

The dashboard is inspired by a **fighter aircraft head-up display** model and is intended for integrated attack-and-detection exercises.

The user can:

- select a target node directly on the map
- inspect the node context before acting
- launch predefined attacks
- observe victim-side telemetry
- observe monitoring-side telemetry
- compare offensive behavior with defensive visibility in real time

Typical offensive actions include:

- categorized scientific attack profiles
- target-oriented operational launch
- dual visibility of victim-side and monitoring-side telemetry
- alignment between attack execution and alert generation

### ATT&CK-aligned scientific taxonomy

The dashboard presents offensive actions as **MITRE ATT&CK-aligned experimental profiles** backed by a structured catalog and execution layer.

The backend catalog is defined in:

```bash
app_core/infrastructure/attack/catalog.py
```

Each profile is represented through a professional `attack_id` and metadata such as:

- ATT&CK or ATT&CK for ICS identifier
- internal attack ID
- domain
- tactic
- target-role constraints
- detection engine
- severity
- execution mode
- expected alerts
- expected forensic artifacts
- rollback requirement
- DFIR escalation flag
- backend script mapping

This design separates:

- the **scientific technique identity**
- the **dashboard presentation**
- the **execution backend**
- the **forensic expectations**

### MITRE provenance and methodological rationale

The attack catalog is derived from **MITRE ATT&CK** and **MITRE ATT&CK for ICS**, which provide publicly recognized technique identifiers, tactic placement, and adversary-behavior semantics.

This matters scientifically because it gives the platform:

- a **standardized behavioral vocabulary**
- a **reproducible technique selection model**
- a **defensible mapping between attack behavior and expected telemetry**
- a **clear link between experimental scenarios and established cybersecurity knowledge**

In practical terms, each CyberLab attack profile is built by starting from a MITRE technique and then constraining it to:

- the CyberLab target role
- the allowed execution scope
- the expected detector
- the expected forensic artifacts
- the rollback and DFIR policy

This means the platform does not claim to reproduce the full real-world complexity of every ATT&CK technique. Instead, it implements **controlled laboratory realizations** of ATT&CK behaviors that preserve the scientific identity of the technique while respecting safety and reproducibility constraints.

The catalog schema is centered on reproducibility. A typical profile includes:

```text
attack_id
legacy_name
display_name
category
description
mitre_domain
mitre_id
mitre_technique
tactic
detection_engine
target_roles
severity
execution_mode
script
expected_alerts
expected_artifacts
safety_policy
rollback_required
dfir_escalation
```

### Existing ATT&CK-aligned techniques

The operational attack set is organized as formal ATT&CK profiles:

- **ICMP Reconnaissance**
  - `T1595_ACTIVE_SCANNING_ICMP_RECON`
  - `T1595 - Active Scanning`
- **Port Scan Reconnaissance**
  - `T1046_NETWORK_SERVICE_DISCOVERY_PORT_SCAN`
  - `T1046 - Network Service Discovery`
- **Unauthorized SSH Attempt**
  - `T1110_001_SSH_PASSWORD_GUESSING`
  - `T1110.001 - Password Guessing`
- **Controlled File Tamper**
  - `T1565_001_STORED_DATA_MANIPULATION_FIM`
  - `T1565.001 - Stored Data Manipulation`
- **Data Exfiltration**
  - `T1048_EXFILTRATION_OVER_ALTERNATIVE_PROTOCOL`
  - `T1048 - Exfiltration Over Alternative Protocol`
- **Modbus Register Manipulation**
  - `T0831_MANIPULATION_OF_CONTROL_MODBUS`
  - `T0831 - Manipulation of Control`
- **Multi-Vector Validation**
  - `CHAIN_MULTI_VECTOR_DETECTION_VALIDATION`
  - composite ATT&CK validation chain

These baseline techniques cover the main experimental layers required by the platform:

- **Reconnaissance**
  - `T1595` and `T1046` model active scanning and service discovery
- **Credential Access**
  - `T1110.001` models failed SSH password guessing
- **Impact and Integrity**
  - `T1565.001` models monitored file tampering for FIM validation
- **Collection and Exfiltration**
  - `T1048` models controlled outbound transfer of lab data
- **ICS / OT manipulation**
  - `T0831` models controlled Modbus-oriented manipulation of process control
- **Composite detection validation**
  - the multi-vector chain combines multiple ATT&CK-aligned steps into a single experimental sequence

### Advanced ATT&CK Techniques panel

The tactical dashboard contains a dedicated **Advanced ATT&CK Techniques** panel. It is organized into three scientific sections:

- **Existing ATT&CK-Aligned Techniques**
- **Advanced Suricata-Detectable Techniques**
- **Advanced Wazuh-Detectable Techniques**

Each ATT&CK card shows:

- attack display name
- MITRE ID and technique name
- ATT&CK domain
- tactic
- detection engine
- allowed target roles
- severity
- execution mode
- expected alerts
- expected forensic artifacts
- launch action

This allows the operator to evaluate the detection model and evidence expectations **before** launching a technique.

The figures below show the operational ATT&CK view of the dashboard. The first image presents the full scenario together with the categorized ATT&CK technique surface, while the second image shows the detailed node intelligence pane used to assess target state, installed tools, exposure surface, and forensic readiness before launch.

![Tactical Cyber Operations Dashboard](Images_readme/tactical_cyber_operations_dashboard.png)
![Tactical Cyber Operations Dashboard](Images_readme/tactical_cyber_operations_dashboard_2.png)

### Advanced Suricata-detectable profiles

The Suricata-oriented section includes:

- `T1595_ACTIVE_SCANNING_ICMP_RECON`
- `T1046_NETWORK_SERVICE_DISCOVERY_PORT_SCAN`
- `T1048_EXFILTRATION_OVER_ALTERNATIVE_PROTOCOL`
- `T1105_INGRESS_TOOL_TRANSFER`
- `T1570_LATERAL_TOOL_TRANSFER`
- `T0846_ICS_REMOTE_SYSTEM_DISCOVERY`
- `T0861_POINT_AND_TAG_IDENTIFICATION`
- `T0877_IO_IMAGE`
- `T0836_MODIFY_PARAMETER`
- `T1692_001_UNAUTHORIZED_COMMAND_MESSAGE`
- `T0831_MANIPULATION_OF_CONTROL_MODBUS`

These profiles focus on **network-visible evidence**, OT subnet probing, Modbus visibility, and protocol-level anomaly generation. In the hybrid IT/OT model, Suricata is the primary engine for network and ICS telemetry, while Wazuh can ingest related `eve.json` events.

At a methodological level, this section groups techniques whose primary observability comes from:

- packet captures
- flow-level behavior
- protocol transactions
- internal host-to-host transfers
- Modbus reads and writes

This is why these profiles are presented as **Suricata-detectable techniques** rather than generic attacks. Their selection is driven by the kind of evidence the platform aims to generate and validate.

### Advanced Wazuh-detectable profiles

The Wazuh-oriented section includes:

- `T1110_001_SSH_PASSWORD_GUESSING`
- `T1078_VALID_ACCOUNTS_SSH_LOGIN`
- `T1082_SYSTEM_INFORMATION_DISCOVERY`
- `T1016_SYSTEM_NETWORK_CONFIGURATION_DISCOVERY`
- `T1049_SYSTEM_NETWORK_CONNECTIONS_DISCOVERY`
- `T1057_PROCESS_DISCOVERY`
- `T1033_SYSTEM_OWNER_USER_DISCOVERY`
- `T1087_ACCOUNT_DISCOVERY`
- `T1083_FILE_AND_DIRECTORY_DISCOVERY`
- `T1005_DATA_FROM_LOCAL_SYSTEM`
- `T1560_ARCHIVE_COLLECTED_DATA`
- `T1565_001_STORED_DATA_MANIPULATION_FIM`
- `T1070_004_FILE_DELETION`
- `T1059_COMMAND_AND_SCRIPTING_INTERPRETER`
- `T1036_MASQUERADING`
- `T1027_OBFUSCATED_FILES_OR_INFORMATION`
- `T1562_001_DISABLE_OR_MODIFY_TOOLS_SIMULATED`

These profiles are oriented toward **host-visible activity** such as authentication, command execution, discovery, file creation, file deletion, integrity changes, and simulated security-tool interference.

Methodologically, these techniques were selected because their expected observability is primarily local to the endpoint:

- authentication logs
- process execution traces
- shell command history or auditd-style telemetry
- file integrity events
- service-state changes

This allows CyberLab to evaluate whether Wazuh-based instrumentation can capture ATT&CK-aligned host activity in a reproducible way.

### Professional summary of the ATT&CK strategy set

The ATT&CK strategy set implemented in CyberLab can be summarized as follows:

- **Enterprise reconnaissance and discovery**
  - active scanning, service discovery, system discovery, account discovery, process discovery, and file discovery
- **Enterprise credential access and remote access validation**
  - failed SSH password guessing and controlled valid-account login
- **Enterprise collection, staging, and exfiltration**
  - local data collection, archiving, ingress transfer, lateral transfer, and exfiltration over alternative protocol
- **Integrity, impact, and anti-forensic behavior**
  - file tampering, file deletion, masquerading, obfuscation, and simulated tool interference
- **ICS discovery and control-oriented behavior**
  - OT subnet discovery, point and tag identification, I/O image acquisition, parameter modification, unauthorized command messaging, and manipulation of control

Taken together, these families provide a coherent attack strategy model for a hybrid IT/OT laboratory. The key point is that the catalog is **behavior-centered and ATT&CK-referenced**, which makes the experimental design stronger than a simple list of arbitrary attack names.

### Execution and safety model

Every ATT&CK profile is constrained by a safety model. The platform enforces or documents the following principles:

- no external targets
- no credential dumping
- no malware payloads
- no uncontrolled denial of service
- no real destructive activity outside lab-created directories
- no unsafe OT writes outside predefined lab scope
- no modification of platform services, OpenStack configuration, or SSH key material

The preferred safe roots are:

```bash
/tmp/nics_attack_lab
/tmp/nics_attack_lab/fim
/tmp/nics_attack_lab/sensitive_data
/tmp/nics_attack_lab/output
```

Execution modes include:

- `controlled`
- `read_only`
- `simulated`
- `restore_by_default`
- `disabled_by_default`

### Execution backend and result preservation

The attack backend follows a structured execution path:

```text
dashboard profile -> attack_id -> catalog lookup -> backend script -> result.json
```

The primary execution endpoint is:

```bash
POST /api/hud/attack/execute
```

An auxiliary compatibility launch path is also available:

```bash
GET /api/hud/attack/launch
```

Every ATT&CK execution generates a structured result directory under:

```bash
app_core/infrastructure/attack/outputs/
```

Each run writes a `result.json` file that records:

- execution metadata
- stdout and stderr traces
- expected alert families
- expected artifact families
- exit code
- success state
- timeline metadata
- chain-of-custody entries
- DFIR relevance flag

### DFIR escalation semantics

The catalog explicitly marks techniques that are DFIR-relevant. In practice, **HIGH** and **CRITICAL** profiles are treated as escalation candidates and their execution result is preserved with forensic-oriented metadata.

This creates a stronger bridge between:

- attack execution
- expected detection coverage
- artifact preservation
- case-oriented incident review

### OT-aware category visibility

The tactical dashboard applies category visibility rules based on the selected target role.

In particular:

- **ICS / OT** attack actions are only exposed when the selected target is an OT asset
- OT assets are modeled as:
  - **PLC**
  - **SCADA**

This means that techniques such as **Modbus Register Manipulation** are not presented for purely IT nodes such as attacker, victim, or monitor systems.

This design strengthens the scientific coherence of the interface because:

- techniques are presented only when they are operationally meaningful
- IT and OT attack surfaces are not mixed without context
- the visual layer better matches the experimental assumptions of hybrid IT/OT studies

### Attack execution model

Attack execution is conceptually organized as:

1. **Frontend attack profile**
2. **Scientific `attack_id`**
3. **Backend catalog resolution**
4. **Concrete script execution**

The launcher supports the scientific abstraction while preserving compatibility with script-based execution. The preferred experimental model is:

```text
attack_id -> catalog metadata -> script_name -> execution
```

This improves reproducibility, interpretability, and experimental consistency when the platform is used in a scientific or technical evaluation setting.

### Pre-attack node intelligence

The tactical dashboard includes a **pre-attack node intelligence** panel. Before launching an attack, the operator can inspect a structured node profile containing the most relevant operational and experimental context.

The panel includes:

- status
- primary IP
- private IP
- floating IP
- operating system
- installed tools count
- image reference
- flavor reference
- instance UUID
- creation timestamp
- update timestamp
- network topology metadata
- security groups
- firewall and exposure surface
- attached volumes
- forensic acquisition readiness flags

This information is intended to support a stronger decision process before action execution. Instead of launching attacks only from topology intuition, the operator can validate whether the target is:

- reachable
- externally exposed
- instrumented with security tooling
- appropriate for IT or OT actions
- suitable for later forensic acquisition

### Real data source strategy

The tactical dashboard uses a hybrid data strategy in order to preserve both graph semantics and operational accuracy.

It combines:

- **`/api/hud/instances`**
  - graph-oriented structure
  - node roles
  - attack/defense/prevention mappings
  - logical topology edges
- **`/api/openstack/instances/full`**
  - real OpenStack inventory state
  - private and floating IPs
  - flavor metadata
  - network metadata
  - security groups
  - attached volumes
  - forensic readiness indicators

This prevents the tactical dashboard from relying only on reduced HUD metadata when presenting node state.

### Tool registry consistency with Instance Tools Manager

To avoid discrepancies in the displayed tool inventory, the tactical dashboard aligns its tool registry with the same backend source used by the **Instance Tools Manager** (`index-tools.html`).

The tool count and tool registry shown in the tactical node profile are synchronized through:

```bash
/api/get_tools_for_instance?instance=<instance_name>
```

This choice is important scientifically and operationally because it ensures that:

- the tactical dashboard and the tools management dashboard report the same installed-tool view
- the operator does not make decisions on conflicting tooling metadata
- pre-attack node readiness is evaluated against the same source of truth used for tool orchestration

### Why it matters

This service makes the relationship between attack generation and detection explicit. After attacks are executed, the resulting events and alerts are registered and can be reviewed through the operational monitoring dashboard, which shows the active IT and OT components together with the generated indicators. This is especially useful for training, demonstrations, and controlled exercises in which the user must understand both sides of the event.

![Operational Monitoring Dashboard](Images_readme/it_ot_environment_dashboard.png)

---

## Forensic Acquisition and Analysis Dashboard

The **Forensic Acquisition and Analysis Dashboard** is the forensic response surface of the platform. It exposes the manual workflow for case management, evidence acquisition, traffic preservation, and post-acquisition analysis.

Its main capabilities include:

- selection of the target instance
- creation and selection of forensic cases
- manual live traffic capture with automatic preservation inside the active case
- disk acquisition
- memory acquisition with LiME
- disk analysis with TSK
- memory analysis with Volatility 3
- manifest browsing and artifact download
- console-based operational traceability

The dashboard is tightly connected to the monitoring and DFIR workflow of the platform.

When monitoring and automated DFIR are enabled:

- **low-severity events** may only be recorded as alerts
- **higher-severity events** may trigger automatic forensic escalation, including case creation and evidence preservation

The manual dashboard reflects that same logic in an inspectable form and also gives the operator direct control when manual intervention is needed.

![Forensic Acquisition and Analysis Dashboard](Images_readme/forensic_acquisition_dashboard.png)
![Forensic Acquisition and Analysis Dashboard](Images_readme/forensic_acquisition_dashboard_2.png)

### Traffic capture

NICS CyberLab supports complementary traffic capture mechanisms at scenario level.

The platform performs periodic rolling traffic capture automatically. Traffic is collected every 120 seconds from the relevant host-side interfaces and stored as time-bounded PCAP segments. This allows continuous observation of network activity across the scenario even when no incident has been detected. In future versions, the capture frequency may be adjusted dynamically according to the operational state of the scenario and the level of risk measured within it.

The platform also provides user-triggered traffic capture from the interface. In this mode, the user selects the instance of interest and can observe and capture its traffic on demand for as long as needed.

Together, these mechanisms support both continuous background traffic collection and flexible operator-driven inspection.

### Traffic preservation inside the forensic case

When an incident requires forensic analysis, network traffic can be preserved as part of the active case. This preservation is not limited to the traffic captured at the time of detection. It may also include traffic collected periodically before and after the incident, so the case retains a broader network context.

This makes it possible to reconstruct network activity before, during, and after the incident. As a result, network evidence becomes part of the same structured case context as disk and memory artifacts, improving traceability, contextual reconstruction, and forensic analysis.

![Live Traffic Analyzer](Images_readme/forensic_live_traffic_analyzer.png)

### Why it matters

This design separates operational traffic acquisition from forensic preservation while allowing both to work together. It supports continuous observability, user-driven inspection, and stronger case reconstruction through the integration of traffic, disk, and memory artifacts within a unified investigative context.

---

## Digital Forensics Report and Analysis Dashboard

The **Digital Forensics Report and Analysis Dashboard** is the case-centered forensic reporting surface of the platform. While the forensic acquisition dashboard focuses on collecting and preserving evidence, this service focuses on **understanding what has been preserved**, **where it is stored**, **how it can be downloaded**, and **what analytical and integrity context is attached to the case**.

Its main capabilities include:

- selection of an existing forensic case
- visualization of the preserved evidence inventory
- structured browsing of artifacts recorded in the case manifest
- direct download of preserved artifacts
- visibility of artifact paths and storage locations inside the case
- inspection of integrity-related metadata such as SHA-256 values
- review of chain of custody entries
- review of pipeline events associated with alerting, acquisition, preservation, and derived outputs
- summary of case-level artifact distribution and preservation status

The dashboard is designed to expose the **forensic structure of the case** in an operationally readable form. Instead of working only with raw directories and JSON files, the analyst can inspect the case through a unified interface that shows both the preserved artifacts and the metadata that explains their provenance.

This service is especially useful after acquisition has finished. At that point, the operator no longer needs only acquisition controls, but also a clear view of:

- which artifacts are available
- which system or node they belong to
- which artifacts are primary and which are derived
- whether integrity information is available
- how the preservation pipeline evolved over time

The dashboard is tightly connected to the internal case structure of the platform, including:

```bash
manifest.json
chain_of_custody.log
metadata/pipeline_events.jsonl
```

It also reflects the preserved evidence directories, including case content such as disk, memory, network, industrial, metadata, analysis, and derived artifacts.

![Digital Forensics Report and Analysis Dashboard](Images_readme/forensic_report.png)
![Digital Forensics Report and Analysis Dashboard](Images_readme/forensic_report_2.png)

### Why it matters

This service turns the forensic case into an inspectable analytical object. It helps the user move from raw evidence preservation to structured forensic interpretation by exposing artifact inventory, provenance, integrity context, and operational chronology in a single view.

---

## FOC Reconstruction Dashboard

The **FOC Reconstruction Dashboard** is the scientific validation surface of the platform. Its role is not to deploy infrastructure, execute attacks, or acquire evidence. Its role is to determine whether the active experiment is **reconstructible, traceable, and reproducible** from the artifacts already produced by the platform.

The dashboard is backed by the independent module:

```bash
app_core/infrastructure/foc_reconstruction/
```

The generated reconstruction artifacts are written to a root-level, removable output directory:

```bash
foc-reconstruction/
```

This design is intentionally read-only with respect to the rest of the platform. The reconstruction layer:

- reads existing scenario, OT, tools, attack, alert, and forensic sources
- normalizes identifiers and relationships
- generates its own manifest, indexes, BOMs, and timeline
- does not modify the original operational or forensic artifacts

If the module or the output directory is removed, the rest of NICS CyberLab continues to operate normally.

### Scientific purpose

The dashboard answers questions such as:

- can the current scenario be reconstructed with scientific rigor
- which structural, operational, evidential, and analytical sources exist
- which relationships are confirmed and which are only inferred
- which reconstruction gaps remain unresolved
- which new alerts, evidence items, or case artifacts have appeared

In that sense, the dashboard functions as a **reproducibility and reconstruction-readiness surface**, not as a generic JSON viewer.

### Reconstruction model

The reconstruction layer is centered on a **FOC Reconstruction Manifest** that references the active experiment through a normalized `scenario_id`.

Its principal outputs are:

- `foc-reconstruction/foc_manifest.json`
- `foc-reconstruction/scenario_bom.json`
- `foc-reconstruction/tools_bom.json`
- `foc-reconstruction/timeline.json`
- `foc-reconstruction/indexes/id_mapping.json`
- `foc-reconstruction/indexes/sources_index.json`
- `foc-reconstruction/indexes/artifacts_index.json`
- `foc-reconstruction/indexes/relationships_index.json`
- `foc-reconstruction/indexes/cases_index.json`
- `foc-reconstruction/hashes/hashes_index.json`

These artifacts do not duplicate heavy evidence such as PCAPs, disk images, or memory dumps. Instead, they preserve:

- normalized identifiers
- source paths
- hashes where feasible
- timestamps
- states
- relationship edges
- reconstruction warnings

### Bootstrap and regeneration semantics

The module supports two reconstruction modes:

- **native**
  - the reconstruction layer exists before the experiment and can preserve IDs from the beginning
- **bootstrap**
  - the reconstruction layer is initialized after the experiment already has scenario, OT, tools, alert, attack, or forensic artifacts

Bootstrap mode is designed for passive adoption of the existing laboratory state. It reads the current project sources, derives normalized FOC identifiers, creates `id_mapping.json`, and reconstructs the manifest, BOMs, and timeline without altering the original files.

### Panels exposed by the dashboard

The user-facing reconstruction view is:

```bash
app_core/static/foc_reconstruction.html
```

with controller:

```bash
app_core/static/js/foc_reconstruction.js
```

The dashboard exposes these scientific panels:

- **FOC Overview**
  - reconstruction status, scenario ID, last update, mode, reproducibility score, completeness
- **FOC Reconstruction Model**
  - conceptual status of Scenario BOM, Tools BOM, Attack Attestation, Detection Attestation, Acquisition Manifest, Preservation Manifest, Chain of Custody, Forensic Analysis Report, and Semantic Observation Report
- **Scenario BOM**
  - IT nodes, OT nodes, edges, roles, node-instance bindings, industrial linkages, deployment state
- **Tools BOM**
  - desired tools, installed tools, pending tools, failed tools, installation logs
- **Timeline**
  - normalized lifecycle, alert, escalation, acquisition, preservation, and analysis events
- **Alerts and Events**
  - attack, alert, triage, and DFIR escalation context
- **Evidence and Cases**
  - case manifests, custody logs, pipeline references, and indexed case artifacts
- **Reconstruction Gaps**
  - unresolved or missing elements that reduce reproducibility
- **Sources and Hashes**
  - indexed source paths, states, sizes, timestamps, and hashes
- **Relationships**
  - confirmed or inferred links between scenario, nodes, tools, attacks, alerts, evidence, and cases

### Reconstruction maturity model

The dashboard makes an explicit distinction between reconstruction phases that are:

- **available**
  - the artifact exists and is indexed
- **partial**
  - some information exists, but key fields or relationships remain incomplete
- **not generated yet**
  - the corresponding phase has not been executed yet
- **missing**
  - the phase is expected for the current state, but the artifact was not found
- **unresolved**
  - information exists, but correlation or interpretation remains incomplete

This distinction is important scientifically. For example, if no forensic acquisition has been launched yet, the dashboard treats acquisition, preservation, custody, and analysis as **not generated yet**, not as a reconstruction failure. This avoids conflating missing evidence with a simple absence of execution.

The maturity summary is presented in four analytical layers:

- **Structural reconstruction**
  - scenario and tool composition can be reconstructed
- **Operational reconstruction**
  - attack execution, alerts, and incident chronology can be reconstructed
- **Evidential reconstruction**
  - alerts can be linked to acquired and preserved evidence
- **Forensic reconstruction**
  - custody, analysis, and higher-level interpretation can be reconstructed

### Tools BOM consistency model

The FOC reconstruction layer treats the active scenario nodes as the canonical scope of the **Tools BOM**. In methodological terms, the main node list is aligned with the same operational logic used by the tool-management surface of the platform.

The principal node-level section contains only active or scenario-bound nodes and preserves, for each node:

- node name
- instance name
- normalized FOC instance ID
- OpenStack instance UUID when available
- private and floating IPs
- desired tools
- installed tools
- pending tools
- failed tools
- installation logs
- resolved tool states

The Tools BOM also separates non-canonical tool artifacts into dedicated classes:

- **orphan tool artifacts**
  - tool JSON or logs that exist on disk but do not map to an active node
- **historical tool artifacts**
  - older execution records that belong to previous runs or non-active nodes
- **host tool artifacts**
  - host-level logs or inventories that are not scenario nodes

This separation is important because it prevents historical or auxiliary artifacts from being misrepresented as active scenario nodes. As a result, the Tools BOM becomes more coherent with the node population exposed by the tool-management workflow and by the tactical dashboards.

### Chronology versus detection surface

The dashboard distinguishes between two related but non-equivalent temporal views:

- **Timeline / Lifecycle and Incident Sequence**
  - the complete reverse-time chronology of the experiment
  - includes lifecycle transitions, tool instrumentation, attack execution, detections, escalation, and forensic pipeline events
- **Alerts and Events / Detection and Escalation Surface**
  - a filtered detection-oriented surface
  - focuses on alerts, triage, DFIR escalation, and case creation without repeating the full offensive chronology

This distinction reduces analytical ambiguity. The timeline answers the question **what happened and in which order**, while the detection surface answers **what the platform detected, how it classified the event, and whether escalation followed**.

### Analytical visualization layer

The reconstruction dashboard also includes a first analytical visualization layer derived from the indexed FOC data. Its purpose is not to replace the textual reconstruction objects, but to provide a compact scientific summary of their current state.

The initial visualization set includes:

- **KPI cards**
  - alert count
  - attack count
  - triage count
  - evidence count
  - forensic case count
  - distinct MITRE technique count
- **Time-series incident chart**
  - temporal evolution of attacks, detections, triage, and DFIR/evidence events
- **Detection distribution donut chart**
  - relative contribution of detection sources such as Wazuh and Suricata families
- **Most affected nodes chart**
  - concentration of indexed events by normalized node
- **MITRE ranking table**
  - most frequent ATT&CK techniques observed in execution outputs
- **Causal reconstruction graph**
  - simplified relational view of scenario, nodes, attacks, alerts, evidence, and analysis links

These visualizations are intentionally conservative. They are produced from the same normalized FOC artifacts already used by the rest of the dashboard and do not introduce additional dependencies or operational requirements.

### Reproducibility scoring

The dashboard includes a reproducibility score on a 0 to 100 scale. The initial model evaluates whether the following reconstruction components are available:

- Scenario BOM
- Tools BOM
- Timeline
- source index
- hash index
- node-instance bindings
- attack-to-alert links
- alert-to-evidence links
- case manifest and chain of custody

This makes the score a structural indicator of reconstruction strength rather than a decorative UI element.

### Reconstruction gaps

One of the most important functions of the dashboard is to reveal what is still missing. Typical gaps include:

- missing scenario identifiers
- unresolved node-instance bindings
- pending or failed tool installations
- missing attack-to-alert correlation
- missing alert-to-evidence correlation
- missing evidence hashes
- missing chain of custody
- missing forensic analysis outputs

Each gap is presented with:

- severity
- status
- expected source
- recommended action

This gives the operator a practical path to improve reproducibility instead of only inspecting artifacts passively.

### Live update model

The reconstruction dashboard supports live refresh through a server-sent events stream:

```bash
GET /api/foc/events/stream
```

This allows the interface to refresh when the indexed source state changes, for example after:

- new tool installation records
- new attack outputs
- new alert sessions
- new forensic cases
- new custody or pipeline events

The update model also makes it possible to refresh the analytical layer as the incident develops. In practice, this allows the dashboard to expose:

- newly detected alerts
- new triage outcomes
- updated attack-to-alert correlations
- new case creation
- newly indexed evidence and analysis outputs
- updated reconstruction gaps and reproducibility score

The live model remains non-critical. If the reconstruction stream degrades or disconnects, the rest of the platform continues operating and the reconstruction dashboard still supports manual refresh and regeneration.

### FOC API surface

The reconstruction layer exposes a dedicated, isolated API:

- `GET /api/foc/status`
- `GET /api/foc/manifest`
- `GET /api/foc/scenario-bom`
- `GET /api/foc/tools-bom`
- `GET /api/foc/timeline`
- `GET /api/foc/gaps`
- `GET /api/foc/sources`
- `GET /api/foc/relationships`
- `GET /api/foc/id-mapping`
- `POST /api/foc/bootstrap`
- `POST /api/foc/regenerate`
- `GET /api/foc/events/stream`

These endpoints are optional services for reconstruction and do not act as dependencies for scenario creation, OT deployment, tool installation, attack execution, or forensic acquisition.

### Export and comparative value

Because the FOC layer produces normalized BOMs, indexes, and a timeline, the reconstruction state is exportable in a form that supports both **single-scenario reconstruction** and **cross-scenario comparison**.

At a methodological level, this enables later comparison of:

- scenario composition
- node instrumentation
- ATT&CK techniques executed
- detection volume and detector families
- forensic case creation
- evidence preservation state
- reconstruction completeness and reproducibility score

This makes the FOC layer useful not only as a validation dashboard for the active scenario, but also as a foundation for longitudinal or comparative experimental studies.

### Why it matters

This dashboard turns the experiment into a scientifically inspectable object. It connects infrastructure composition, instrumentation state, attack outputs, alerts, evidence preservation, and analytical results into a single reconstruction surface. As a result, the platform can be evaluated not only by what it executes, but also by how completely and rigorously the resulting experiment can be reconstructed afterward.

---


## 4. Remote Lab Exchange

**Remote Lab Exchange** is a platform capability that allows NICS CyberLab to exchange data with external machines or remote laboratory environments for later processing and structured feedback recovery.

This capability is designed to support workflows in which selected artifacts must be transferred outside the local scenario for specialized analysis and then returned to the platform in the form of reports, extracted results, or other derived outputs. The exchanged data may include network traffic captures, suspicious files, malware samples, structured datasets, logs, or other artifacts generated during experimentation.

Instead of treating this exchange as an isolated external workflow, NICS CyberLab incorporates it as an operational bridge between the local platform and remote processing environments. In this way, artifacts produced inside the platform can be exported to other analysis machines or partner labs, processed remotely, and then reintroduced into NICS CyberLab together with the corresponding feedback.

Typical actions supported through this capability include:

- selecting and preparing artifacts for exchange
- packaging files when needed
- transferring artifacts to remote machines or labs
- launching remote processing tasks
- verifying remote execution status
- receiving processed outputs or analysis reports
- visualizing returned feedback inside the platform

This makes it possible to use NICS CyberLab not only as a local experimentation environment, but also as a coordination point for distributed analysis workflows involving external machines or remote labs.

![Remote Lab Exchange](Images_readme/LAB_EXCHANGE_DASHBOARD.png)

### Why it matters

This capability extends NICS CyberLab beyond local execution boundaries. It allows the platform to send traffic captures, suspicious files, malware-related artifacts, logs, datasets, or other experiment outputs to external systems for remote processing, and then recover the resulting feedback in an inspectable way. As a result, NICS CyberLab can participate in distributed experimentation and analysis workflows without breaking the continuity of the platform experience.

---

## 5. End-to-end usage sequence

A typical end-to-end workflow is:

### Step 1

Deploy the OpenStack infrastructure with:

```bash
bash openstack-installer/openstack-installer.sh
```

### Step 2

Launch the dashboards with:

```bash
bash start_dashboard.sh
```

### Step 3

Create the base IT scenario in the **IT Scenario Editor**.

### Step 4

If needed, extend it with **PLC** and **SCADA** components in the **Industrial Scenario Editor**.

### Step 5

Install the required offensive, defensive, monitoring, and analysis tools with the **Instance Tools Manager**.

### Step 6

Access the installed tools through the **Security Training and Tools Portal** and interact with their real dashboards or consoles.

### Step 7

Run integrated exercises in the **Tactical Cyber Operations Dashboard** to observe both the attack side and the monitoring side.

### Step 8

When the incident severity justifies it, preserve and analyze evidence through the **Forensic Acquisition and Analysis Dashboard**.

### Step 9

Review the preserved case, artifact inventory, manifest, chain of custody, and pipeline events in the **Digital Forensics Report and Analysis Dashboard**.

### Step 10

Validate reconstruction completeness, evidential traceability, and reproducibility through the **FOC Reconstruction Dashboard**.

---

## 6. Key platform strengths

NICS CyberLab brings together capabilities that are often separated across multiple environments:

- **Automated infrastructure deployment**
- **Visual scenario modeling**
- **Hybrid IT and IT/OT support**
- **Centralized node-level tool installation**
- **Direct access to real cybersecurity tools**
- **Integrated attack-and-detection exercises**
- **Case-aware forensic acquisition and analysis**
- **Case-centered forensic reporting and evidence review**
- **Scientific reconstruction and reproducibility validation**
- **Educational and professional usability**
- **Operational traceability across the workflow**

This combination makes the platform suitable for:

- cybersecurity training
- guided laboratory exercises
- attack-and-detection demonstrations
- DFIR workflow validation
- hybrid IT/OT experimentation
- reproducible security research environments

---

## 7. Important paths

### Infrastructure deployment

```bash
openstack-installer/openstack-installer.sh
```

### OpenStack virtual environment

```bash
openstack-installer/openstack_venv
```

### Generated OpenStack credentials

```bash
admin-openrc.sh
```

### Dashboard launcher

```bash
start_dashboard.sh
```

### OpenStack service recovery

```bash
restart_openstack.sh
```

### Example PLC program

```bash
industrial-scenario/PLC/plc_programs/TankControl.st
```

### FOC reconstruction module

```bash
app_core/infrastructure/foc_reconstruction/
```

### FOC reconstruction artifacts

```bash
foc-reconstruction/
```

---

## 📝 Acknowledgments

This repository has been partially supported by the project "CiberIA: Investigación e Innovación para la Integración de Ciberseguridad e Inteligencia Artificial" (Proyecto C079/23), financed by "European Union NextGeneration-EU, the Recovery Plan, Transformation and Resilience", through INCIBE. It has also been partially supported by the project SecAI (PID2022-139268OB-I00) funded by the Spanish Ministerio de Ciencia e Innovacion, and Agencia Estatal de Investigacion.
