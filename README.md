![Fondos_INCIBE](Images_readme/logo_fondos_incibe.png)

This repository is part of 
- The project "CiberIA: Investigación e Innovación para la Integración de Ciberseguridad e Inteligencia Artificial" (Proyecto C079/23), financed by "European Union NextGeneration-EU, the Recovery Plan, Transformation and Resilience", through INCIBE.
- The Programa Global de Innovación en Seguridad for the promotion of Cátedras de Ciberseguridad en España, funded by the European Union NextGeneration-EU Funds, through the Instituto Nacional de Ciberseguridad (INCIBE).




---

# FORGE-VI

**Forensic Reproducibility and Grounded Experimentation for Virtualized Infrastructures**

FORGE-VI is a reproducible cybersecurity experimentation and training platform for **IT and hybrid IT/OT environments**. It combines automated infrastructure deployment, visual scenario construction, node-level tool installation, role-oriented operational access, attack-and-detection exercises, and forensic acquisition, preservation, analysis, and reporting inside a single workflow.

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

## 2.1. Scientific method used across NICS CyberLab

NICS CyberLab is not designed as a collection of isolated tools. It is designed as a **controlled scientific workflow** for cybersecurity experimentation, preservation, forensic analysis, reconstruction, and uncertainty-aware interpretation in IT and hybrid IT/OT environments.

The scientific value of the platform does not come from calling a result "scientific". It comes from making explicit, step by step:

- what scenario was declared and deployed
- what intervention or attack was executed
- what detections and alerts were observed
- what artifact triggered acquisition
- what evidence was preserved
- what integrity and custody guarantees exist
- what forensic layers were actually analyzed
- what causal relations were reconstructed from preserved evidence
- what uncertainty still limits interpretation
- what can be supported, degraded, or not yet claimed

### Core methodological principle

The project follows a **preserve first, analyze second, reconstruct third, interpret cautiously** model.

This means:

- primary evidence is acquired and preserved before high-level interpretation
- derived reports never replace preserved artifacts
- causal reconstruction is performed over preserved and normalized outputs, not over live systems
- uncertainty, degradation, and unsupported claims remain visible instead of being hidden

In practical terms, the platform distinguishes four scientific layers:

1. **Controlled intervention layer**
   - the scenario is deployed in a reproducible environment
   - tools, roles, and OT/IT topology are declared explicitly
   - attacks and detections are executed under controlled conditions
2. **Preservation layer**
   - acquisition, manifests, custody logs, hashes, and evidence links preserve what was captured
   - the preserved case becomes the auditable reference point
3. **Analytical layer**
   - multilayer forensic analysis processes preserved network, memory, disk, OT, alert, custody, and timeline artifacts
   - each analytical layer is evaluated for usefulness, not just completion
4. **Interpretive layer**
   - FOC Reconstruction, causal reconstruction, uncertainty budgeting, evidence-support evaluation, and executive conclusions operate on preserved and derived artifacts
   - no claim is stronger than the evidence and uncertainty budget allow

### End-to-end scientific lifecycle

Across the platform, the scientific method can be summarized as the following chain:

```text
Scenario declaration
-> controlled deployment
-> tool preparation
-> attack / intervention execution
-> detection observation
-> trigger selection
-> evidence acquisition
-> preservation and custody
-> multilayer forensic analysis
-> timeline and cross-layer findings
-> causal reconstruction
-> uncertainty evaluation
-> evidence-based conclusions
```

This chain is visible in different parts of the platform:

- **Scenario editors**
  - declare the environment to be studied
- **Instance Tools Manager**
  - defines the operational and detection surface available in the experiment
- **Attack and detection workflows**
  - produce the controlled intervention and the observable reaction
- **Forensic Acquisition and Analysis Dashboard**
  - preserves, indexes, hashes, and analyzes the resulting case
- **FOC Reconstruction**
  - organizes the structural, evidential, analytical, and readiness context
- **FOC Causal Reconstruction**
  - evaluates expected causal relations against preserved evidence
- **FOC Scientific Evidence Lifecycle Dashboard**
  - presents the final scientific reading of what can and cannot be concluded

### Scientific claims model

NICS CyberLab does not treat every generated file as equivalent to knowledge. Instead, it separates claims into three classes:

- **Supported claims**
  - directly supported by preserved and verifiable evidence
- **Degraded or ambiguous claims**
  - partially supported, inferred, temporally unresolved, or limited by incomplete coverage
- **Unsupported or not-yet-claimable statements**
  - not justified by the preserved artifacts or blocked by missing evidence

This is why the platform preserves distinctions such as:

- `completed` vs `completed_with_degradation`
- `useful output` vs `completed_without_useful_output`
- `synchronized clocks` vs `limited causal temporal ordering confidence`
- `evidence processing coverage: strong` vs `causal interpretation confidence: limited`

These distinctions are not cosmetic. They are part of the scientific method of the platform.

### Role of preservation, integrity, and custody

The project assumes that an interesting detection or a plausible attack narrative is not enough on its own.

Scientific and forensic interpretation must be grounded in:

- preserved artifacts
- manifest linkage
- chain of custody
- integrity verification
- reproducible case paths
- explicit source references

For this reason, the platform separates:

- the **execution** of integrity and custody validation
- from the **result** of case-wide integrity completeness

---

## 2.2. Current scientific reporting status

The current reporting stack already supports a stricter and more scientifically explicit interpretation of repeated **Level B** executions and nested **Level A over Level B** analysis runs.

### What is already achieved

- **Level B and nested Level A repetition counts are now independent**
  - the platform now supports a separate `nested_level_a_repetitions` input for Level B workflows
  - this prevents the previous ambiguity where nested Level A runs could be implicitly tied to the requested Level B repetition count
- **Failed Level B executions are excluded from accepted scientific aggregates**
  - unsuccessful or non-preserved Level B runs are retained for diagnostic audit
  - they are not pooled into accepted evidence, timing, preservation, or causal-reconstruction denominators
- **Truthful reporting now separates distinct denominator scopes**
  - standalone Level A
  - Level A over Level B cases
  - accepted Level B cases
- **Case-directory aliasing is made explicit**
  - when a retained lightweight case bundle uses a Level B case identifier but the preserved heavy-case directory resolves to a different internal path, the report exposes that mapping explicitly instead of hiding it
- **Network evidence is now reported conservatively**
  - network context is distinguished from real packet-level evidence
  - if `preserved_segments=0` and no preserved PCAP exists, Modbus function/register/value remain declared rather than observed
- **Manifest and custody semantics are now reported conservatively**
  - if large artifacts were skipped during integrity validation, the package uses `partial verification`
  - it no longer overstates those cases as full verification
- **Causal reconstruction reporting now includes root-cause inspection**
  - relation-level `missing` and `degraded` states are no longer treated as opaque labels only
  - the reports now explain the root cause, affected pipeline stage, evidence checked, missing evidence, and the exact correction needed
- **Gap reports now distinguish three different questions**
  - whether a table can be generated now
  - whether the missing data can be recovered from existing artifacts
  - whether a final paper claim is scientifically defensible now

### What the current reports can already support

- preliminary audit tables over the currently accepted Level B denominator
- explicit causal-path interpretation for each accepted Level B case
- nested Level A stability discussion over preserved Level B source cases
- honest reporting of missing OT export, missing packet-level Modbus confirmation, missing raw Wazuh trigger binding, missing forensic-intervention linkage, and partial verification semantics

### What is still not solved at the evidence level

The current documentation improvements do **not** mean that the underlying evidence gaps are solved. At the moment, the reports still identify the following unresolved issues when they appear in a campaign:

- fewer accepted Level B cases than the intended final `N_B`
- missing preserved OT export
- missing preserved PCAP or packet-level Modbus evidence
- missing raw Wazuh alert-to-case binding
- missing explicit `forensic_intervention` provenance artifact
- partial manifest/custody verification when large-artifact skip remains enabled

In short: the reporting layer is already much more truthful and scientifically defendible, but final paper claims still depend on what was actually preserved during acquisition and retention.

A validation step may execute successfully while the final integrity assessment remains partial. The platform records that distinction instead of hiding it.

For a root-cause oriented register of the main scientific obstacles found during these iterations, see [README_OBSTACULOS_CIENTIFICOS.md](README_OBSTACULOS_CIENTIFICOS.md).

### What is now enforced in the Level B preservation flow

The platform now also applies stricter **preserve-first** behavior inside the **Level B** execution path itself, not only in the reporting layer.

- **Background-case adoption is now filtered more aggressively**
  - the runner no longer treats any recent `CASE-*` directory as reusable background evidence
  - a candidate case must at least look like a real preserved case with `manifest.json`, `pipeline_events.jsonl`, and active or recent preservation signals
  - this prevents empty or half-created case directories from being silently adopted as if they were valid forensic cases
- **Trigger alerts now require temporal coherence with the executed attack**
  - Level B no longer accepts any generic HIGH/CRITICAL Modbus write alert regardless of when it appears
  - the matcher and fallback scorer now require the alert timestamp to stay inside a bounded window around the actual attack execution
  - this reduces the risk of binding a preserved case to a delayed or unrelated alert and then selecting the wrong network window
- **Stale placeholder case directories are now pruned before they can interfere with a new repetition**
  - empty `CASE-*` directories without `manifest.json`, custody, or pipeline events are treated as abandoned placeholders rather than valid preservation state
  - the Level B runner prunes those directories before trigger arming, and the global DFIR preservation guard also clears them if one is still pointed to as the active case
  - this reduces the risk of a repetition getting stuck behind a non-real case or reusing a case that never became a preserved bundle
- **Critical scientific artifacts are now persisted explicitly during Level B**
  - `metadata/trigger_alert_binding.json`
  - `metadata/forensic_intervention.json`
  - `metadata/normalized_causal_timestamps.json`
  - `metadata/critical_evidence_gate.json`
  - each of these files is written into the case, registered in the manifest, and emitted into the pipeline-event trail
- **A critical evidence gate now runs before a case is treated as scientifically acceptable**
  - the gate checks for packet-level network evidence presence, OT export presence, raw trigger binding, forensic intervention, memory artifacts, disk artifacts, manifest/custody presence, and normalized timestamps
  - if those requirements are not met, the case is marked as diagnostic/audit only instead of being treated as scientifically complete
- **Cleanup now depends on preserved scientific metadata**
  - heavy-case cleanup is no longer allowed unless the lightweight scientific memory includes the explicit trigger binding, forensic intervention artifact, normalized timestamps, and critical evidence gate result
  - this reduces the risk of deleting the heavy case before the minimum scientific reconstruction metadata has been preserved
- **Level B now runs node free-space cleanup on `fuxa` and `plc` around repetition boundaries**
  - after a heavy case is deleted, the runner applies `pre_memory_cleanup_inside_node.sh` over SSH to `fuxa` and `plc`
  - before the next repetition launches a fresh attack, the runner repeats that cleanup as a mandatory pre-attack gate
  - this reduces the risk of a new repetition starting while stale acquisition files on the nodes still consume space from the previous case
- **Failed Level B repetitions now close the campaign early instead of continuing to launch attacks**
  - if a repetition ends with `execution_status=failed`, the batch stops there
  - final reporting is still generated from the repetitions already executed, with the early-stop reason preserved in the job/report trail
  - this avoids unprofessional "keep trying after terminal failure" behavior and makes the campaign boundary scientifically explicit
- **Old Level B cases are now converted into a lightweight audit shell instead of being left as incoherent remnants**
  - heavy memory, disk, and raw network captures are removed for space recovery
  - the case path is rebuilt as a lightweight audit-only shell containing manifest/custody, critical metadata, analysis outputs, hashes, causal outputs, and an explicit `lightweight_retention_audit.json`
  - the audit file records that the heavy evidence was deleted intentionally by the platform for storage management and not by tampering
  - the retained shell is capped by policy to stay under `500 MB`
- **The lightweight retained bundle now preserves the critical scientific surface without re-keeping heavy captures**
  - OT export files such as `industrial/ot_export_*.json`
  - the explicit metadata artifacts listed above
  - per-layer analysis outputs, causal reconstruction outputs, retention manifests, hashes, and custody context
  - raw PCAP/PCAPNG, memory dumps, and disk images are not re-kept inside the lightweight shell
- **Network preservation now normalizes impossible trigger windows instead of collapsing to zero selected segments**
  - if a malformed or delayed trigger timestamp would place `case_window_start_utc` after `case_window_end_utc`, the importer records that normalization explicitly and keeps the window usable
  - this is a defensive fallback only; the primary fix is still to bind the correct alert to the correct repetition
- **The monitor stream now follows only newly appended alerts**
  - the remote Wazuh monitor switched from a generic `tail -f` to a new-events-only follow mode
  - this reduces accidental reuse of pre-existing alerts when a repetition starts listening for its trigger
- **The main `index` view now exposes compact live execution timing**
  - running experimentation jobs show current phase, elapsed time, and last repetition duration
  - active DFIR preservation now shows a compact live badge with case id, current phase, and elapsed time
  - when experimentation finishes, the last duration remains visible as a lightweight summary instead of disappearing immediately

In short: the platform no longer relies only on truthful post-hoc reporting. It now pushes more of the scientific completeness policy into the actual **Level B** acquisition, preservation, adoption, and cleanup workflow.

### Role of multilayer forensic analysis

The multilayer forensic pipeline is the empirical processing stage of the method. Its purpose is to answer:

- was the preserved evidence actually processed
- which layers produced useful findings
- which layers remained partial, failed, blocked, or unavailable

The expected layers include:

- evidence inventory
- integrity and custody validation
- temporal validation
- network analysis
- memory analysis
- disk analysis
- OT export analysis
- alert and detection analysis
- pipeline and custody analysis
- unified timeline generation
- cross-layer findings
- forensic report generation

Scientifically, this stage measures **coverage and usefulness of evidence processing**, not causal proof. A case may have strong multilayer coverage and still only partial causal reconstruction.

### Role of temporal calibration and uncertainty

Temporal interpretation is treated as a first-class scientific constraint.

The platform therefore distinguishes:

- node clock synchronization
- availability of timestamps in preserved artifacts
- resolvability of available timestamps
- coverage of timestamps needed by causal edges
- final causal temporal ordering confidence

The uncertainty model is explicit rather than implicit. It is used to prevent overclaiming.

For example:

- synchronized clocks do not guarantee that every artifact contains usable timestamps
- a low `max_clock_offset` does not automatically imply strong causal temporal ordering
- missing or unresolved timestamps can keep a causal relation degraded or ambiguous even when synchronization is good

This is why the platform generates and consumes:

- time synchronization measurements
- time validation reports
- uncertainty budgets
- temporal confidence states

### Role of ground truth and causal reconstruction

The project uses **scenario ground truth** as an expected causal model, not as assumed proof.

Ground truth defines:

- the expected attack path
- expected relations
- expected evidence sources
- temporal and semantic expectations
- optional OT-specific details such as protocol, function code, register, and expected value

The causal module then tests that expected model against preserved evidence and classifies each expected relation as:

- `recovered`
- `degraded`
- `ambiguous`
- `missing`

Metrics such as `CPR`, `Weighted CPR`, degraded rate, ambiguous rate, missing rate, integrity ratio, evidence completeness ratio, and reconstruction confidence are therefore **derived interpretive metrics**, not claims of absolute truth.

### Role of OT specificity

For hybrid IT/OT scenarios, the scientific method must preserve the difference between:

- observing generic traffic
- observing protocol-specific OT activity
- inferring process-level impact
- proving packet-level register/value causality

This is why the platform makes Modbus specificity explicit:

- protocol presence may be confirmed
- target PLC may be confirmed
- function code, register, value, or OT-state effect may remain only partial

The platform does not silently upgrade protocol presence into full industrial causal precision.

### Role of evidence-based interpretation

The final scientific reading of a case is not a raw log dump and not a single score.

Instead, the platform derives:

- evidence-based reconstruction stories
- hypothesis support summaries
- cross-layer support matrices
- claimability boundaries
- counter-evidence and gaps
- supported, degraded, and unsupported conclusions

The intended question is not:

```text
Did the platform produce a nice dashboard?
```

The intended question is:

```text
What can be defended from preserved evidence, what remains degraded, and what cannot yet be claimed?
```

### Reproducibility and auditability

The scientific method used throughout the project also depends on reproducibility.

This is why the platform favors:

- normalized case directories
- stored manifests and custody logs
- explicit derived artifacts
- staleness detection
- on-demand regeneration instead of silent recalculation
- separation between primary evidence and derived interpretation

If a derived executive summary, causal graph, or support report becomes stale because a dependent artifact changed, the platform marks it as stale and requires regeneration. It never silently upgrades the conclusion.

### Final methodological interpretation

Taken together, the method used across NICS CyberLab can be summarized as follows:

```text
Preserved evidence is the foundation.
Multilayer analysis establishes empirical processing coverage.
FOC organizes the reconstruction context.
Causal reconstruction evaluates expected relations against preserved evidence.
Uncertainty constrains interpretation.
Final conclusions remain bounded by what the evidence, integrity state, temporal model, and analytical coverage actually support.
```

This is the central methodological rule of the project:

> The scientific value of NICS CyberLab lies in exposing what was declared, what was preserved, what was analyzed, what was reconstructed, what remains uncertain, and what cannot be claimed.

---

## 3. Main platform services

## FORGE-VI Home Dashboard

The home view (`index.html`) is the unified entry point to the platform. It presents the full operational and scientific state of the active experiment in a single screen, without requiring navigation to individual views. This is the first view the user sees after starting the platform and the natural starting point for understanding what is deployed, what has been detected, and how far the current experiment has progressed toward a complete forensic reconstruction.

![FORGE-VI Home Page](Images_readme/FORGE_VI_HOME_PAGE.png)

The top KPI bar summarises the most critical metrics of the active experiment:

| KPI | Meaning |
|-----|---------|
| **OpenStack Instances** | Number of virtual nodes currently synchronized from the OpenStack inventory |
| **Installed Tools** | Total number of tools installed across all scenario nodes |
| **Detected Alerts** | Number of detection events indexed in the active forensic alert store |
| **Forensic Cases** | Number of preserved forensic cases in the evidence store |
| **Evidence Artifacts** | Total number of indexed artifacts across all preserved cases |
| **FOC Readiness** | Quantified FOC reconstruction readiness score for the current experiment |

Directly below the KPI bar, the **FORGE-VI Scientific Results** banner presents the real-time scientific summary of the active campaign. It includes:

- campaign identifier (`CMP-…`) and scenario identifier (`scn-…`)
- number of evaluated experimental executions and sealed forensic cases
- **Causal Path Recoverability (CPR)** across all runs, expressed as a percentage
- recovered versus total causal edges (`rec/total`)
- per-edge state summary (`e1` through `e8`), color-coded as recovered, ambiguous, degraded, or missing

This banner is clickable and opens the **FORGE-VI Scientific Dashboard** for the full experimental view.

The two notification bars show:

- **Live Alert Indicator** — most recent Wazuh and Suricata detection events, displayed as dual-source rows with source badges, alert summary, and type annotation
- **OpenStack Health** — current health and synchronization state of the OpenStack node cluster

The central area presents the **staged workflow navigation**. Each stage card represents a discrete phase of the end-to-end experimental and forensic workflow:

1. **Attack Lab** — ATT&CK-aligned attack execution and node intelligence
2. **Detection & Prevention** — monitoring, alert inspection, and detection coverage
3. **Forensic Lab** — evidence acquisition, preservation, and case management
4. **Forensic Report** — case-centered artifact review, manifest, custody, and pipeline events
5. **FOC** — FOC Reconstruction and causal reconstruction readiness
6. **FOC Scientific Life Tool** — evidence lifecycle and scientific interpretation surface
7. **FOC Experiment Manager** — campaign management, repetition control, and comparability

The bottom panel provides five parallel readiness panels visible simultaneously without scrolling:

- **Scenario Readiness** — per-component status of the IT scenario, OT scenario, inventory, tools, detection, forensics, and FOC layers
- **Recent Activity** — chronological list of the last observable events across all platform layers
- **Detection Coverage** — operational state of Wazuh Agent, Suricata, FIM, Modbus Detection, and Traffic Capture sensors
- **Attack Catalog Status** — ATT&CK execution readiness, detection linkage, and forensic acquisition outcome for the active attack profile
- **Forensic / FOC Readiness** — scientific reconstruction completeness including scenario BOM, tools BOM, detection attestation, forensic analysis manifest, and FOC readiness verdict

### Why it matters

The home view makes the entire experimental state inspectable in a single glance. The operator can assess whether the scenario is deployed, whether tools are installed, whether attacks have been detected, whether a forensic case has been sealed, and whether the causal reconstruction is complete — all before opening any individual view. The embedded FORGE-VI Scientific Results banner means that the CPR, edge states, and reproducibility metrics from the active campaign are always visible at a glance, even when the operator is not inside the scientific dashboard itself.

---

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
- **Suricata-oriented detection and rollback profiles**
  - Suricata Modbus Register Manipulation Detection
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

The Suricata-oriented detection configuration profile for Modbus manipulation installs a dedicated rule file:

```bash
/var/lib/suricata/rules/nics-modbus-register-manipulation.rules
```

The production rule set is intentionally narrow. It is designed to detect only high-confidence Modbus write operations relevant to industrial ATT&CK control manipulation experiments, including:

- single-register writes associated with `T0836` and `T1692.001`
- multiple-register writes associated with `T0836` and `T1692.001`
- single-coil writes associated with Modbus control manipulation
- multiple-coil writes associated with Modbus control manipulation

This production profile does **not** alert on normal SCADA polling, holding-register reads, coil reads, or generic TCP/502 visibility. The goal is to answer a strict question:

- did a Modbus write occur that could modify the PLC state?

For temporary troubleshooting, the project also distinguishes a separate conceptual profile:

- **Production Modbus Register Manipulation Detection**
  - persistent deployment profile
  - detects only write operations
  - avoids noise from normal Modbus traffic
- **Debug Modbus Visibility**
  - temporary diagnostic mode
  - may alert on generic TCP/502 visibility or read activity
  - should not be used as the permanent detection profile

These Suricata alerts are written to:

```bash
/var/log/suricata/eve.json
```

If the existing Wazuh + Suricata integration profile is already deployed, the same events are also ingested by Wazuh without requiring additional changes to `ossec.conf` or the Wazuh agent installation path.

The integration profile also installs a focused local Wazuh rule override for the OT Modbus write signatures emitted by the NICS CyberLab Suricata rules. This means the telemetry path preserves two layers of meaning:

- the original Suricata alert stored in `eve.json`
- a higher-priority Wazuh rule match for:
  - `910836101`
  - `910836102`
  - `910836103`
  - `910836104`

The local override is applied through:

```bash
/var/ossec/etc/rules/local_rules.xml
```

and is intended to prevent high-confidence OT control-manipulation events from appearing with the same low generic wrapper level used for ordinary JSON-ingested alerts.

The practical telemetry chain for these OT detections is:

1. `Suricata` on the observing node matches the Modbus write rule.
2. The alert is written into `/var/log/suricata/eve.json`.
3. `Wazuh Agent` on that same node ingests `eve.json` through the prepared localfile integration.
4. `Wazuh Manager` on the monitoring node receives and reports the event.
5. `FOC Reconstruction` can index that alert and correlate it with:
   - the attack execution
   - the targeted PLC or SCADA node
   - the reconstructed timeline
   - later evidential and forensic artifacts

This also explains an important distinction in scoring:

- before the OT-specific local Wazuh rule is applied, the raw `Wazuh rule level` can remain low because the generic JSON ingestion rule is broad
- after the OT-specific local Wazuh rule is applied, the same Modbus write signatures are escalated to a more appropriate Wazuh level for operational visibility
- independently of that, the underlying Suricata event still represents the authoritative network detection
- the platform therefore preserves both:
  - the native Wazuh level
  - the higher-level derived severity used by the reconstruction and triage layers

For verified Modbus write detections, the intended causal relation is:

- `attack execution -> Suricata write alert -> Wazuh event -> FOC produced_alert relation`

When the target node, timing window, and ATT&CK-aligned signature all match, the reconstruction should explicitly preserve:

- the `related_attack_id`
- the `correlation_status`
- the `correlation_confidence`
- the `correlation_reason`

This makes the attack-to-detection relationship inspectable as a cause-and-effect chain rather than as an isolated alert.

The paired removal workflow is exposed through the regular **Uninstall** action of the Instance Tools Manager rather than as a separate installable catalog entry. It only removes:

- `/var/lib/suricata/rules/nics-modbus-register-manipulation.rules`
- the corresponding `nics-modbus-register-manipulation.rules` entry inside `suricata.yaml`

It does **not** remove:

- Suricata itself
- the Wazuh Agent
- the Suricata → Wazuh integration path
- `eve.json`
- `ossec.conf`
- any other Suricata rule file such as `local.rules`, `suricata.rules`, `nics-ping.rules`, or third-party rule bundles

The recommended installation order for OT telemetry validation is:

1. Install Suricata
2. Install Wazuh Agent
3. Install Wazuh + Suricata Integration Rollback
4. Install Suricata Modbus Register Manipulation Detection
5. Execute the controlled Modbus register manipulation attack
6. Verify the alert in `eve.json` and in Wazuh

If the Wazuh + Suricata integration profile was installed before the OT-specific local rules were introduced, rerun that same integration profile once on the PLC or SCADA node so the updated `local_rules.xml` block is applied.

If the Modbus-specific rule set must be withdrawn without affecting the rest of the monitoring stack, the corresponding **Uninstall** action can be executed afterward for the same tool identifier. The removal action validates `suricata.yaml`, restores a backup automatically if validation fails, and preserves the rest of the Suricata and Wazuh telemetry path.

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

The Attack Lab view also includes a frontend-only informational MITRE layer:

- each primary attack card exposes a compact chevron
- clicking the chevron opens a transparent explanatory panel
- the panel shows the profile name, MITRE ID, domain, tactic, operational meaning, expected evidence, expected detection sources, and the official MITRE reference
- this panel is educational only and does **not** execute attacks, call the backend, change attack state, or alter the scenario graph

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

### Industrial attack adaptation for the tank-control scenario

The OT attack layer includes a dedicated **industrial resolution and validation path** for the real tank-control assets packaged with the laboratory:

- `industrial-scenario/PLC/plc_programs/TankControl.st`
- `industrial-scenario/FUXA/fuxa_mi_proyecto_simple.json`

The implementation objective is to prevent unsafe or scientifically weak Modbus execution. In methodological terms, the platform does **not** treat the PLC address space, the SCADA tag map, or the OpenStack OT endpoints as fixed constants. Instead, it derives a runtime industrial model before allowing control-oriented ATT&CK execution.

### Conservative Ubuntu node disk cleanup

For OT/monitoring nodes that become storage-constrained during repeated alerting or forensic collection, the repository includes a conservative cleanup helper:

- `cleanup_ubuntu_node_disk_safe.sh`
- `pre_memory_cleanup_inside_node.sh`

It is designed for Ubuntu nodes and removes only non-essential data such as:

- rotated and compressed logs under `/var/log`
- vacuumed `systemd` journal data
- APT caches
- stale files in `/tmp` and `/var/tmp`
- zero-byte Suricata side logs

It does **not** remove active Suricata rule files, current `eve.json`, current `fast.log`, current configuration, or preserved forensic artifacts.

The outer wrapper connects by SSH and executes `pre_memory_cleanup_inside_node.sh` remotely. If a remote dump path is provided, the cleanup preserves:

- the dump file itself
- its parent directory
- `/tmp/LiME`

### Independent node health dashboard

The repository includes an independent operational module for node-state inspection:

- view: `node_health.html`
- route: `/node-health`
- backend: `app_core/infrastructure/node_health/node_health_api.py`

This module does not alter the existing FOC, attack, detection or forensic workflows. It provides:

- OpenStack-driven node discovery with no hardcoded node list
- OS-aware SSH user selection derived from the instance image
- per-node live health probe for CPU, RAM, disk and key services
- per-node IDS, SIEM and agent inventory derived from `tools-installer/installed` and `tools-installer-tmp`
- live SSH inspection of tool runtime state, version, Suricata rule-files, NICS signatures and Wazuh local rule/FIM configuration
- a tree-style security menu that separates package presence on node from service runtime state and lets the operator drill down per tool
- per-tool rule inspection showing the real rule file content read from the node plus a compact interpretation for Suricata custom signatures
- startup overview mode that shows only scenario-wide and host-wide state until the user explicitly selects a node
- an embedded action console
- one-click safe disk cleanup over SSH using `pre_memory_cleanup_inside_node.sh`
- node-level time synchronization inspection using the same controlled strategy as the FOC temporal pre-flight
- explicit `Measure Clock Offset` and `Fix Time Synchronization` controls in the Node Health view

For time synchronization, Node Health does not implement a second temporal engine. It reuses the same repository helper:

- `app_core/infrastructure/forensics/scripts/time_sync_preflight.sh`

The legacy repository-root entrypoint:

- `e2_max_clock_offset.sh`

is preserved as a compatibility wrapper and forwards to the canonical forensic script.

but applies it to the currently selected instance through a node-scoped execution filter. This keeps the semantics consistent between:

- Node Health
- FOC Reconstruction
- Causal Reconstruction

while avoiding hardcoded instance IPs or duplicate timing logic.

The Node Health time-sync controls follow the same safety model:

- `Measure Clock Offset` is non-destructive and only measures skew
- `Fix Time Synchronization` is explicit and may install or start `chrony`, execute `chronyc -a makestep`, restart `chrony`, and then measure again
- correction is never applied automatically when the view loads
- if an active forensic case exists, corrective synchronization is blocked by default
- corrective synchronization during an active case requires an explicit maintenance or laboratory override
- every corrective synchronization run is recorded as a time-sync intervention artifact

Node-scoped temporal outputs are written under:

```bash
runtime/time_sync/node_health/<instance_id>/
```

including:

- `time_sync.json`
- `time_sync_before.json`
- `time_sync_after.json`
- `job_status.json`
- `time_sync.stdout.log`
- `time_sync.stderr.log`

The Node Health UI exposes, per selected node:

- temporal synchronization state
- max clock offset in milliseconds
- selected node offset
- whether correction was applied
- whether `chrony` was already present or installed by the helper
- whether `makestep` was applied
- nodes measured and failed inside the scoped run
- worst-node summary from the resulting measurement set

This is intentionally operational rather than evidentiary. It is meant to support node maintenance and temporal conditioning before forensic acquisition or causal reconstruction, not to replace the preserved time-sync artifacts attached to a forensic case.

The industrial resolver is implemented in:

```bash
app_core/infrastructure/attack/industrial_resolver.py
```

Its role is to construct a unified industrial context from four classes of source:

- **PLC structured-text source**
  - parses IEC 61131-3 declarations such as `level AT %QW2 : INT` and `level_max AT %QW3 : INT`
- **FUXA project source**
  - parses ModbusTCP device configuration, tag inventory, tag addresses, and HMI variable references
- **industrial runtime state**
  - reads `industrial-scenario/state/industrial_state.json` to recover OT deployment state and installed OT tool status
- **OpenStack runtime inventory**
  - resolves the actual PLC and SCADA instances, their current IP addresses, and their runtime accessibility

The resolver writes a set of runtime artifacts under:

```bash
app_core/infrastructure/attack/runtime/
```

including:

- `industrial_plc_map.json`
- `industrial_scada_map.json`
- `industrial_runtime_assets.json`
- `industrial_asset_register_map.json`

This industrial asset register map is the canonical OT execution substrate. It fuses:

- PLC variables
- SCADA tags
- semantic roles
- current PLC and SCADA IPs
- Modbus endpoint candidates
- attack usage roles
- write eligibility
- validation notes

An important scientific constraint follows from this design: **FUXA tag numbering and OpenPLC internal register numbering are not assumed to be identical**. For example, the PLC program may define `level` at `%QW2` while FUXA references the same signal with address `3`. This difference is treated as an uncertainty that requires live validation rather than a hardcoded equivalence.

### Live Modbus validation and safety policy

Before any Modbus write-oriented ATT&CK technique is executed, the platform can validate the real tank map using:

```bash
app_core/infrastructure/attack/scripts/validate_tank_modbus_map.py
```

This validator:

- reads `industrial_asset_register_map.json`
- connects to the runtime PLC endpoint
- probes candidate holding registers and coils
- records validated Modbus addresses
- records endpoint conflicts when FUXA visual metadata diverges from runtime OT connectivity

The resulting validation evidence is written to:

```bash
app_core/infrastructure/attack/runtime/industrial_modbus_validation.json
```

The write policy is then generated from the validated map into:

```bash
app_core/infrastructure/attack/ics_attack_policy.json
```

This policy is intentionally restrictive:

- default write posture is **deny**
- writes require live validation
- writes require read-before-write
- writes require read-after-write
- writes require rollback
- writes require restored-state verification

For the current tank scenario, the main write target is the setpoint-like variable:

- `level_max`

By contrast, the following variables are treated as read-only by default:

- `level`
- `openOutletValve`
- `outletValveOpenStatus`
- `openInletValve`
- `inletValveOpenStatus`
- `airValveOpenStatus`

This distinction is scientifically important. `level_max` functions as a threshold or setpoint parameter and is therefore suitable for controlled parameter-manipulation experiments. `level`, valve commands, and valve-state variables are not accepted as generic write targets unless a separate explicitly bounded experiment is defined.

The practical consequence is strict:

- if the industrial map is not validated, write techniques do not report a simulated success
- they terminate in a degraded or failed state instead

### Controlled tank setpoint manipulation

The OT attack strategy for this scenario is organized around a reproducible control-manipulation chain:

- `T0846_ICS_REMOTE_SYSTEM_DISCOVERY`
  - bounded OT service validation against the runtime PLC and SCADA assets
- `T0861_POINT_AND_TAG_IDENTIFICATION`
  - live read-oriented identification of tank variables and their SCADA counterparts
- `T0802_AUTOMATED_COLLECTION`
  - short-window collection of process-state observations
- `T0877_IO_IMAGE`
  - I/O snapshot of level, threshold, valve commands, valve states, and enable conditions
- `T0836_MODIFY_PARAMETER`
  - controlled modification of `level_max`
- `T1692_001_UNAUTHORIZED_COMMAND_MESSAGE`
  - the same bounded target represented as an unauthorized Modbus command event
- `T0831_MANIPULATION_OF_CONTROL_MODBUS`
  - wrapper-level causal chain covering discovery, mapping, pre-state capture, manipulation, rollback, and recoverability
  - legacy reference copy preserved at `app_core/infrastructure/attack/scripts/t0831_manipulation_of_control_modbus_antiguo.py`

The principal experimental scenario is therefore:

- **Controlled Tank Setpoint Manipulation**
  - PLC source: `TankControl.st`
  - SCADA source: `fuxa_mi_proyecto_simple.json`
  - principal parameter target: `level_max`
  - principal ATT&CK technique: `T0836`
  - control-impact wrapper: `T0831`
  - command-oriented representation: `T1692.001`

An important operational detail applies to this chain:

- the SCADA layer may be the user-selected control surface in the dashboard
- but the effective Modbus write endpoint remains the validated PLC endpoint exposed by the runtime industrial map
- when a PLC private IP is available, the Modbus write path prefers that internal endpoint over the floating IP
- this keeps the OT command on the internal path that is expected to be visible to the PLC-side Suricata sensor
- recent `T0831` outputs therefore preserve both:
  - `requested_target_*`
  - `effective_target_*`

This prevents a false interpretation where a run appears to target `SCADA` directly even though the actual `mbpoll` write was issued against the PLC Modbus service.

### Structured OT evidence generated by the attack layer

The industrial ATT&CK layer is accepted as successful only when it produces structured OT evidence rather than a terminal transcript alone.

Typical outputs include:

- `industrial_asset_register_map.json`
- `industrial_modbus_validation.json`
- `plc_state_before.json`
- `plc_state_after.json`
- `plc_state_restored.json`
- `modbus_transaction_log.json`
- `rollback_log.json`
- `causal_edges.json`
- `causal_graph.json`
- `causal_path_recoverability.json`
- `uncertainty_report.json`

These artifacts preserve:

- attack identity
- MITRE identity
- scenario identity
- requested target identity when the dashboard selection differs from the effective OT endpoint
- target IP and target role
- effective target IP and effective target role
- source IP when available
- execution parameters
- observed pre-state and post-state
- rollback outcome
- causal dependencies
- uncertainty statements

This makes the OT layer scientifically stronger than a simple “write register X” workflow. The experiment can be evaluated as a causal chain from Modbus action to process-visible effect, SCADA observability, and restoration behavior.

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

### Operational home summary

The main `index.html` home view now consumes a lightweight aggregated backend summary instead of rebuilding the operational state from many independent requests. The goal is to keep the dashboard responsive while making the displayed state explicit and scientifically interpretable.

The aggregated home summary exposes:

- `active_scenario`
- `openstack_inventory_status`
- `node_status`
- `tool_status`
- `attack_status`
- `detection_status`
- `forensic_status`
- `evidence_status`
- `foc_status`

The home view differentiates operational states such as:

- `not_configured`
- `not_started`
- `running`
- `completed`
- `failed`
- `unavailable`
- `unknown`

This prevents a missing scenario from being presented as a generic backend failure. For example, when no scenario is active, the home view reports `No active scenario selected` instead of leaving every metric as `Unknown`.

The summary is intentionally compact. It focuses on:

- active scenario
- OpenStack node count
- installed tool count
- detected alert count
- forensic case count
- preserved evidence count
- FOC readiness state

Full details remain inside the dedicated views for monitoring, forensics, and reconstruction.

### Detection, Wazuh, and FOC relationship

For OT experiments, the real-time detection path is:

1. `Suricata` on the observing node detects the network event and writes it to `eve.json`.
2. `Wazuh Agent` on that same node ingests the Suricata event.
3. `Wazuh Manager` on the monitoring node receives and reports the alert.
4. `FOC Reconstruction` indexes the attack event, the detection event, and the forensic artifacts so they can be linked as cause-and-effect evidence.

For Modbus register manipulation in particular, the platform now distinguishes the operational roles more clearly:

- `Suricata` provides the authoritative network detection
- `Wazuh` provides manager-side alerting and severity handling
- `FOC` reconstructs whether the detection can be causally linked to a specific indexed attack and to preserved evidence

This same relationship is reflected in the home dashboard through:

- short real-time alert descriptions
- explicit detection status instead of generic `Unknown`
- FOC missing-component reporting when reconstruction is still incomplete

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

The current automatic DFIR workflow now treats the rolling capture directory as a continuous observational buffer rather than as a blocking pre-acquisition copy step. The rolling source remains:

- `app_core/infrastructure/ics_traffic/captures/full_scenario_captures`

When a case is created automatically, the platform records the case creation time, acquisition start time, trigger time when available, and the intended network context window. It then prioritizes volatile evidence and performs:

`case creation -> acquisition profile initialization -> memory acquisition first -> network context import from rolling PCAPs -> disk acquisition -> analysis and reconstruction`

This means memory acquisition is no longer delayed by case-level PCAP preservation when continuous rolling capture already exists.

Only the PCAP segments that overlap the case window are imported into the case. The selection rule is:

`pcap_start <= case_window_end and pcap_end >= case_window_start`

The importer writes:

- `CASE_ID/network/traffic_preserved/network_context_manifest.json`

and records:

- source capture root
- selected PCAPs
- original path
- case-local path
- interface
- segment start time
- segment end time
- preservation mode
- size
- SHA-256 hash
- import time
- integrity status

If a rolling PCAP segment still appears to be open and actively written by `tcpdump`, it is not preserved as final evidence yet. Instead, it is recorded as a pending segment inside the manifest and can be imported later after rotation closes safely.

The automatic workflow no longer relies on "latest case" resolution for case-bound network preservation. It passes the explicit `case_id` and `case_dir` so the imported network context is attached to the correct forensic case.

The preferred preservation mode order is:

- `reflink` if supported
- `hardlink` if source and destination share the same filesystem
- `copy` with `rsync` fallback otherwise

Regardless of the preservation mode, every preserved segment used as evidence is hashed and represented in the manifest.

![Live Traffic Analyzer](Images_readme/forensic_live_traffic_analyzer.png)

### Why it matters

This design separates operational traffic acquisition from forensic preservation while allowing both to work together. It supports continuous observability, user-driven inspection, and stronger case reconstruction through the integration of traffic, disk, and memory artifacts within a unified investigative context.

It also improves forensic volatility handling. RAM is the most volatile source, so the platform now prioritizes memory preservation first while still retaining a strong network context from the continuous rolling capture buffer. FOC Reconstruction and FOC Causal Reconstruction continue consuming normalized preserved case artifacts; they are not turned into acquisition modules.

### Volatility 3 memory analysis and Linux symbol workflow

Memory analysis in NICS CyberLab is based on **Volatility 3** and is designed as a real case-driven workflow rather than as a static wrapper around a single dump file.

The relevant implementation surface is split into:

- `app_core/infrastructure/forensics/volatility_symbols.py`
- `app_core/infrastructure/forensics/scripts/analyze_memory_vol3.sh`
- `app_core/infrastructure/forensics/scripts/generate_vol3_symbols_ssh.sh`
- the Forensics and FOC backend endpoints that orchestrate inventory, symbol resolution, generation jobs, and plugin execution

The platform now keeps Linux symbols **inside the project itself** so the memory-analysis pipeline does not depend on an external hardcoded directory. The internal symbol store is:

```bash
app_core/infrastructure/forensics/volatility_symbol_store/
```

with the subdirectories:

- `app_core/infrastructure/forensics/volatility_symbol_store/linux`
- `app_core/infrastructure/forensics/volatility_symbol_store/metadata`

This store contains compressed Volatility 3 Linux ISF symbol files such as `.json.xz` plus metadata that records how and when each symbol was generated.

#### Why Linux symbols are required

For Linux memory analysis, Volatility 3 can usually read the memory image and extract the kernel banner first, but higher-value plugins require a compatible symbol table for the captured kernel.

In practice, this means:

- `banners.Banners` may succeed without a full kernel symbol match
- `linux.pslist.PsList`
- `linux.lsmod.Lsmod`
- `linux.sockstat.Sockstat`
- `linux.check_syscall.Check_syscall`
- `linux.bash.Bash`

require a compatible Linux ISF symbol file that matches the captured kernel closely enough for Volatility 3 to build the kernel layer and symbol table correctly.

Without that symbol, Volatility 3 typically fails with requirement errors such as:

- `Unsatisfied requirement: kernel.layer_name`
- `Unsatisfied requirement: kernel.symbol_table_name`
- `Unable to validate plugin requirements`

#### Supported operating-system families

The current integrated workflow supports Linux symbol handling for the operating-system families used by the platform:

- **Ubuntu**
  - the system detects the OS family, codename, kernel release, and architecture dynamically
  - a matching Ubuntu debug-symbol workflow is used to obtain the data needed to build the Volatility 3 ISF
- **Debian**
  - the system detects the OS family, codename, kernel release, architecture, and kernel package version dynamically
  - a matching Debian debug-package workflow is used to obtain the data needed to build the Volatility 3 ISF

These decisions are made from preserved case context, runtime inventory, and live node inspection when needed. The user is not expected to type the kernel version, distribution family, SSH user, or target parameters manually.

#### Symbol inventory, resolution, and generation

The symbol-management layer follows four steps:

1. **Inventory**
   - scan the internal project symbol store
   - read symbol metadata
   - expose available symbols by OS, codename, kernel, architecture, hash, and generation mode

2. **Resolution**
   - inspect the selected memory dump
   - run `banners.Banners` when necessary
   - infer the required kernel banner and kernel release
   - match the dump against existing local symbols

3. **Generation**
   - if no compatible symbol exists, launch a controlled symbol-generation workflow
   - use the builder logic from the integrated backend, not a hardcoded shell script per node
   - generate the Linux ISF, compress it to `.json.xz`, and write it into the in-project symbol store

4. **Reuse**
   - if a compatible symbol already exists, reuse it directly
   - do not overwrite an existing symbol silently

The metadata sidecar for each symbol is preserved under:

```bash
app_core/infrastructure/forensics/volatility_symbol_store/metadata/
```

and records technical context such as:

- target operating-system family
- codename
- kernel release
- architecture
- source package or source package version when known
- generation timestamp
- generation mode
- SHA-256

#### Builder safety model

The integrated symbol-generation workflow is designed to be operationally safe for the rest of the platform:

- the memory source node is **not** modified with debug packages
- the symbol builder operates separately from the target workload
- generated symbols are copied back into the host-side project store
- Wazuh configuration is not modified by symbol generation
- the workflow is designed to avoid persistent repository drift on the builder environment
- temporary build material such as extracted `vmlinux` files or large debug packages is cleaned after generation

If a `System.map` file exists but is clearly invalid or too small, it is ignored and the symbol is built from valid kernel debug material instead of trusting an incomplete map.

#### UI workflow in Forensics and FOC

The symbol workflow is available from both:

- **Forensics view**
- **FOC Reconstruction view**

In both views, the workflow is dynamic:

- the selected case or memory artifact determines the relevant dump
- the system derives the likely node, operating-system family, and kernel context automatically
- the system checks whether compatible symbols already exist in the internal project store
- if symbols exist, analysis proceeds directly
- if symbols do not exist, the UI can offer symbol generation or trigger it automatically depending on the selected mode

The user is not required to provide:

- IP addresses
- node names
- kernel strings
- SSH users
- symbol paths

#### Memory-analysis outputs

When memory analysis is executed successfully or partially, the workflow writes structured outputs into the case tree. At the Forensics side, Volatility outputs are preserved under case-local memory result directories such as:

```bash
app_core/infrastructure/forensics/evidence_store/<CASE_ID>/memory/volatility_results_<node_ref>/
```

The output set may include:

- `banners.txt`
- `pslist.txt`
- `lsmod.txt`
- `sockstat.txt`
- `check_syscall.txt`
- `bash.txt`
- `memory_preflight.json`
- `memory_findings.json`

The memory-analysis phase is intentionally explicit about partial success. A dump may be readable while some plugins fail because symbols are missing or only partially compatible. In that case the platform records the real reason rather than fabricating a successful result.

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
- `foc-reconstruction/attestations/attack_attestation.json`
- `foc-reconstruction/attestations/detection_attestation.json`
- `foc-reconstruction/attestations/alerts_normalized.json`
- `foc-reconstruction/attestations/alert_correlation.json`
- `foc-reconstruction/attestations/alert_correlation_summary.json`
- `foc-reconstruction/attestations/acquisition_profile.json`
- `foc-reconstruction/attestations/forensic_intervention.json`
- `foc-reconstruction/attestations/forensic_analysis_manifest.json`
- `foc-reconstruction/attestations/scenario_ground_truth.json`
- `foc-reconstruction/attestations/case_manifest_link.json`
- `foc-reconstruction/attestations/foc_context_summary.json`
- `foc-reconstruction/validation/foc_readiness_report.json`
- `foc-reconstruction/indexes/id_mapping.json`
- `foc-reconstruction/indexes/sources_index.json`

### Últimas mejoras en la vista FOC Reconstruction (2026-06-16)

Se han añadido mejoras en la interfaz de `FOC Reconstruction` para mostrar con mayor claridad la calidad semántica del caso y las razones reales que impiden la reconstrucción causal completa. Cambios principales:

- Panel **Trigger Selection**: muestra el `triggering_alert_id`, `triggering_alert_name`, `triggering_alert_severity`, `triggering_alert_original_sensor`, `triggering_alert_collector`, `triggering_alert_protocol`, `triggering_alert_mitre`, `trigger_selection_score`, `trigger_selection_reason`, `candidate_triggers_evaluated` y `stronger_trigger_available`. La vista normaliza sensores mal serializados, intenta enriquecer MITRE/protocolo desde la timeline actual y separa `global_alerts_indexed`, `alerts_in_selected_case_window` y `trigger_candidates_in_case_window` para no mezclar actividad global con la ventana del caso.

- **FOC JS cache-bust**: `app_core/static/foc_reconstruction.html` carga `app_core/static/js/foc_reconstruction.js` con un sufijo de versión (`?v=...`) para evitar que el navegador siga sirviendo una versión antigua del panel `Trigger Selection` después de una corrección frontend.

- Etiqueta **Trigger quality**: una etiqueta concisa (`strong`, `medium`, `weak`, `unknown`) derivada del `trigger_selection_score` y la severidad para evitar sobreventa de causalidad completa.

- Lista de **Blockers reales**: se muestran las secciones que bloquean la reconstrucción (`attack_attestation`, `detection_attestation`, `alerts_normalized`, `alert_correlation`, `forensic_intervention`) con su estado actual, campos faltantes, razón de bloqueo, fuente esperada y si puede resolverse con fuentes locales.

- Mejora en `detection_attestation`: la vista intentará rellenar honestamente campos verificables localmente como `engine_version`, `mitre_technique`, `rule_file`, `rule_source` y `enabled_at`. Si no existe fuente verificable, se mostrarán `unknown`/`not_available` y el readiness permanecerá como `partial`.

- Mejora en `forensic_intervention`: se intenta extraer `commands_executed` desde las fuentes preservadas (pipeline events, manifests, chain of custody). Si no hay evidencia real, se muestra `commands_executed: not_available` y la razón `commands not preserved in current sources`.

- Panel **Why causal reconstruction is not ready**: una explicación directa y concisa que lista las attestations incompletas y por qué impiden marcar `causal_reconstruction_ready: true`.

Notas operativas:

- La UI respeta el valor de `causal_reconstruction_ready` y no lo modifica. Permanecerá en `false` hasta que las attestations y enlaces sean suficientemente completos y trazables.
- Umbrales de calidad del trigger (por defecto): `>=400` → `strong`, `250–399` → `medium`, `>0` → `weak`. Estos umbrales pueden ajustarse si se desea.

Para ver los cambios en acción, abrir la página `app_core/static/foc_reconstruction.html` en la aplicación y recargar la reconstrucción (`Bootstrap` / `Regenerate` / `Refresh`).

The FOC dashboard KPI cards (`Alerts`, `Attacks`, `Triage`, `MITRE`) now fall back to aggregated reconstruction summaries when the browser does not render `timeline.events` correctly on first load. This avoids false zero values when the dashboard payload still contains valid indexed detections and attacks.

The graph panel in `FOC Reconstruction` has also been upgraded into a lightweight **FOC Reconstruction Graph Suite** without changing the backend reconstruction logic. The graph now presents an aggregated **FOC Reconstruction Snapshot** with visual layer toggles (`Topology`, `Attack`, `Detection`, `Attack→Alert`, `Evidence`, `Custody`, `Analysis`, `Timeline`, `Findings`, `Semantic`, `Causal`), lightweight client-side filters, and a drill-down side panel. It does not render every raw alert or artifact as an individual node, does not recalculate causal logic in the browser, and keeps `Semantic` / `Causal` explicitly unavailable or blocked when those layers do not yet exist in real FOC data.

The same graph view now includes an **Investigation Questions** mode built entirely as lightweight frontend presets. Each question applies a predefined layer and filter configuration on top of the already indexed FOC state so the analyst can move through the reconstruction as a forensic story: affected systems, attack activity, detections, confirmed correlations, uncertain alerts, noise, evidence, custody, and analysis completeness. These presets do not trigger new heavy backend queries and do not alter the reconstruction logic; they only reconfigure the aggregated graph view and the explanatory drill-down panel.

### Multilayer forensic analysis under demand

`FOC Reconstruction` now includes an **on-demand multilayer forensic analysis workflow** for any preserved case found under:

```bash
app_core/infrastructure/forensics/evidence_store/CASE-*
```

This workflow is intentionally **not automatic**. Opening the FOC dashboard does not execute analysis. Instead, the **Evidence and Cases** panel exposes a case-level action:

- `Run Multilayer Forensic Analysis`

This action is only meaningful when preserved evidence already exists for the selected case. The goal is to turn a preserved case into a validated analytical object without coupling the workflow to a single hardcoded `CASE-*`.

The backend now exposes dedicated case-analysis endpoints:

- `GET /api/foc/cases`
- `GET /api/foc/cases/{case_id}/analysis-status`
- `POST /api/foc/cases/{case_id}/analysis/run`
- `GET /api/foc/cases/{case_id}/analysis/logs`
- `GET /api/foc/cases/{case_id}/analysis/report`
- `POST /api/foc/cases/{case_id}/analysis/validate`

The analysis is executed in background and persists its own runtime state per case at:

```bash
<CASE_DIR>/analysis/analysis_status.json
```

The phase workflow is explicit and validated. The current implementation uses the following sequence:

- `preflight_validation`
- `evidence_inventory`
- `integrity_custody_validation`
- `temporal_validation`
- `network_analysis`
- `memory_analysis`
- `disk_analysis`
- `ot_export_analysis`
- `alerts_detection_analysis`
- `pipeline_custody_analysis`
- `unified_forensic_timeline`
- `cross_layer_findings`
- `forensic_analysis_report_generation`
- `foc_readiness_update`

Generated outputs are written inside the case itself, under:

- `analysis/00_inventory/evidence_inventory.json`
- `analysis/01_integrity_custody/integrity_custody_report.json`
- `analysis/02_time_validation/clock_offset_report.json`
- `analysis/03_network/network_findings.json`
- `analysis/04_memory/memory_findings.json`
- `analysis/05_disk/disk_findings.json`
- `analysis/06_ot/ot_findings.json`
- `analysis/07_alerts/alert_findings.json`
- `analysis/08_pipeline_custody/pipeline_findings.json`
- `analysis/09_timeline/unified_forensic_timeline.json`
- `analysis/10_findings/cross_layer_findings.json`
- `analysis/forensic_analysis_manifest.json`
- `analysis/forensic_analysis_report.json`
- `analysis/forensic_analysis_summary.md`

The dashboard shows phase-level state as:

- `pending`
- `running`
- `completed`
- `skipped_*`
- `failed_*`

This is important because the workflow must remain honest:

- if a memory dump does not exist, memory analysis is skipped
- if a RAW disk exists but Sleuth Kit is missing, disk analysis fails with an explicit dependency error
- if a preserved artifact cannot be read, the failing phase records the expected output, debug paths, and the suggested action

The **visual interpretation** of this multilayer analysis is also intentionally **on-demand**. `FOC Reconstruction` does not load the full multilayer cockpit automatically when the main dashboard or the case-analysis modal is opened. Instead:

- the modal first loads only lightweight execution state, phase state, and debug context
- the analyst must explicitly press `View Analysis Report`
- only then does the UI request the normalized visual summary and the derived report view

This keeps the main FOC view responsive and avoids loading heavyweight forensic summaries when the user only wants to inspect status or phase progress.

The workflow reuses the real local analysis surface already present in the repository:

- `app_core/infrastructure/forensics/scripts/analyze_network_pcap.sh`
- `app_core/infrastructure/forensics/scripts/analyze_memory_vol3.sh`
- `app_core/infrastructure/forensics/scripts/analyze_disk_tsk.sh`
- `app_core/infrastructure/forensics/scripts/build_case_timeline.py`
- `app_core/infrastructure/forensics/scripts/time_sync_preflight.sh` as the formal time synchronization pre-flight helper

### Time Synchronization Pre-flight

The platform now treats clock measurement and optional correction as a distinct, auditable pre-flight activity.

The canonical temporal helper is:

```bash
app_core/infrastructure/forensics/scripts/time_sync_preflight.sh
```

The repository-root wrapper:

```bash
e2_max_clock_offset.sh
```

is retained for compatibility with older commands and integrations.

and it is intentionally split into two explicit modes:

- **measure only**
  - default
  - safe
  - does not install packages
  - does not change services
  - does not change node clocks
  - prefers `chronyc tracking` when available
  - falls back to a non-destructive SSH epoch comparison when `chrony` is not installed on the target node
- **measure and fix**
  - explicit
  - only when the operator requests correction
  - may install and start `chrony`
  - may run `chronyc -a makestep`
  - may restart `chrony`

The default safe mode is:

```bash
bash app_core/infrastructure/forensics/scripts/time_sync_preflight.sh --case-id CASE-YYYYMMDD-HHMMSS
```

The explicit correction mode is:

```bash
DO_FIX_TIME=1 SSH_KEY="$HOME/.ssh/my_key" bash app_core/infrastructure/forensics/scripts/time_sync_preflight.sh --case-id CASE-YYYYMMDD-HHMMSS --fix-time
```

The script also accepts:

- `--out`
- `--threshold-ms`
- `--status-filter`
- `--ip-prefix`

or equivalent environment variables such as:

- `TIME_SYNC_OUT`
- `TIME_SYNC_BEFORE_OUT`
- `TIME_SYNC_AFTER_OUT`
- `TIME_SYNC_THRESHOLD_MS`
- `TIME_SYNC_DEGRADED_THRESHOLD_MS`
- `DO_FIX_TIME`

The output is now preserved as JSON instead of only console text. When a case is known, the primary artifact is written to:

```bash
app_core/infrastructure/forensics/evidence_store/<CASE_ID>/metadata/time_sync.json
```

and, when correction is requested, the helper also preserves:

```bash
app_core/infrastructure/forensics/evidence_store/<CASE_ID>/metadata/time_sync_before.json
app_core/infrastructure/forensics/evidence_store/<CASE_ID>/metadata/time_sync_after.json
```

The JSON records:

- generated time
- mode
- whether correction was requested
- synchronization thresholds
- nodes successfully measured
- failed nodes and failure reasons
- maximum clock offset in milliseconds and seconds
- worst node
- per-node SSH user used
- whether `chrony` already existed
- whether `chrony` was installed by the script
- whether correction was applied
- before/after summaries when correction mode was used

The synchronization state is normalized as:

- `synchronized`
- `degraded`
- `not_synchronized`
- `unknown`

using these default thresholds:

- `max_clock_offset_ms <= 1000`
  - `synchronized`
- `max_clock_offset_ms <= 5000`
  - `degraded`
- `max_clock_offset_ms > 5000`
  - `not_synchronized`

This pre-flight is deliberately **not automatic** during view load. In `FOC Reconstruction` it is exposed as an explicit user action:

- `Time Synchronization`
- `Measure Clock Offset`
- `Fix Time Synchronization`

The correction path requires explicit confirmation in the UI so infrastructure changes never happen silently.

Temporal correction policy is deliberately conservative:

- measuring clock offset is considered non-destructive and is allowed by default
- corrective synchronization changes node state and may alter timestamps, logs, apparent event ordering, and volatile evidence
- therefore corrective synchronization must not run silently during an active forensic case
- if an active forensic case exists, corrective synchronization is blocked by default
- it only proceeds under an explicit laboratory or maintenance override
- every corrective synchronization run is recorded as an intervention artifact

This distinction matters methodologically:

- `Measure Clock Offset` supports temporal characterization
- `Fix Time Synchronization` is an infrastructure intervention
- the intervention may improve the uncertainty budget for later causal reconstruction
- but it must never be confused with passive observation of the original forensic state

### Multilayer Forensic Evidence Cockpit

The multilayer workflow now produces a dedicated **visual summary layer** for `FOC Reconstruction`:

```bash
analysis/visual/analysis_visual_summary.json
```

This file is generated in backend as a **derived, normalized, read-only summary** of already existing authoritative outputs. The frontend does not parse large raw reports or phase text logs directly in order to build the cockpit.

The corresponding API surface is:

- `GET /api/foc/cases/{case_id}/analysis/visual-summary`

The visual summary distinguishes three concepts that must not be conflated:

- **pipeline execution status**
- **evidence analysis status**
- **forensic reconstruction status**

This is scientifically important because a case can show:

- `progress_percent = 100`
- `execution_status = completed`
- `forensic_reconstruction_status = partial`

without contradiction. In that situation the pipeline finished, but some layers remain partial, ineffective, missing, or blocked, and semantic or causal reconstruction still has not been generated.

The visual summary includes:

- case and analysis identifiers
- execution timestamps
- progress percentage
- execution status
- evidence-analysis status
- forensic-reconstruction status
- confidence state
- main limitation
- warnings and blockers
- available layers
- normalized layer statuses
- artifact and log paths
- lightweight structural graph nodes and edges
- pipeline timeline entries
- forensic timeline entries
- visual recommendations

The cockpit is rendered as:

- executive status header
- layer status matrix
- evidence coverage ring
- structural-evidential analysis graph
- timeline panel
- limitations panel
- optional raw technical view

#### On-demand loading behavior

The cockpit is only loaded when the user explicitly presses:

- `View Analysis Report`

This action is exposed at **case level**, alongside:

- `Run Multilayer Forensic Analysis`
- `Open Analysis Status`
- `View Analysis Report`

If the user opens the case-analysis modal without requesting the report:

- the platform shows the current analysis status
- the phase matrix
- the debug panel
- available evidence layers
- and a placeholder explaining that the visual cockpit is available on demand

When `View Analysis Report` is pressed, the cockpit is opened in a **separate wide transparent window** dedicated to visual interpretation. This keeps the status modal focused on execution and debugging, while the report window can use a broader layout for:

- executive summary
- evidence coverage ring
- structural-evidential graph
- timeline views
- limitations
- optional raw technical views

If `View Analysis Report` is pressed while no completed or partial analysis exists, the UI reports that no analysis is available yet.

If `View Analysis Report` is pressed while analysis is still running, the UI reports:

- current execution status
- current phase
- current percentage
- any already known missing or incomplete outputs

If required report artifacts are still missing, the UI reports that fact explicitly instead of pretending the visual layer exists.

In other words, `View Analysis Report` acts as an explicit **on-demand inspection action**, not as a blind file opener. It first checks the current analytical state and then either:

- loads the cockpit
- reports that analysis has not started
- reports that analysis is still running
- or reports that expected derived outputs are still missing or incomplete

### Memory-analysis integration inside FOC Reconstruction

The FOC multilayer workflow treats memory as a first-class analytical layer, but it does not pretend that memory analysis is always available or always complete.

The memory phase now performs an explicit pre-flight and symbol-resolution workflow before attempting the full Linux plugin suite. The generated case artifacts include:

- `analysis/04_memory/memory_preflight.json`
- `analysis/04_memory/memory_findings.json`
- `analysis/04_memory/<dump_id>/vol3_banners.txt`
- `analysis/04_memory/<dump_id>/vol3_pslist.txt`
- `analysis/04_memory/<dump_id>/vol3_sockstat.txt`
- `analysis/04_memory/<dump_id>/vol3_lsmod.txt`
- `analysis/04_memory/<dump_id>/vol3_check_syscall.txt`
- `analysis/04_memory/<dump_id>/vol3_bash.txt`
- `analysis/04_memory/<dump_id>/vol3_execution_report.json`

The pre-flight artifact records whether memory analysis is possible for each dump and why. It includes technical fields such as:

- case identifier
- dump path
- dump size
- dump SHA-256
- inferred source node
- linked manifest and custody context
- detected operating-system family
- detected kernel
- symbol search paths
- symbols found
- Volatility 3 availability and version
- compatibility assessment
- blocking reason
- warnings

This design matters because a Linux memory dump can be:

- fully analyzable
- partially analyzable
- readable but blocked by missing symbols
- invalid or unsupported

and each state must be represented honestly.

#### Plugin-by-plugin execution model

The FOC memory phase does not reduce memory analysis to a single pass/fail bit. Instead, it executes plugins progressively and assigns each one its own state:

- `completed`
- `failed`
- `skipped`
- `not_available`

This means:

- `banners` can succeed even if process listing fails
- `pslist`, `sockstat`, `lsmod`, `check_syscall`, and `bash` can be recorded individually
- partial memory analysis remains visible to the user and to the final case report

If symbols are missing, the workflow records the exact failure instead of hiding it behind a generic `analysis failed` message. The debug record preserves:

- plugin name
- executed command
- exit code
- stdout path
- stderr path
- error message
- missing requirements
- kernel-layer status
- symbol-table status
- suggested fix

#### Multilayer meaning

Within FOC Reconstruction, memory is one layer of a broader analytical workflow that also covers:

- evidence inventory
- integrity and custody
- time validation
- network analysis
- disk analysis
- OT exports
- alerts and detections
- custody and pipeline analysis
- unified timeline
- cross-layer findings

The scientific rule is that missing Linux symbols must not falsely mark the whole case as complete. Instead:

- memory can be `failed_missing_symbols` or `partial_missing_symbols`
- the rest of the multilayer workflow can still continue where possible
- the final report must show memory as incomplete
- FOC readiness must reflect the real state of the analytical evidence

This preserves rigor: the platform can continue building a defensible network, disk, OT, alert, and timeline reconstruction while still exposing that the memory layer remains incomplete until compatible Volatility 3 symbols exist.

The same rigor is reflected in the visual cockpit. A phase marked `completed` is not automatically treated as green or evidentially useful. For example:

- a memory phase that technically completed
- but analyzed zero effective dumps
- or produced zero effective plugin results

is rendered as a **warning**, not as a full success.

Likewise:

- `skipped` is not success
- empty output is not success
- partial custody remains warning
- unavailable timeline remains explicit
- semantic reconstruction remains `not generated`
- causal reconstruction remains `blocked or not generated`

This prepares the visual base for later semantic and causal reconstruction work without manufacturing causal meaning ahead of time.

The FOC layer remains read-only with respect to:

- OpenStack deployment
- Terraform / Ansible
- attack execution
- Suricata / Wazuh configuration
- primary evidence content

It only adds **derived analysis outputs** under the selected case and then regenerates the FOC view so that:

- `Analysis` can stop being `0 / 10`
- `Forensic` can move beyond `NOT_COMPLETED`
- `Semantic` stays blocked until explicitly generated later
- `causal_reconstruction_ready` remains `false`

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

The FOC layer makes an explicit distinction between:

- **primary evidence**
  - PCAP
  - memory dumps
  - disk images
  - logs
  - OT exports
  - chain of custody records
- **derived reconstruction metadata**
  - BOMs
  - normalized alerts
  - attack and detection attestation
  - alert correlation
  - forensic intervention summaries
  - analysis manifests
  - context summaries

This distinction is important because the FOC module is read-only and reconstructive. It does not replace or mutate the original evidence sources.

The reconstruction layer also indexes industrial runtime and OT attack-support artifacts when present, including:

- `industrial_plc_map.json`
- `industrial_scada_map.json`
- `industrial_runtime_assets.json`
- `industrial_asset_register_map.json`
- `industrial_modbus_validation.json`
- `ics_attack_policy.json`
- OT attack outputs such as `causal_graph.json`, `uncertainty_report.json`, `modbus_transaction_log.json`, and restored-state snapshots

This is important for hybrid IT/OT experiments because it allows the FOC layer to reconstruct not only the existence of an industrial attack, but also the variable-resolution model, the validated register mapping, the policy boundary that allowed or denied a write, and the resulting causal evidence chain.

### Bootstrap and regeneration semantics

The module supports two reconstruction modes:

- **native**
  - the reconstruction layer exists before the experiment and can preserve IDs from the beginning
- **bootstrap**
  - the reconstruction layer is initialized after the experiment already has scenario, OT, tools, alert, attack, or forensic artifacts

Bootstrap mode is designed for passive adoption of the existing laboratory state. It reads the current project sources, derives normalized FOC identifiers, creates `id_mapping.json`, and reconstructs the manifest, BOMs, and timeline without altering the original files.

### Extended FOC attestation layer

The module now extends the original BOM-and-timeline reconstruction with a second normalized layer intended for causal reconstruction, uncertainty handling, and later scientific reproducibility analysis.

The new artifacts answer questions such as:

1. which scenario was deployed
2. which IT and OT nodes existed
3. which OpenStack instance corresponds to each node
4. which tools were installed on each node
5. which attack was executed
6. with which tool, protocol, parameters, register, and value
7. which detection mechanisms were active
8. which alerts were generated
9. which alerts correlate to which attacks
10. which forensic intervention was triggered
11. which cases, artifacts, and preserved evidence were created
12. which analysis outputs exist
13. what reconstruction context is available for later causal work

The new normalized files are:

- `attack_attestation.json`
  - normalized execution view of indexed attacks, targets, MITRE metadata, parameters, and protocol-level operation details when derivable
- `detection_attestation.json`
  - detection stack snapshot per node plus observed rules and high-level alert totals
- `alerts_normalized.json`
  - normalized alert records suitable for later correlation and uncertainty processing
- `alert_correlation.json`
  - explicit attack-to-alert correlation view derived from indexed relationships
- `alert_correlation_summary.json`
  - compact interface-safe summary of correlation counts, top signatures, top rules, top nodes, and missing-expected-alert samples
- `acquisition_profile.json`
  - preserved evidence profile separated from derived metadata
- `forensic_intervention.json`
  - case creation, orchestration, acquisition, and preservation events
- `forensic_analysis_manifest.json`
  - indexed forensic analysis events and analysis-output artifacts
- `scenario_ground_truth.json`
  - preserved scenario-level reference copied into the FOC context, later complemented by the authoritative causal ground truth under `scenarios/<scenario_id>/scenario_ground_truth.json`
- `case_manifest_link.json`
  - case-to-artifact link normalization
- `foc_context_summary.json`
  - compact answer-oriented summary of what the reconstruction layer currently knows
- `foc_readiness_report.json`
  - semantic completeness gate used before the derived causal reconstruction layer is allowed to run

These files are generated by the same `foc-reconstruction` module and are referenced from the main `foc_manifest.json` under `derived_context`.

### FOC readiness validation

Before the derived causal module generates artifacts such as `causal_graph.json`, the base FOC layer validates whether the normalized context is semantically complete enough to support traceable reconstruction.

The readiness layer checks not only file existence, but also field usefulness and traceability across:

- `attack_attestation.json`
  - executed attack, tool, version, MITRE technique, target node, target IP, protocol, port, Modbus function when applicable, register, value, timestamps, and success criteria
- `detection_attestation.json`
  - detection engine, engine version, active rule, rule id, severity, rule file, rule hash when available, MITRE association, and active node
- `alerts_normalized.json`
  - timestamp, detector, rule id, severity, origin, destination, protocol, and normalized message
- `alert_correlation.json`
  - attack-to-alert relation, alert-to-rule relation, and correlation state
- `acquisition_profile.json`
  - triggering alert, acquisition profile, target nodes, expected artifacts, acquired artifacts, alert-to-start latency, start-to-sealed latency, and result
- `forensic_intervention.json`
  - associated case, trigger, target nodes, tools used, commands when present, collected artifacts, and custody events
- `forensic_analysis_manifest.json`
  - explicit `analysis_performed` state so preservation is not misrepresented as analysis
- `scenario_ground_truth.json`
  - expected causal edges, required evidence by edge, semantic rules, and temporal rules
- `case_manifest_link.json`
  - manifest linkage, artifact existence, and artifact presence inside the case manifest

The readiness report is written to:

```bash
foc-reconstruction/validation/foc_readiness_report.json
```

and exposes:

- `causal_reconstruction_ready`
- `readiness_state`
- `missing_prerequisites`
- per-artifact validation coverage and problem fields

This means the module will not mark `causal_reconstruction_ready: true` while attack attestation, detection attestation, alert correlation, acquisition profile, case-manifest linkage, or valid ground-truth structure remain incomplete.

### Alert correlation endpoint behavior

Because full alert correlation can become very large, the API now defaults to the compact summary instead of the full payload:

```bash
GET /api/foc/alert-correlation
```

returns:

```bash
foc-reconstruction/attestations/alert_correlation_summary.json
```

while:

```bash
GET /api/foc/alert-correlation?full=true
```

returns the complete:

```bash
foc-reconstruction/attestations/alert_correlation.json
```

This keeps the interface responsive while preserving full provenance for deep inspection or later export.

### FOC base layer versus derived causal reconstruction

The platform now separates two post-preservation layers clearly:

1. **FOC Reconstruction**
   - normalizes the preserved observational context
   - indexes scenario, tools, alerts, evidence links, custody, intervention, timeline, and multilayer analysis outputs
   - validates whether the preserved context is semantically ready for later causal work
2. **FOC Causal Reconstruction**
   - consumes the normalized FOC and multilayer analysis outputs
   - does not rerun forensic tools
   - does not reparse PCAP, memory, disk, or OT artifacts from scratch
   - derives ground-truth-aware causal edges, uncertainty, and reconstruction metrics under a controlled intervention model

This second layer is implemented in:

```bash
app_core/infrastructure/foc_causal_reconstruction/
```

and is intentionally a **derived, post-analysis module**, not a replacement for FOC Reconstruction.

The causal layer consumes already normalized artifacts such as:

- `foc-reconstruction/attestations/foc_context_summary.json`
- `foc-reconstruction/validation/foc_readiness_report.json`
- `foc-reconstruction/attestations/attack_attestation.json`
- `foc-reconstruction/attestations/detection_attestation.json`
- `foc-reconstruction/attestations/alert_correlation.json`
- `foc-reconstruction/attestations/forensic_intervention.json`
- `foc-reconstruction/attestations/case_manifest_link.json`
- `analysis/visual/analysis_visual_summary.json`
- `analysis/forensic_analysis_report.json`
- `analysis/01_integrity_custody/integrity_custody_report.json`
- `analysis/02_time_validation/clock_offset_report.json`
- `analysis/09_timeline/unified_forensic_timeline.json`
- `metadata/time_sync.json`

The causal layer therefore answers a different question from the base FOC layer:

- FOC Reconstruction:
  - *what was preserved, normalized, linked, and analysed*
- FOC Causal Reconstruction:
  - *which expected causal edges are supported, degraded, ambiguous, or missing under the preserved evidence and uncertainty budget*

### Scenario ground truth for causal reconstruction

The causal module requires an explicit scenario ground truth file:

```bash
scenarios/<scenario_id>/scenario_ground_truth.json
```

This file is scenario-level, not case-level. It declares:

- expected attack identity and MITRE context
- expected protocol or OT operation details
- expected artifacts and analysis layers
- expected causal edges
- semantic rules
- temporal rules
- optional edge weights for weighted CPR

If `scenario_ground_truth.json` is missing, or if it exists but does not define valid `expected_edges` (every edge must declare `edge_id`, `source`, `target`, and `required_evidence`), causal reconstruction is blocked and CPR is not calculated.

The ground truth that was actually used is never left implicit. Every causal run surfaces a `ground_truth_summary` block with `ground_truth_status`, `ground_truth_path`, `ground_truth_version`, `scenario_id`, `expected_edges` (count), `ground_truth_loaded_at`, and `ground_truth_validation_status`, so the cockpit can always answer "which ground truth produced this CPR" instead of computing a recoverability score against an unstated reference.

For the Modbus baseline scenario (`scn-b83dbbfb` / `industrial_file`), the expected causal path now includes two additional, evidence-grounded intermediate steps - `network_modbus_write` (driven by `analysis/03_network/network_findings.json`) and `plc_or_scada_state_observation` (driven by `analysis/06_ot/ot_findings.json`) - between the unauthorized Modbus write and the rest of the chain. The declared `target_register`/`expected_value` on these edges are explicitly labeled `register_value_basis: declared_in_ground_truth_not_packet_verified`, because the current network/OT parsers report Modbus traffic presence and OT record counts, not packet-level register/value extraction. Nothing is inferred beyond what the analyzers actually produce.

### Derived causal outputs

The causal layer never writes into the primary preserved evidence tree. It writes only to:

```bash
<CASE_PATH>/derived/reconstruction/
```

with these derived artifacts:

- `causal_graph.json`
- `uncertainty_report.json`
- `reconstruction_metrics.json`
- `causal_edges.csv`
- `causal_reconstruction_report.md`
- `causal_status.json`

These files are analytical derivatives. They do not replace the original evidence, the original manifest, or the original chain of custody.

### Causal metrics and scientific caution

The causal module computes audit-oriented indicators such as:

- `causal_path_recoverability` (CPR), with a derived `recoverability_label` (`mostly_recoverable`, `partially_recoverable`, `weak_recoverability`, `low_recoverability`) and a plain-language `interpretation` sentence so a CPR value is never shown without its caveat
- `weighted_cpr`
- `recovered_edges`, `degraded_edges`, `ambiguous_edges`, `missing_edges`
- `evidence_completeness_ratio`
- `integrity_verification_ratio`, now reported alongside a `graph_scope_integrity_ratio` (artifacts actually referenced by the graph) and a `case_wide_integrity_ratio` (manifest-wide hash validation) so a single ratio is never shown without explaining which scope it covers
- `analysis_coverage_ratio`
- `temporal_confidence_state`, reported together with the uncertainty window in seconds (not only milliseconds), the synchronization state, whether correction was applied, the worst node, and a one-line explanation of what that window means for event ordering
- `reconstruction_confidence` - always labeled **composite but non-authoritative**, never presented as an absolute score
- a `kpis` list attached to `reconstruction_metrics.json`, where every KPI carries its own `value`, `meaning` (formula), `interpretation`, and `severity`

The status model for expected edges is restricted to:

- `recovered`
- `degraded`
- `ambiguous`
- `missing`

`recovered` is never assigned from pure temporal proximity or visual correlation alone. The system requires preserved, linked, and auditable evidence support. An edge whose temporal check is declared but unresolved (`temporal_status: unknown`) can no longer be marked `recovered` either; it is downgraded to `degraded` with an explicit limitation. Only an edge with no temporal relation declared at all is `temporal_status: not_required`, which is the sole non-`supported` temporal state compatible with `recovered`. If support is partial, inferred, or temporally unresolved, the edge is degraded or ambiguous instead of being presented as confirmed.

Execution success and reconstruction quality are tracked as three independent axes rather than one blended status:

- `execution_status` (`not_started`, `running`, `completed`, `failed`) - whether the module ran technically
- `reconstruction_state` (`not_available`, `blocked`, `completed`, `completed_with_degradation`, `weak_reconstruction`, `failed`) - the quality of the causal reconstruction produced
- `scientific_confidence` (`strong`, `limited`, `weak`, `ambiguous`, `unknown`) - the interpretive weight the result can carry

`scientific_confidence` can never be `strong` when the ambiguous-edge rate exceeds 20% or when integrity is only `partial`, regardless of how high CPR is. `execution_status: completed` with `progress_percent: 100` only ever means the run finished - it is never read as a claim that the causal reconstruction itself is strong.

The graph is therefore a **derived causal-forensic reconstruction**, not a claim of absolute causality.

### CLI and API for causal reconstruction

The causal layer supports reproducible command-line execution:

```bash
python -m app_core.infrastructure.foc_causal_reconstruction.cli \
  --case-path app_core/infrastructure/forensics/evidence_store/CASE-YYYYMMDD-HHMMSS \
  --ground-truth scenarios/<scenario_id>/scenario_ground_truth.json \
  --out derived/reconstruction
```

Optional flags:

- `--strict`
- `--degraded-ok`
- `--json`

Recommended exit codes:

- `0`
  - outputs generated
- `1`
  - invalid case path
- `2`
  - missing manifest
- `3`
  - missing chain of custody
- `4`
  - missing ground truth
- `5`
  - validation failure or strict-mode missing-edge failure
- `6`
  - controlled internal failure

The FOC API now exposes lightweight causal endpoints:

- `GET /api/foc/causal/status?case_id=...`
- `POST /api/foc/causal/run`
- `GET /api/foc/causal/report?case_id=...`
- `GET /api/foc/causal/metrics?case_id=...`
- `GET /api/foc/causal/graph?case_id=...`

These endpoints read derived artifacts or start the background causal job. They do not execute forensic acquisition or heavy raw-evidence parsing.

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
- **Causal Reconstruction**
  - per-case causal state, prerequisites, CPR preview, degradation and ambiguity preview, and on-demand access to the derived causal cockpit

### Causal Reconstruction cockpit

The `FOC Reconstruction` interface exposes a dedicated on-demand causal action per case:

- `Run Causal Reconstruction`
- `View Causal Cockpit`

Opening the cockpit only fetches the lightweight `causal_status.json` (execution/reconstruction/confidence triad, ground truth summary, KPI list, and a per-file `outputs` availability map). Each detail section then fetches only the narrow endpoint it needs, independently and lazily, the first time it is expanded: the edge matrix and graph preview call `GET /api/foc/causal/graph-summary` (capped to 15 nodes / 20 edges, with a flat-table fallback if a future scenario exceeds the cap), the uncertainty section calls `GET /api/foc/causal/uncertainty`, and only the raw markdown report - the one section explicitly allowed to be heavier - calls the bundled `GET /api/foc/causal/report`. Opening one section never triggers a fetch for another. Initial page load and case-list polling never trigger a recompute of causality or a full-graph render.

The executive header shows the three status axes as distinct rows rather than one blended line:

- **Execution status** - whether the module ran (`not_started`, `running`, `completed`, `failed`)
- **Reconstruction state** - the quality of the result (`not_available`, `blocked`, `completed`, `completed_with_degradation`, `weak_reconstruction`, `failed`)
- **Scientific confidence** - the interpretive weight it can carry (`strong`, `limited`, `weak`, `ambiguous`, `unknown`)

Below that, the cockpit shows:

- a **Ground Truth** panel (status, version, scenario_id, expected edge count, validation status, resolved path)
- a **Derived Outputs** panel built from the same `available` / `not_available` / `invalid` map used by the raw artifact list, so the two can never contradict each other
- KPI cards (CPR, weighted CPR, recovered/degraded/ambiguous/missing edges, evidence completeness, integrity verification, analysis coverage, temporal confidence, reconstruction confidence), each carrying its own meaning, interpretation, and severity
- on-demand **Edge status matrix** (now including each edge's `meaning`, `status_reason`, and explicit "evidence found" / "evidence missing" labels), **Uncertainty budget** (temporal window in seconds with an explanation, plus the graph-scope vs. case-wide integrity breakdown), **Causal graph preview**, and **Raw markdown report**

A stale-data banner appears when the underlying analysis outputs (memory findings, forensic analysis report, visual summary) were modified after the causal artifacts were last generated, and now carries a `Regenerate Causal Reconstruction` action wired to the same on-demand run call - staleness is never resolved automatically. When the preserved clock offset makes temporal ordering weak, the header also surfaces an explicit warning and caution sentence rather than burying that risk in the uncertainty detail section.

The UI does not render a causal graph when `causal_graph.json` does not exist, and it does not present blocked or missing prerequisites as success.

### Time synchronization in FOC and causal reconstruction

`FOC Reconstruction` now shows a dedicated **Time synchronization** section per case and a modal for manual execution and inspection.

That surface reports:

- synchronization state
- maximum clock offset
- worst node
- nodes measured
- nodes failed
- whether correction was applied
- before/after summaries when available
- preserved output paths

The multilayer phase `temporal_validation` still writes:

```bash
analysis/02_time_validation/clock_offset_report.json
```

but now derives it from the richer preserved `metadata/time_sync.json` schema when available.

The causal reconstruction layer then prefers the preserved time-sync artifact over the older minimal clock-offset report whenever it exists. The uncertainty budget therefore uses:

```text
U = max_clock_offset + timestamp_resolution + acquisition_jitter
```

with the best preserved temporal source available:

1. `metadata/time_sync.json`
2. `metadata/time_sync_after.json` / `metadata/time_sync_before.json`
3. `analysis/02_time_validation/clock_offset_report.json`

As a result, improving synchronization before acquisition and reconstruction can lower:

- `max_clock_offset`
- `uncertainty_window`
- temporal ambiguity on expected edges

and can improve:

- `temporal_confidence_state`
- `causal_path_recoverability`
- `reconstruction_confidence`

without changing the preserved primary evidence itself. The change is only in the quality of the temporal calibration used to interpret already preserved events.

### FOC Scientific Evidence Lifecycle Dashboard

The platform now also exposes a second, separate scientific view:

```bash
app_core/static/foc_scientific_evidence_lifecycle.html
```

with controller:

```bash
app_core/static/js/foc_scientific_evidence_lifecycle.js
```

This view does **not** replace `FOC Reconstruction`. The technical `FOC Reconstruction` dashboard remains the deep operational and scientific workspace. The new page is an **executive scientific evidence dashboard** that answers a narrower question:

```text
What can we scientifically conclude from this execution, based on preserved evidence, multilayer analysis, causal reconstruction, and uncertainty?
```

It is intentionally lighter than the full FOC dashboard:

- it does not re-run forensic tools on page load
- it does not parse PCAPs, memory dumps, disk images, OT exports, or alerts in the browser
- it does not fetch large raw reports by default
- it only loads a lightweight case summary first
- technical artifacts remain accessible on demand

#### Canonical executive summary artifact

The new dashboard reads a derived summary stored per case at:

```bash
app_core/infrastructure/forensics/evidence_store/<CASE_ID>/derived/executive/evidence_lifecycle_summary.json
```

This file is generated from already-preserved and already-generated artifacts. It does not modify primary evidence and does not replace the original analysis or causal outputs.

Its schema centers on:

- `execution_summary`
- `trigger_summary`
- `evidence_lifecycle`
- `multilayer_analysis_summary`
- `causal_summary`
- `uncertainty_summary`
- `integrity_summary`
- `final_forensic_conclusion`
- `limitations`
- `next_required_actions`

The file is intentionally a **decision surface**, not a raw dump. It consolidates:

- the acquisition trigger that led to the preserved case
- the current preservation and custody state
- the multilayer forensic analysis usefulness matrix
- the derived causal reconstruction state and CPR family of metrics
- the preserved uncertainty budget
- the distinction between supported, degraded, and unsupported claims

#### View structure

The `FOC Scientific Evidence Lifecycle Dashboard` shows:

- **Executive Summary**
  - case ID, scenario ID, evidence lifecycle status, multilayer status, causal status, evidence-analysis confidence, forensic-reconstruction confidence, causal-interpretation confidence, and main limitation
- **Evidence Lifecycle Rail**
  - scenario deployed, attack executed, detection observed, trigger selected, acquisition executed, evidence preserved, integrity/custody checked, time synchronization validated, multilayer analysis completed, timeline generated, cross-layer findings generated, causal reconstruction generated, and executive conclusion produced
  - each rail card is clickable and opens a transparent explanation panel with:
    - what the phase means
    - why it has its current state
    - which artifacts support it
    - which scientific limitation applies
    - which detailed dashboard sections explain it further
  - internal links from that panel scroll to the relevant dashboard section and temporarily highlight it
- **Lifecycle Actions**
  - run/regenerate multilayer analysis, measure/fix time synchronization, run/regenerate causal reconstruction, run full evidence lifecycle, generate executive summary
- **Multilayer Forensic Analysis**
  - compact layer matrix with `status`, `usefulness_status`, artifact path, logs, summary, and limitations
- **Memory Analysis Coverage**
  - per-plugin memory coverage derived from preserved Volatility 3 execution reports: banner extraction, process listing, socket listing, loaded modules, syscall checks, shell history, symbol availability, and explicit blocked/partial plugin states
- **Alert Triage and Trigger Selection**
  - total indexed alerts, case-window relevance, correlated vs uncorrelated alerts, evaluated trigger candidates, selected trigger score/source/rule, stronger-trigger availability, rejected-candidate summary, and noise ratio
- **Causal Reconstruction Summary**
  - CPR, weighted CPR, recovered/degraded/ambiguous/missing edges, reconstruction confidence, and main limitation
- **Uncertainty Summary**
  - clock synchronization, evidence timestamp availability, available timestamp resolvability, causal-edge timestamp coverage, causal temporal ordering confidence, max clock offset, uncertainty window, correction state, integrity-validation execution vs case-wide integrity completeness, and worst node
- **Trigger Path vs Causal Attack Path**
  - explicit comparison between the acquisition trigger and the causal scenario under evaluation, with a third "cannot be confirmed" state distinct from "aligned" and "misaligned"
- **Modbus Specificity**
  - protocol, function-code, register, value, target PLC, and PLC/SCADA state precision with `confirmed` / `partial` / `not_available` semantics
- **Evidence-Based Reconstruction Story**
  - short narrative built only from preserved evidence and already-derived support artifacts; it does not invent causal precision or hide unsupported claims
- **Evidence-Based Hypothesis Support**
  - atom-level forensic reasoning layer: per-layer evidence atoms, cross-layer support matrix, hypothesis support report, forensic storyline, claimability boundary, and counter-evidence/gaps (see dedicated section below)
- **Final Forensic Conclusion**
  - supported conclusions, degraded or ambiguous conclusions, and unsupported or not-yet-claimable conclusions
- **Reports and Artifacts**
  - on-demand access to preserved and derived reports without loading their content automatically
- **Limitations and Next Required Actions**
  - explicit scientific caveats and concrete follow-up actions

#### Snapshot vs live-state semantics

The dashboard now labels the provenance of each major panel explicitly instead of mixing stored and live state:

- `Source: executive summary snapshot`
- `Source: live pipeline status`
- `Source: causal reconstruction artifacts`
- `Source: evidence-based hypothesis support`

If the executive summary is stale, that state is surfaced near the top of the executive panel, not buried as a minor tag. The banner reports:

- executive summary status
- the stale reason, for example `Causal reconstruction artifacts were modified after the executive summary was generated.`
- the required action, for example `regenerate executive summary`

The same rule applies to `Evidence-Based Hypothesis Support`: if any of its eleven tracked source artifacts changed after generation, the dashboard marks it `stale` and warns that its metrics are not authoritative until regenerated; if it has never been generated, it shows `not_generated` rather than silently omitting the section.

#### Multilayer analysis vs causal reconstruction

The dashboard keeps two different counting models separate:

- **multilayer analysis**
  - evaluates whether preserved evidence was processed across the expected forensic layers
  - example: `15 completed layers with useful output`
- **causal reconstruction**
  - evaluates whether the scenario's expected attack relations were reconstructed from preserved evidence
  - example: `5 recovered causal edges out of 8 expected relations`

The UI therefore includes an explicit bridge note:

`15 completed layers does not mean 8 causal edges must be fully recovered.`

#### CPR and Weighted CPR

The executive view no longer shows `CPR` and `Weighted CPR` as opaque scores.

It now exposes:

- the CPR formula
  - `fully recovered expected causal edges / total expected causal edges`
- the Weighted CPR formula
  - `recovered edge weight / total expected edge weight`
- the total expected edge weight
- the recovered edge weight
- the degraded edge weight
- the penalty terms that affect `reconstruction_confidence`
  - degradation penalty
  - ambiguity penalty
  - temporal penalty
- the final weighted score

Important: the weighted CPR value itself is only the scenario-weighted recoverability ratio. Temporal and degradation penalties affect `reconstruction_confidence`, not the raw `Weighted CPR` ratio.

#### Temporal synchronization vs causal timestamp confidence

The uncertainty panel now separates infrastructure clock state from artifact timestamp usability:

- `Clock synchronization`
- `Evidence timestamp availability`
- `Available timestamp resolvability`
- `Causal edge timestamp coverage`
- `Causal temporal ordering confidence`
- `Reason`

This is deliberate. A synchronized infrastructure does **not** guarantee that every forensic artifact contains usable timestamps for causal ordering.

The intended reading is:

- available timestamps may resolve cleanly
- some causal edges may still lack the timestamps required to order them
- therefore `Clock synchronization: synchronized` can coexist with `Causal temporal ordering confidence: limited`

#### Trigger path vs reconstructed attack path

The panel is now named:

- `Acquisition Trigger Path vs Reconstructed Attack Path`

When the preserved forensic case was acquired because of a host/FIM-oriented trigger but the causal model evaluates an OT Modbus path, the dashboard reports:

- `Status: trigger attack mismatch`
- `Scientific interpretation: valid case with acquisition-trigger limitation`

This is not presented as an error. It is presented as a controlled scientific limitation of the preserved case.

#### Executive wording refinements

The executive surface intentionally distinguishes three different scientific claims instead of collapsing them into a single confidence label:

- `Evidence processing coverage`
  - how completely the preserved evidence was processed across the expected multilayer pipeline
- `Forensic reconstruction confidence`
  - how strong the reconstruction remains at the multilayer forensic level
- `Causal interpretation confidence`
  - how strong the derived causal interpretation remains once temporal, integrity, trigger-path, and Modbus-specific limitations are applied

This is why the dashboard may report:

- `Evidence processing coverage: strong`
- `Forensic reconstruction confidence: partial`
- `Causal interpretation confidence: limited`

without contradiction.

#### Modbus specificity

The executive dashboard now ends the Modbus section with an explicit interpretation block:

- `Confirmed`
  - Modbus/TCP traffic targeting the PLC was observed.
- `Partially supported`
  - function code, register, value, and OT state relation.
- `Not fully claimable`
  - complete packet-level register and value causality.

This makes the limitation explicit: current preserved evidence confirms Modbus/TCP activity toward the PLC, but not complete packet-level register/value precision.

#### Executive conclusion compression

The executive conclusion no longer repeats every completed layer as a separate sentence.

Instead it groups supported claims into higher-level categories such as:

- Evidence preservation
- Forensic processing
- Cross-layer analysis
- Causal reconstruction

The detailed per-layer inventory remains available under the multilayer matrix and `View technical details`.

#### Backend contract

The dashboard uses these lightweight API surfaces:

- `GET /api/foc/evidence-lifecycle-dashboard?case_id=...`
- `POST /api/foc/evidence-lifecycle-dashboard/generate`
- `POST /api/foc/lifecycle/run-multilayer-analysis`
- `POST /api/foc/lifecycle/run-causal`
- `POST /api/foc/lifecycle/run-full`
- `POST /api/foc/lifecycle/generate-summary`
- `GET /api/foc/lifecycle/job-status?job_id=...`
- `GET /api/foc/reports/index?case_id=...`
- `GET /api/foc/reports/file?case_id=...&type=...`
- `POST /api/foc/time-sync/measure`
- `POST /api/foc/time-sync/fix`
- `POST /api/foc/evidence-support/run`
- `POST /api/foc/evidence-support/regenerate`
- `GET /api/foc/evidence-support/status?case_id=...`
- `GET /api/foc/evidence-support/report?case_id=...`
- `GET /api/foc/evidence-support/storyline?case_id=...`
- `GET /api/foc/evidence-support/claimability?case_id=...`
- `GET /api/foc/evidence-support/counter-evidence?case_id=...`
- `GET /api/foc/evidence-support/atoms?case_id=...&limit=...`

These routes are **adapters over existing services**, not a second forensic pipeline:

- multilayer execution reuses `run_analysis(...)`
- time synchronization reuses `run_time_sync(...)`
- causal reconstruction reuses `run_causal_reconstruction(...)`
- the executive dashboard only consolidates the outputs they already generate

#### Background job model

Heavy operations remain button-driven and run in the background.

The executive view never launches them automatically.

The new dashboard tracks:

- the native live subsystem states for:
  - multilayer analysis
  - time synchronization
  - causal reconstruction
- executive jobs for:
  - summary generation
  - full evidence lifecycle orchestration

The `Run Full Evidence Lifecycle` action is intentionally an orchestrator, not a new analytic engine. It executes, in order:

1. `Measure Clock Offset`
2. `Run Multilayer Forensic Analysis`
3. `Run Causal Reconstruction`
4. `Generate Executive Summary`

It reuses the existing runners and waits for their terminal states. It does not reimplement PCAP, memory, disk, OT, alert, or causal evaluators.

### FOC Experimentation module

The platform now also includes an additional, optional module for **campaign-oriented repetition and comparability management**:

```bash
app_core/infrastructure/foc_experimentation/
```

with dedicated API surface:

```bash
/api/foc/experimentation/...
```

and two new independent views:

```bash
app_core/static/foc_repetition_manager.html
app_core/static/foc_reconstruction_comparability.html
```

This module is intentionally **separate from**:

- `FOC Scientific Evidence Lifecycle Dashboard`
- `FOC Reconstruction`
- `Forensic Acquisition and Analysis Dashboard`

It does **not** replace them and it does **not** modify their internal execution logic.

Its responsibilities are different:

- **Executive Scientific Reconstruction Surface**
  - explains a single preserved execution
- **Forensic Repetition Manager**
  - manages repetition campaigns and registers execution workspaces
- **Forensic Reconstruction Comparability View**
  - compares already-generated executions

#### Architectural rules

The module is designed as:

- optional
- modular
- non-invasive
- reversible

If the experimentation blueprint is not registered or fails to load, the current platform views continue to operate normally.

The module never writes campaign artifacts into the original case directory structure except by **linking** an existing case in read-only mode. Campaign outputs remain isolated under:

```bash
app_core/infrastructure/forensics/evidence_store/repetition_campaigns/
```

with per-campaign structure such as:

```bash
app_core/infrastructure/forensics/evidence_store/repetition_campaigns/<CAMPAIGN_ID>/
```

and per-execution structure such as:

```bash
app_core/infrastructure/forensics/evidence_store/repetition_campaigns/<CAMPAIGN_ID>/<LEVEL>/<EXECUTION_ID>/
```

#### Campaign levels

The module distinguishes three methodological levels, each bound to an explicit `source_mode` that determines what input is mandatory and what artifact the execution produces:

- **Level A** — `source_mode: linked_existing_case`
  - reuses an already preserved forensic case in **read-only mode**
  - a `linked source case` is **mandatory**; the campaign cannot be created without it
  - does not modify the original case, does not execute a new attack, does not acquire new evidence
  - is intended to study **repeatability of the analytical and reconstruction layer** over the same preserved artifacts
- **Level B** — `source_mode: new_incident_execution`
  - a `linked source case` is **explicitly not required** and, in Guided Mode, is not even shown
  - requires an `active deployed scenario` (`scenario_id`), an `attack profile`, a `detection policy`, a `trigger policy`, and an `acquisition policy` — each kept as a distinct concept answering a different question: detection policy is *what source/alert is listened to*, trigger policy is *what condition fires acquisition*, acquisition policy is *what evidence gets preserved*
  - the `attack profile` is selected from the real MITRE ATT&CK-aligned catalog (`app_core/infrastructure/attack/catalog.py`), not a placeholder: the campaign builder shows the actual technique, MITRE ID, script, expected alerts, expected artifacts, rollback requirement, and DFIR escalation expectation for the selected `attack_id`
  - each execution creates a **new forensic case**; an existing case is never reused as evidence
  - is intended to study **stability of forensic reconstruction** under equivalent, documented experimental conditions
- **Level C** — `source_mode: full_redeployment`
  - same case-independence rule as Level B, plus a `deployment profile` and `scenario profile`
  - redeploys the scenario and creates a new forensic case per execution
  - is intended to study **platform and environment reproducibility**, not only forensic repeatability

`linked_existing_case` and `new_incident_execution`/`full_redeployment` are mutually exclusive by construction: `campaign_service.create_campaign()` rejects a Level A request without a case (`"A linked source case is required for Level A. Select a preserved case before creating the campaign."`) and rejects a Level B/C request without a resolvable `scenario_id` (`"Scenario ID is required for Level B. Select or auto-detect an active deployed scenario before starting execution."`), so the two source models cannot be silently mixed.

For Level B/C, an existing case can still be attached, but only as an **optional reference case** (Advanced Mode only): it copies defaults, thresholds, the expected causal model, or comparison-family settings, and is never treated as evidence and never required.

In the current implementation, the module fully supports **linked-case registration**, **scenario-scoped execution without a linked case**, and isolated execution-profile generation without touching the original evidence. This means the experimentation layer can already:

- register campaigns under either source model
- create independent execution workspaces
- seal ground-truth context
- build comparison profiles
- compute a design-only `comparison_family_id` and register it in the comparison registry
- compare executions, both numerically and by comparison family

**Execution-mode note.** `foc_experimentation` now exposes two distinct Level B paths:

- **Run Dry-Run Execution**
  - does **not** launch a real attack
  - does **not** wait for a real detection
  - does **not** create a heavy forensic case
  - does **not** perform real acquisition
  - instead, it reuses the existing backend scientific chain over a preserved reference case or the currently active preserved case:
    - `Bootstrap FOC`
    - `Regenerate Reconstruction`
    - `Run Causal Reconstruction`
    - `Run Full Evidence Lifecycle`
  - only after those backend functions complete does it register the new dry-run execution workspace and its lightweight profiles

- **Run Real Level B Execution**
  - arms DFIR auto-acquisition
  - launches the selected real attack
  - waits for a real matching detection
  - creates a new real forensic case
  - initializes the `volatile_first_with_continuous_network_context` acquisition profile
  - acquires memory first
  - imports overlapping network context segments from the rolling capture buffer without blocking RAM acquisition
  - acquires disk after memory has been sealed
  - runs the real lifecycle chain
  - registers the resulting execution and result card

#### Volatile-first acquisition and continuous network context

The real Level B path and the automatic DFIR orchestration now follow a volatile-first acquisition strategy:

`case creation -> acquisition profile initialization -> memory acquisition first -> network context import from rolling PCAPs -> disk acquisition -> analysis and reconstruction`

This strategy preserves the existing continuous capture design and does not replace it. The rolling PCAP store remains active and unchanged at:

- `app_core/infrastructure/ics_traffic/captures/full_scenario_captures`

The difference is that case-level network preservation no longer blocks RAM acquisition. While memory acquisition is running, the backend may inspect or index the rolling PCAP directory, but it does not wait for a full PCAP copy before preserving volatile memory.

After RAM acquisition completes, the platform imports only the PCAP segments that overlap the case window and writes:

- `CASE_ID/network/traffic_preserved/full_scenario_captures/`
- `CASE_ID/network/traffic_preserved/network_context_manifest.json`

It also updates:

- `CASE_ID/metadata/acquisition_profile.json`
- `CASE_ID/metadata/pipeline_events.jsonl`
- `CASE_ID/chain_of_custody.log`
- `CASE_ID/analysis/00_inventory/evidence_inventory.json`
- `CASE_ID/analysis/01_integrity_custody/integrity_custody_report.json`

The acquisition profile now records at least:

- `case_created_utc`
- `acquisition_started_utc`
- `memory_started_utc`
- `memory_completed_utc`
- `network_context_import_started_utc`
- `network_context_import_completed_utc`
- `disk_started_utc`
- `trigger_time_utc` when available
- `network_context_window`
- `source_capture_root`
- `selection_policy`
- `open_segment_policy`
- `memory_priority_policy`

Open PCAP segments are handled safely. If a segment overlaps the case window but is still being written, the importer records it as pending instead of treating it as final preserved evidence. This preserves correctness without losing the network context model.

The scientific rule remains the same across the experimentation module:

- full heavy PCAP histories are not copied blindly
- only case-relevant overlapping segments are preserved
- the preserved case stores lightweight manifests, hashes, timing, and linkage metadata
- later comparison and reconstruction rely on normalized case artifacts, not on whole-day raw PCAP duplication

**Honest scoping note.** Level C still does **not** execute a full real redeployment-and-attack pipeline inside `foc_experimentation` itself. Its current implementation preserves the redeployment model, scientific memory, blueprint validation, and controlled scenario-destruction logic, but it does not yet perform a full automatic "destroy → redeploy → attack → detect → acquire → analyze" orchestration equivalent to the Level B real-execution path.

#### Simple usage guide

Use the experimentation module in this order:

1. Open `Forensic Repetition Manager`
2. Select the methodological level:
   - `Level A` for reanalysis repeatability over an existing preserved case
   - `Level B` for controlled repeated incident execution
   - `Level C` for redeployment-aware reproducibility studies
3. Provide the source input required for the selected level:
   - `Level A`: select the preserved `linked source case` (mandatory)
   - `Level B` / `Level C`: provide or auto-detect the `scenario_id` of an active deployed scenario; a linked case is optional and only available in Advanced Mode as a `reference case`
4. If `Level B` or `Level C` is selected and the comparison registry already has a comparable result for that scenario, review the `Recommended Comparable Experiment` panel and either:
   - click `Use Recommended Attack For Comparability` to keep the same attack profile, trigger policy, acquisition profile, and `comparison_family_id`, or
   - click `Start New Comparison Family` to diverge intentionally and start a new family
5. Review the proposed defaults and the pre-flight checklist
6. Create the campaign
7. Start the campaign or run the next execution
   - for Level B, `Run Dry-Run Execution` now replays the scientific backend chain over a preserved case without launching a real incident
   - for a real incident in Level B, use `Run Real Level B Execution` instead
8. Wait until the execution generates its scientific profiles, especially:
   - `ground_truth_seal.json`
   - `baseline_noise_profile.json` when applicable
   - `forensic_comparison_profile.json`
   - `forensic_result_card.json`
9. After at least two executions have generated `forensic_comparison_profile.json`, open `Forensic Reconstruction Comparability View`

#### Campaign status semantics

The experimentation module now separates **technical completion**, **scientific limitation**, and **comparability readiness**.

This distinction is deliberate:

- **Scientific degradation is not a technical failure**
- a campaign may finish correctly and still remain scientifically limited
- a stable Level A reanalysis can preserve inherited case limitations without meaning the module failed

The campaign manifest therefore distinguishes:

- `status`
  - the aggregated campaign status shown in the UI
- `technical_outcome`
  - whether the executions completed technically
- `scientific_outcome`
  - whether usable outputs still carry scientific limitations
- `comparison_readiness`
  - whether enough execution profiles exist for comparability analysis
- `technical_failures`
  - real blocking failures such as missing required profiles, invalid JSON, unreadable artifacts, or failed stages
- `scientific_limitations`
  - non-blocking limitations such as degraded causal edges, trigger-path mismatch, partial integrity, limited temporal ordering confidence, or reconstructed ground-truth context

The intended aggregation rule is:

- if all executions are `completed`, the campaign is `completed`
- if executions are usable but one or more are `completed_with_degradation`, the campaign is `completed_with_degradation`
- if real technical failures exist, the campaign is `completed_with_failures`
- if outputs exist but the campaign is incomplete, the campaign is `partial`
- if not enough profiles exist for scientific comparison, the campaign may remain `insufficient_data`

In practical terms, a Level A campaign can now correctly read as:

```text
Campaign status: completed_with_degradation
Technical outcome: completed
Scientific outcome: completed_with_degradation
Comparison readiness: ready
```

This means:

- the campaign is not broken
- the executions were created
- usable `forensic_comparison_profile.json` artifacts exist
- the comparison can proceed
- the degradation is inherited from the base case or from preserved scientific limitations, not from orchestration failure

#### What to do next

- If you only have one execution:
  - inspect the execution workspace and verify that the expected scientific profiles were created correctly
- If you have two or more executions:
  - open the comparability view and evaluate whether the reconstructions are:
    - `Comparable`
    - `Comparable With Degradation`
    - `Not Comparable`
    - `Insufficient Data`
- If the campaign is `completed_with_degradation`:
  - treat this as usable output with scientific limitations, not as a broken run
  - inspect `scientific_limitations` before concluding that the experimentation pipeline failed
- If the campaign is `completed_with_failures`:
  - inspect `technical_failures` first
  - repair missing profiles, failed stages, unreadable artifacts, or invalid manifests before comparing executions
- If the campaign or execution is degraded:
  - inspect temporal confidence, trigger alignment, missing profiles, and execution warnings before drawing conclusions
- If `scenario_id` is missing:
  - `Level A` can still proceed, but the comparison metadata will be weaker
  - `Level B` and `Level C` should be completed with a valid scenario context before execution

The intended role separation remains:

- `FOC Scientific Evidence Lifecycle Dashboard`
  - explains one execution
- `Forensic Repetition Manager`
  - creates campaigns and generates executions
- `Forensic Reconstruction Comparability View`
  - compares already-generated executions

while keeping the original case read-only.

#### Ground-truth sealing

The experimentation module uses **cryptographic sealing**, not encryption, for the experimental ground truth.

Each execution can store:

- `ground_truth.json`
- `ground_truth_seal.json`

The seal records:

- `ground_truth_sha256`
- `scenario_profile_sha256`
- `attack_profile_sha256`
- `attack_script_sha256`
- creation time
- attack start time
- whether the seal is valid with respect to the attack start boundary

The purpose is methodological:

- to prove what attack model and scenario profile the execution claims to evaluate
- to record whether that profile was sealed before the attack timing boundary
- to distinguish valid pre-attack sealing from post-hoc linked-case reconstruction

#### Baseline noise and comparability

For Level B and Level C interpretations, the module also defines a `baseline_noise_profile.json` and a threshold-based comparability rule.

The initial configurable baseline threshold is:

```text
baseline_noise_threshold = 0.15
```

and the relative-difference model is:

```text
relative_difference = abs(value_i - value_j) / max(value_i, value_j, epsilon)
```

Comparability is not subjective. It is computed with explicit thresholds over:

- `CPR`
- `Weighted CPR`
- hypothesis-support shift
- degradation flags
- temporal confidence
- trigger-path alignment
- integrity completeness

This produces one of four states:

- `Comparable`
- `Comparable With Degradation`
- `Not Comparable`
- `Insufficient Data`

This numeric `status` answers **"did the recovered metrics stay within margin?"**. It is deliberately kept independent from a second, orthogonal axis, `comparison_type`, which answers a different question: **"are these executions even the same experiment by design?"** See *Comparison Registry and Family-Based Grouping* below.

#### Methodological basis

The experimentation module includes a dedicated methodological reference basis rather than decorative bibliography.

It records why specific comparison and repeatability rules are justified, including references such as:

- NIST SP 800-86
- NIST SP 800-61 Rev. 3
- NIST SP 800-82 Rev. 3
- NIST SP 800-92
- NIST IR 8387
- SWGDE Best Practices for Digital Evidence Collection
- NIST CFTT
- ISO 5725-1
- ISO 5725-2
- JCGM VIM repeatability / reproducibility / uncertainty
- ACM Artifact Review and Badging
- MITRE ATT&CK
- Lakens equivalence-testing methodology

The purpose is not citation for its own sake. The purpose is to justify:

- why executions are separated from comparisons
- why read-only linkage to preserved cases matters
- why threshold-based comparability is used instead of vague similarity claims
- why uncertainty and degradation remain explicit

#### Scientific memory, lightweight result profiles, and comparison families (2026-06-25)

The experimentation module now treats **scientific memory** as a first-class artifact. The platform does not compare full cases and does not duplicate heavy evidence by default. Instead, it preserves a compact, auditable memory of scenarios, cases, executions, analysis outputs, and comparison-ready results under:

```bash
app_core/infrastructure/forensics/evidence_store/repetition_campaigns/scientific_memory/
```

with independent registries for:

- `scenario_registry/`
- `case_registry/`
- `execution_registry/`
- `result_registry/`
- `analysis_registry/`
- `retention_registry/`
- `blueprints/`

This is the operational meaning of the rule:

```text
We do not compare full cases. We compare lightweight forensic result profiles generated under comparable experimental conditions.
```

##### Why full cases are not compared

Two scientifically equivalent executions are not expected to be bit-identical. Memory dumps, disk images, PCAPs, timestamps, PIDs, counters, transient buffers, and background traffic naturally drift between executions. Reproducibility is therefore measured as:

- semantic equivalence
- causal equivalence
- uncertainty-class stability
- hypothesis-support stability
- conclusion-class stability

and **not** as byte-for-byte equality of:

- memory dumps
- disk images
- full PCAP payloads
- the entire `evidence_store`

##### What is stored instead of heavy evidence

Each execution can preserve lightweight comparison artifacts such as:

- `scenario_profile.json`
- `attack_profile.json`
- `ground_truth.json`
- `ground_truth_seal.json`
- `baseline_noise_profile.json`
- `detection_trigger_profile.json`
- `acquisition_profile.json`
- `preservation_profile.json`
- `forensic_comparison_profile.json`
- `forensic_result_card.json`
- `analysis_repeatability_profile.json` for Level A

The original heavy artifacts remain in the original forensic case directory when they exist. The experimentation module stores:

- normalized summaries
- hashes
- references
- metrics
- result cards
- scenario blueprints
- retention manifests

instead of duplicating dumps, disk images, or PCAPs inside `repetition_campaigns/`.

##### Scientific memory cards and registries

The module now persists four lightweight card families:

- `scenario_result_card.json`
  - stable scenario identity, topology fingerprint, tool/configuration summaries, supported attacks, blueprint path, and redeployability metadata
- `case_result_card.json`
  - case identity, scenario linkage, acquisition/preservation summary, manifest/digest hashes, and retention policy
- `analysis_result_card.json`
  - analysis coverage and high-level analysis/causal/uncertainty state
- `forensic_result_card.json`
  - the comparison-ready result profile for one execution

The global lightweight historical index is:

```bash
app_core/infrastructure/forensics/evidence_store/repetition_campaigns/scientific_memory/result_registry/comparison_result_registry.json
```

Each entry is a `forensic_result_card` and includes, among others:

- `result_card_id`
- `case_id`
- `execution_id`
- `campaign_id`
- `evaluation_level`
- `source_type`
- `scenario_id`
- `scenario_fingerprint`
- `topology_fingerprint`
- `attack_profile_id`
- `attack_script_sha256`
- `attack_parameters_hash`
- `trigger_policy`
- `acquisition_profile_id`
- `CPR`
- `Weighted_CPR`
- `uncertainty_class`
- `hypothesis_support`
- `final_conclusion_class`
- `scientific_limitations`
- `comparison_family_id`
- `comparison_profile_path`
- `retention_policy`
- `heavy_artifacts_retained`
- `heavy_artifacts_location`

##### Scenario registry and Level C blueprint memory

The module also preserves lightweight scenario memory even if the active scenario is later destroyed. It writes:

- `scenario_registry/scenario_registry.json`
- one `scenario_result_card.json` per `scenario_fingerprint`
- one `scenario_reconstruction_blueprint.json` per comparable scenario family

The blueprint keeps only what is needed to reconstruct an equivalent scenario for Level C:

- topology definition
- IT and OT node-role structure
- network definitions and high-level configuration hashes
- PLC / SCADA/HMI references when available
- tool-installation, IDS, SIEM, trigger, acquisition, analysis, and FOC profile identifiers
- expected alerts
- expected artifacts
- expected causal model references

It does **not** preserve heavy evidence.

##### `comparison_family_id` and why it must not depend on results

`comparison_family_id` identifies the **experimental design family**, not the outcome. Its purpose is to answer:

```text
Are these executions the same experiment by design?
```

It is therefore computed only from design-time fields such as:

- `scenario_fingerprint`
- `topology_fingerprint`
- `attack_profile_id`
- `attack_script_sha256`
- `attack_parameters_hash`
- `expected_causal_edges`
- `trigger_policy_id`
- `acquisition_profile_id`
- `analysis_profile_id`
- `foc_profile_id`

It explicitly does **not** depend on:

- `CPR`
- `Weighted CPR`
- `recovered_edges`
- `degraded_edges`
- `missing_edges`
- `uncertainty result`
- `hypothesis_support`
- `final_conclusion_class`
- `comparability status`

This rule is methodologically mandatory. If `comparison_family_id` changed whenever a result degraded, then variability in the experiment would destroy the family identity that is needed to study variability in the first place.

##### Level A, Level B, and Level C under the lightweight-profile model

- **Level A**
  - reuses the same preserved case in read-only mode
  - does not create a new incident or a new forensic case
  - regenerates only post-preservation products
  - stores `analysis_repeatability_profile.json` plus a `forensic_result_card.json`
  - answers: *If the same preserved evidence is analyzed again, do we obtain equivalent forensic reconstruction results?*
- **Level B**
  - uses the same deployed scenario
  - is intended to create a **new forensic case per execution**
  - the current first-phase implementation can already preserve the experimental design, generate the planned case identity, and register lightweight result profiles; the full automated attack→detection→acquisition→analysis orchestration is still declared as future work and is never faked by the UI
  - answers: *If the same incident is executed again in the same deployed scenario, do we recover comparable forensic reconstructions?*
- **Level C**
  - preserves a scenario reconstruction blueprint
  - is intended to redeploy the scenario and then behave like Level B
  - uses `scenario_fingerprint` and `topology_fingerprint` to detect redeployment equivalence or scenario drift
  - answers: *If the scenario is redeployed from its saved specification, can the platform recover comparable forensic reconstructions again?*

This is why the module uses the formulation:

```text
Level B creates new forensic cases in the same deployed scenario.
Level C recreates the scenario and then creates new forensic cases.
```

##### Recommended Comparable Experiment

When the operator selects Level B or Level C, the module can query:

- `comparison_result_registry.json`
- `scenario_registry.json`
- `case_registry.json`

to recommend the attack/configuration that preserves direct comparability with previous results.

The panel `Recommended Comparable Experiment` tells the user, in plain language:

- which previous result card is being matched
- which scenario fingerprint and comparison family it belongs to
- which attack profile and MITRE technique should be reused
- which trigger policy and acquisition profile should be reused
- why changing these choices creates a new comparison family

Two explicit paths exist:

- `Use Recommended Attack For Comparability`
  - keeps the same experimental family when possible
- `Start New Comparison Family`
  - allows an intentional deviation and preserves it as a new family for future comparisons

##### Direct comparison, exploratory comparison, and scenario drift

The comparability layer now distinguishes:

- **Direct family comparison**
  - the executions belong to the same `comparison_family_id`
  - direct forensic comparability is scientifically valid
- **Exploratory comparison only**
  - the executions come from different comparison families
  - they can be inspected together, but should not be presented as direct reproducibility evidence
- **Platform-level comparison with scenario drift**
  - Level C redeployment changed the scenario or topology fingerprint enough that the run must be interpreted as drift-aware platform reproducibility, not direct family equivalence

This distinction is separate from the numeric comparability status:

- `Comparable`
- `Comparable With Degradation`
- `Not Comparable`
- `Insufficient Data`

The first answers *"same experiment by design?"* and the second answers *"did the result stay within the allowed margins?"*.

##### Lightweight retention and heavy-evidence cleanup

The module now supports retention preparation around the rule:

```text
The platform must preserve scientific memory, not duplicate heavy evidence.
```

Before deleting or archiving heavy generated-case artifacts, the module verifies that the execution already preserves:

- `forensic_result_card.json`
- `forensic_comparison_profile.json`
- `case_result_card.json`
- `execution_manifest.json`
- preservation summary
- chain-of-custody summary
- analysis summary
- causal metrics
- uncertainty summary
- hypothesis-support summary
- final conclusion class
- original manifest/digest hashes when available

and can generate `retention_manifest.json` plus a retention-registry entry. This records:

- what was retained
- what was archived or deleted
- who performed the action
- why it was done
- where the original heavy case lived
- whether future comparisons remain possible after cleanup

The retained comparison logic therefore survives even if the heavy case is later archived or removed, because future comparability uses lightweight result profiles and scientific memory registries rather than duplicated dumps or PCAP equality.

The UI now exposes this policy directly through:

- `Delete Generated Case Artifacts`
  - visible only for Level B / Level C executions that actually generated a heavy case
  - requires typing exactly `OK`
  - preserves comparison memory and only removes or archives heavy runtime artifacts

##### Level C scenario destruction

Because the platform may need to keep only one active scenario at a time, the module now also exposes a controlled Level C action:

- `Destroy Full Scenario For Level C Redeployment`
  - visible only in Level C context
  - requires typing exactly `OK`
  - validates that lightweight scenario memory already exists before destruction
  - preserves:
    - `scenario_registry.json`
    - `scenario_result_card.json`
    - `scenario_reconstruction_blueprint.json`
    - result cards
    - comparison profiles
    - campaign and execution manifests
  - generates `scenario_destruction_manifest.json`

This follows the rule:

```text
Destroying a scenario must not delete the scientific memory needed to compare scenarios, cases, executions, or results.
```

##### Passive scientific-memory synchronization

To avoid invasive changes in the original dashboards, `foc_experimentation` now performs **passive synchronization** when its own API surface is used:

- active scenario files are scanned to refresh lightweight scenario cards and scenario reconstruction blueprints
- existing preserved cases are scanned to refresh `case_registry`
- campaign/result generation refreshes scenario, case, execution, analysis, and result registries

This keeps the module modular while still allowing historical scientific memory to outlive the active scenario or the heavy case workspace.

##### Additional experimentation endpoints

In addition to the earlier campaign and comparison endpoints, the module now exposes:

- `POST /api/foc/experimentation/scientific-memory/sync`
- `GET /api/foc/experimentation/scientific-memory/scenarios`
- `GET /api/foc/experimentation/scientific-memory/cases`
- `GET /api/foc/experimentation/scientific-memory/results`
- `POST /api/foc/experimentation/retention/prepare`
- `POST /api/foc/experimentation/case-cleanup/validate`
- `POST /api/foc/experimentation/case-cleanup/delete`
- `POST /api/foc/experimentation/scenario-destruction/validate`
- `POST /api/foc/experimentation/scenario-destruction/destroy`

These endpoints keep the experimentation layer self-contained. They do not modify the original FOC, Forensic Lab, Attack Lab, or Node Health execution logic.

#### Scientific interpretation rules enforced by the executive summary

The executive summary does not collapse everything into a single "confidence" label.

It keeps separate:

- `evidence_analysis_confidence`
- `forensic_reconstruction_confidence`
- `causal_interpretation_confidence`

It also keeps the trigger path and the causal path distinct. When the trigger that selected the forensic case is host/FIM-oriented but the causal scenario under evaluation is OT/Modbus-oriented, the dashboard states that mismatch explicitly rather than hiding it.

Likewise, a completed phase is not treated as a useful phase only because a file exists. The dashboard inherits the multilayer usefulness semantics already normalized by `analysis/visual/analysis_visual_summary.json`.

#### Technical access without initial payload explosion

The dashboard is designed to stay lightweight:

- the initial load consumes the executive summary and live status only
- no giant alert array is loaded initially
- no full markdown report is loaded initially
- no full causal graph is loaded initially
- no raw case file is parsed in the browser initially

When an analyst opens a report from `Reports and Artifacts`, the content is fetched on demand from `GET /api/foc/reports/file`.

This keeps the page usable as an executive decision surface while preserving drill-down access to the real derived or preserved artifacts.

#### Implementación real del orquestador Level B, corrección de adquisición de disco y métricas de paper Level C (2026-06-27 / 2026-07-06)

Esta iteración cierra tres brechas que bloqueaban la ejecución real controlada de Level B, la adquisición de disco en el flujo DFIR AUTO, y la generación automática de las métricas de paper del workflow completo.

**1. Orquestador de ejecución real Level B (`level_b_orchestrator.py`).**
El botón `Run Next Execution` del Forensic Repetition Manager ejecutaba únicamente un scaffold de workspace (planificación sin ejecución real): creaba `execution_manifest.json`, `execution_plan.json`, `ground_truth_seal.json` y `baseline_noise_profile.json`, pero nunca armaba DFIR auto-acquisition, lanzaba el ataque seleccionado, esperaba una detección real, creaba un caso forense nuevo ni adquiría evidencia. El módulo `level_b_orchestrator.py` implementa el flujo completo de 23 fases:

```text
execution_workspace_created → scenario_validated → attack_profile_validated →
dfir_auto_armed → attack_launched → attack_completed → detection_waiting →
detection_observed / failed_detection → trigger_selected → forensic_case_created →
memory_acquisition_started/completed → network_context_import_started/completed →
disk_acquisition_started/completed → preservation_completed →
multilayer_analysis_started/completed → foc_reconstruction_completed →
causal_reconstruction_completed → executive_summary_generated →
comparison_profile_generated → forensic_result_card_registered
```

Cada fase se persiste mediante `job_runner.append_phase` para que el panel de estado del Repetition Manager la refleje en tiempo real. Los pilares reutilizados en lugar de reimplementados:

- **Detección de alertas**: `run_monitor_session()` extraída de `live_wazuh_stream()` en `monitor/alerts_logger.py` — misma lógica de parseo `NICS_ALERT_JSON`, mismo `AlertsLogger`, sin dependencia Flask. Timeout configurable; la fase marca `failed_detection` si no llega ninguna alerta que cumpla la política, **nunca** marca la ejecución como exitosa sin detección real.
- **Adquisición de memoria**: wrapper puro `acquire_memory()` extraído de `api_forensics_acquire_memory()` en `forensics_api.py`, reutilizando `_run_script(acquire_memory_lime_ssh.sh, ...)` con el mismo fallback de usuario SSH.
- **Adquisición de disco**: wrapper puro `acquire_disk()` extraído de `api_forensics_acquire_disk()`, best-effort no fatal (degraded si Kolla/libvirt no alcanzable), consistent con el framing "disk, si aplica" del spec.
- **Importación de red**: `capture_packets_fixed_duration` de `ics_traffic/traffic_api.py`, solo el segmento relevante del buffer continuo.
- **Cadena de análisis completa**: `start_full_lifecycle_job(case_id, force_analysis=True)` de `evidence_lifecycle_dashboard.py` — encadena time-sync, multilayer analysis, causal reconstruction y executive summary en una sola llamada ya existente.
- **Perfil de comparación y registro de result card**: `build_execution_profiles()` y `comparison_registry` ya implementados en iteraciones anteriores, ahora llamados sobre el `case_bundle` real.
- `attach_real_case_to_execution()` añadida a `execution_service.py` — actualiza el workspace de ejecución ya creado con el caso real, corrige los `stage_statuses` de `completed_with_degradation` a `completed` para las fases genuinamente ejecutadas (`attack_executed`, `detection_observed`, `acquisition_executed`, etc.).

**Seguridad por defecto confirmada:** dry-run es el modo predeterminado; la ejecución real requiere un botón explícito `Run Real Level B Execution` + confirmación escrita `OK`, idéntica al patrón ya usado por `delete_generated_case_artifacts` y `destroy_full_scenario`. `Start Selected Campaign` (loop multi-ejecución) permanece en modo dry-run exclusivamente para Level B — no encadena ataques reales de forma desatendida.

**2. Corrección de adquisición de disco DFIR AUTO (`acquire_disk_kolla_libvirt.sh`).**
La adquisición de disco fallaba sistemáticamente con `sudo_noninteractive_unavailable` aunque la regla sudoers NOPASSWD estuviera correctamente instalada. El problema era una cadena de tres capas:

- `forensics_api.py` probaba primero `sudo -n true` (no cubierto por la regla Cmnd_Alias) antes de probar el script específico — orden invertido.
- El script `acquire_disk_kolla_libvirt.sh` usaba `sudo -n -E true` como probe interno antes de re-ejecutarse con privilegio root — mismo problema más el flag `-E` (preserve-env) no permitido sin `SETENV` en sudoers.
- El probe devolvía `exit=1` por args incorrectos (`__nics_probe__`) y el operador lógico `||` lo interpretaba como fallo de sudo.

Las tres correcciones aplicadas:

- `forensics_api.py`: el prerequisite check ahora prueba primero `sudo -n /bin/bash <script> __nics_probe__`; solo si ese falla cae al `sudo -n true` como fallback de credencial cacheada.
- `acquire_disk_kolla_libvirt.sh`: `__nics_probe__` como primer argumento hace `exit 0` inmediatamente antes de cualquier lógica de adquisición; el re-exec usa `sudo -n /bin/bash "$0"` en lugar de `sudo -n -E "$0"`.
- `start_dashboard.sh` sección `[2.8/6]`: instala automáticamente la regla NOPASSWD en `/etc/sudoers.d/nicscyberlab-acquire-disk` la primera vez, pidiendo contraseña solo esa vez; idempotente — si ya funciona, salta sin hacer nada.

La regla correcta en `/etc/sudoers.d/nicscyberlab-acquire-disk`:

```
Defaults!NICS_DFIR_DISK_HELPER !requiretty
Cmnd_Alias NICS_DFIR_DISK_HELPER = /bin/bash <repo>/app_core/infrastructure/forensics/scripts/acquire_disk_kolla_libvirt.sh *
younes ALL=(root) NOPASSWD: NICS_DFIR_DISK_HELPER
```

**3. Exportador de métricas de paper Level C (`tools/forge_vi_paper_metrics_exporter.py`).**
El script `tools/forge_vi_paper_metrics_exporter.py` lee únicamente artefactos verificados en disco (sin valores manuales ni inferidos sin fuente declarada) y produce siete ficheros en `paper_exports/FORGE-VI/`:

```text
FORGE-VI_LevelC_Workflow_Checks.csv        — check booleano por run y agregado N/N
FORGE-VI_LevelC_Workflow_Checks.json       — ídem con source_file y source_key por campo
FORGE-VI_LevelC_Operational_Metrics.csv   — latencias y tamaños (media ± SD)
FORGE-VI_LevelC_Reconstruction_Metrics.csv — edges, CPR, wCPR por run
FORGE-VI_LevelC_Comparison_Metrics.csv    — estabilidad FSR inter-run
FORGE-VI_LevelC_Paper_Tables.tex          — tabla LaTeX lista para el paper
FORGE-VI_LevelC_Field_Source_Map.csv      — source_file + source_key por campo
```

Los campos no disponibles en los artefactos actuales se marcan `missing_from_existing_reports` — nunca se rellenan con valores inventados. Por cada caso se escribe además un stub `metadata/workflow_phase_summary.json` con la lista de campos pendientes y el fichero destino sugerido para que el siguiente run de adquisición/deployment los persista y el exportador los recoja automáticamente.

El exportador está accesible también desde el botón `Generate Level C Workflow Metrics` en `foc_paper_evidence.html` (sección FORGE-VI Audit), mediante el endpoint `POST /api/foc/paper-evidence/level-c/workflow-metrics/run`. El endpoint `GET /api/foc/paper-evidence/level-c/workflow-metrics/files` devuelve la lista de ficheros ya generados. La página carga el inventario de ficheros en el arranque sin requerir acción del operador.

**Estado verificado de los 6 runs aceptados (N_C = 6):**

| Fase | Campo | Resultado |
|------|-------|-----------|
| Execute | attack_profile_executed, ground_truth | 6/6 |
| Execute | attack_duration | 21 ± 3 s |
| Detect | alert_observed, trigger_bound | 6/6 |
| Detect | attack-to-alert latency | 21 ± 25 s |
| Acquire | memory first, acquisition_order_valid | 6/6 |
| Acquire | alert-to-memory latency | 23 ± 11 s |
| Acquire | alert-to-sealed latency | 2096 ± 301 s |
| Preserve | required artifacts | 6/6 (memory 4 GiB, disk 37 GiB, pcap 2.9 GiB) |
| Validate | time_reference_coherent | 6/6 |
| Analyze | useful layers | 12/14 (memory=partial en todos, expected) |
| Reconstruct | CPR (solo diagnóstico) | 0.500, 4R/2D/2M/0A estable |
| Compare | FSR invariants, CPR, edge pattern | 6/6 estable |

**Campos faltantes — pendientes de instrumentación del pipeline:**

```text
teardown_completed, redeploy_completed, same_topology_instantiated,
effective_inventory_recorded, deployment_time_s, redeployment_time_s,
validation_gate_passed, segmentation_verified, sensor_liveness_verified,
plc_scada_reachable, validation_time_s, trigger_inside_attack_window,
comparison_family_match
```

Estos campos requieren que el pipeline de deployment/validation escriba datos en `metadata/workflow_phase_summary.json` durante el run. Los stubs por caso ya están creados con la lista exacta de campos pendientes y el fichero destino de cada uno.

**4. Corrección del job-status en entorno multi-worker (`job_runner.py`).**
`get_job(job_id)` solo buscaba en el dict `_JOBS` en memoria — process-local en Gunicorn `-w 4`. Un job iniciado por el worker A era invisible para los workers B, C, D, dando `job_not_found` en ~3/4 de los polls. La función ahora cae al fichero en disco (`CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json")`) cuando no encuentra el job en memoria, exactamente como `evidence_lifecycle_dashboard.get_lifecycle_job()` ya hacía. Los jobs encontrados en disco se cachean en `_JOBS` para que polls sucesivos al mismo worker no relean el disco.

**5. Corrección de resolución de caso en `level_a_scientific_report_service.py`.**
`_run_level_a_report_job` resolvía el directorio del caso de referencia únicamente desde `config.base_case_path` / `config.run_case_path`, que son `null` en la mayoría de campañas creadas por ID desde la UI. La corrección añade un fallback a `resolve_case_source(case_id=source_case_id)` de `profile_builder.py` cuando el campo de ruta está vacío, el mismo helper que `load_case_bundle` ya usaba. El botón `Generate Level A Scientific Report` en `foc_paper_evidence.html` dejaba de fallar con `reference_case_path_not_found` a partir de esta corrección.

**Verificación aplicada:** `python -m py_compile` sobre todos los módulos Python tocados; `bash -n` sobre `start_dashboard.sh`; prueba live del endpoint Level C mediante `curl POST` contra gunicorn en ejecución; prueba del probe de disco (`sudo -n /bin/bash <script> __nics_probe__` → exit=0); comprobación de correspondencia HTML id ↔ JS `byId` para los cuatro nuevos elementos del botón Level C.

**Lo que no cambia esta iteración:** el motor de adquisición DFIR AUTO preexistente, el flujo de análisis multicapa, el motor de reconstrucción causal, los pesos de relación, el esquema de `forensic_result_card.json`, el `comparison_family_id` hash, ni ninguna lógica de Level A o Level C existente.

#### Correcciones de claridad y consistencia científica en la UI de Level B (2026-06-25)

Tras la corrección del modelo de fuente del 2026-06-24, una revisión funcional de la UI resultante (`foc_repetition_manager.html`/`.js`) encontró que, aunque el backend ya no exigía un caso enlazado para Level B, varios elementos visuales seguían sugiriendo lo contrario o mezclaban conceptos científicos distintos bajo el mismo valor. Esta iteración corrige doce puntos concretos, todos en la capa de presentación y de metadatos de diseño — **ningún cambio toca el motor de adquisición, análisis o reconstrucción causal**.

**Bug real encontrado y corregido: `trigger_policy_id` y `acquisition_profile_id` se mostraban con el mismo valor.** La causa no era conceptual sino un defecto concreto introducido el 2026-06-24: el *fallback* de visualización en `renderSourceSummary()` usaba literalmente la misma cadena (`"default_kolla_lime_tshark_v1"`) para ambos campos cuando `state.proposal` todavía no los exponía (`build_campaign_proposal()` nunca los devolvía). La corrección tiene dos partes: (1) `build_campaign_proposal()` ahora devuelve los cinco identificadores fijos reales (`detection_policy_id`, `trigger_policy_id`, `acquisition_profile_id`, `analysis_profile_id`, `foc_profile_id`), de modo que la UI muestra el valor configurado real en vez de adivinar un *fallback*; (2) se introduce `detection_policy_id` (`"wazuh_suricata_alert_ingestion_v1"`) como un **cuarto concepto de diseño**, distinto de `trigger_policy_id` (`"highest_severity_alert_v1"`) y de `acquisition_profile_id` (`"default_kolla_lime_tshark_v1"`), porque responden preguntas distintas: qué fuente de detección se escucha, qué condición dispara la adquisición, y qué evidencia se preserva tras el disparo. `detection_policy_id` se añade también como entrada del hash de `comparison_family_id` (`compute_comparison_family_id` pasa de 9 a 10 campos posicionales) y al esquema de `forensic_result_card.json`, manteniendo la misma garantía de que solo participan campos de diseño previos a la ejecución.

**El selector de `attack profile` deja de ser un texto genérico y pasa a ser un dato real.** Antes, Level B mostraba literalmente `Attack profile: Selected automatically per scenario`, sin indicar qué se iba a ejecutar. La corrección añade un nuevo endpoint de solo lectura, `GET /api/foc/experimentation/attack-catalog`, que reexpone el catálogo ATT&CK ya existente y validado (`app_core/infrastructure/attack/catalog.py`, el mismo que usa el Tactical Cyber Operations Dashboard) — no se inventan datos nuevos. El Step 2 del Repetition Manager incorpora un selector real (`attack-profile-select`) que, al elegir un `attack_id`, despliega su `display_name`, `mitre_id`/`mitre_technique`, `tactic`, `script`, `severity`, `detection_engine`, `expected_alerts`, `expected_artifacts`, `rollback_required` y `dfir_escalation` — exactamente el conjunto de campos exigido. El `attack_id` seleccionado se persiste en `campaign_config.json` reemplazando al campo `attack_profile_override` (de nombre más ambiguo y nunca antes resuelto contra un catálogo real).

**`Selected case path` ya no aparece como si fuera evidencia para Level B/C.** Antes, si el operador seleccionaba un caso de referencia opcional, la UI mostraba la misma línea `Selected case path: ...` usada por Level A, lo cual sugería reutilización como evidencia. Ahora, para Level B/C, la misma información se presenta bajo la etiqueta `Scenario context source` junto con el texto explícito: *"Scenario context was inferred from a previous case, but this case will not be reused as evidence. Level B will create a new forensic case for each execution."* Si no hay caso de referencia, la línea se omite por completo en vez de mostrar un *placeholder* confuso.

**El texto de ayuda de `Scenario ID` deja de heredar la redacción de Level A.** El texto genérico ("se extrae del caso enlazado o de artefactos FOC preservados") solo es correcto para Level A. Para Level B/C, el texto ahora es explícito sobre por qué el escenario es obligatorio: *"Scenario ID identifies the active deployed scenario where the new incident execution will run. Level B requires a deployed scenario because each execution launches a new attack, waits for detection, creates a new forensic case, preserves evidence, and generates a new comparison profile."*

**El botón `Use Recommended Attack For Comparability` ya no aparece habilitado sin recomendación.** Antes, cuando el registro de comparación no tenía resultados previos para el escenario, el panel mostraba el mensaje de "sin resultados" pero dejaba ambos botones activos, lo cual sugería que aceptar la recomendación era una opción válida incluso sin datos que recomendar. Ahora el botón se deshabilita explícitamente (`disabled`, con razón visible: *"No previous comparable result exists for this scenario family."*) y el mensaje principal se reescribe a: *"No previous comparable result was found. You can start a new comparison family. Future executions using the same scenario, attack profile, trigger policy, acquisition policy, and FOC profile will be directly comparable with this one."*

**`Register Existing Case As Result Card` se separa del flujo principal de Level B.** Esta acción es válida y útil, pero al aparecer justo bajo el formulario de creación de campaña sugería —de nuevo— que un caso anterior era parte del flujo normal de Level B. Se traslada a una sección propia, retitulada `Comparison Registry Tools` / `Historical Result Registration`, colapsada por defecto dentro de un `<details>`, con el texto: *"Use this tool only to register previous preserved cases as lightweight result cards. This does not link the case as evidence for Level B."*

**Nuevas piezas explicativas, añadidas sin tocar lógica de ejecución:**
- antes de `Create Campaign`, Level B/C muestra ahora: *"This Level B campaign will not reuse an old forensic case. It will create a new forensic case for each execution after attack detection and forensic acquisition."*
- en `Review execution plan`, Level B/C muestra el flujo operacional completo de 15 pasos (16 para Level C, que añade el redeployment como primer paso): validar escenario desplegado, capturar ruido base, sellar el ground truth, lanzar el ataque, esperar detección, evaluar severidad, seleccionar trigger, crear caso forense, adquirir, preservar, analizar multicapa, reconstrucción causal y FOC, generar resumen ejecutivo, generar el perfil de comparación, y registrar el `forensic_result_card`.

**Corrección de un defecto de UI sin relación con Level B, encontrado durante la misma revisión: los botones de campaña no se deshabilitaban sin campaña seleccionada.** `applyCampaignActionState()` solo deshabilitaba `Pause`/`Stop` en ausencia de campaña; `Start Campaign` y `Run Next Execution` permanecían visualmente activos (aunque sus *handlers* ya fallaban en silencio por una guarda interna), y la ruta de retorno temprano de `renderSelectedCampaign()` cuando no hay campaña seleccionada nunca llamaba a `applyCampaignActionState()`, dejando el estado de los botones congelado en el de la última campaña vista. La corrección llama explícitamente a `applyCampaignActionState(null, null)` en esa ruta, deshabilita los cuatro botones, y muestra: *"No campaign selected. Create or select a campaign before running executions."* Al crear una campaña, además, se confirma ahora explícitamente con: *"Campaign created successfully. Next action: Run first Level B execution."*

**Verificación realizada:** `python -m py_compile` sobre los seis módulos Python tocados; verificación de balance de llaves/paréntesis del JavaScript modificado; correspondencia 1:1 entre los `id` de DOM referenciados desde JS y los declarados en HTML; arranque real del servidor de desarrollo con llamadas `curl` contra `GET /api/foc/experimentation/attack-catalog`, `POST /api/foc/experimentation/campaigns/proposal` (confirmando que los cinco identificadores fijos ya no colisionan) y `POST /api/foc/experimentation/campaigns/create` con un `attack_id` real del catálogo, seguido de limpieza de los artefactos de prueba generados.

#### Comparison Registry, agrupación por familia de comparación, y corrección del modelo de fuente en Level B/C (2026-06-24)

Esta iteración cierra dos defectos concretos del módulo `foc_experimentation`: (1) la ausencia de una lógica de agrupación científica entre ejecuciones, y (2) una incoherencia de validación en el frontend que presentaba `linked source case` como obligatorio para Level B, contradiciendo el modelo de fuente que el backend ya respetaba.

**Problema metodológico de fondo.** Antes de este cambio, dos ejecuciones podían pertenecer al mismo experimento por diseño (mismo escenario, mismo perfil de ataque, misma política de disparo, misma política de adquisición) y aun así no existir ningún mecanismo que las agrupara como tales. Si esa agrupación se hubiera calculado a partir de los resultados (`CPR`, `Weighted CPR`, `recovered_edges`, `hypothesis_support`, `final_conclusion`), dos ejecuciones científicamente comparables habrían podido terminar en familias distintas solo porque una salió degradada o tuvo menor recuperación causal. Esto habría sido un error metodológico real, no cosmético.

**Nuevo módulo: `app_core/infrastructure/foc_experimentation/comparison_registry.py`.** El identificador de agrupación, `comparison_family_id`, se calcula con una función cuya firma solo acepta campos de diseño experimental previos a la ejecución — sin `**kwargs`, de modo que la fuga de datos de resultado es estructuralmente imposible, no solo una convención de código:

```text
compute_comparison_family_id(*, scenario_fingerprint, topology_fingerprint,
    attack_profile_id, attack_script_sha256, attack_parameters_hash,
    expected_causal_edges, trigger_policy_id, acquisition_profile_id,
    analysis_profile_id, foc_profile_id) -> "family-<sha256[:16]>"
```

Estos campos están **explícitamente excluidos** del cálculo del `comparison_family_id`, sin excepción: `CPR`, `Weighted CPR`, `recovered_edges`, `degraded_edges`, `hypothesis_support`, `final_conclusion`, el estado de incertidumbre, y el estado de comparabilidad. `scenario_fingerprint` se deriva de `scenario_id` más la firma ordenada de los `expected_edges` (`compute_scenario_fingerprint`); `attack_parameters_hash` se deriva únicamente del subconjunto de diseño del perfil de ataque (`protocol`, `register`, `expected_value`, `ot_function`, `tool_used`, `tool_version`), excluyendo campos específicos de la ejecución como las marcas de tiempo de inicio/fin del ataque.

Cada ejecución genera ahora un `forensic_result_card.json` (`build_forensic_result_card`), un perfil ligero que registra:

- identidad: `result_card_id`, `execution_id`, `campaign_id`, `level`, `generated_at`
- campos de diseño/agrupación (los únicos que alimentan el `comparison_family_id`): `scenario_fingerprint`, `topology_fingerprint`, `attack_profile_id`, `attack_script`, `attack_script_sha256`, `attack_parameters_hash`, `expected_causal_edges`, `trigger_policy_id`, `acquisition_profile_id`, `analysis_profile_id`, `foc_profile_id`
- punteros, nunca copias: `original_case_id`, `original_case_path`, `comparison_profile_path`
- política de retención explícita: `retention_policy: "lightweight_profile_only"`, `heavy_artifacts_retained: false`, `heavy_artifacts_location` (la ruta del caso original; la evidencia pesada nunca se mueve)
- una instantánea de resultado (`cpr`, `weighted_cpr`, `global_support_level`, `final_claimability_status`) que es **puramente informativa** y nunca se relee como entrada del `comparison_family_id`

El registro global se persiste en `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/comparison_registry/comparison_result_registry.json` con escritura atómica (`tmp` + `replace`). Durante la verificación funcional se detectó y corrigió un bug real: `append_to_registry` deduplicaba por `result_card_id` (un `uuid4` nuevo en cada llamada), de modo que registrar dos veces el mismo caso con `register_existing_case_as_result_card` producía dos filas distintas para la misma ejecución lógica. La corrección dedupe por `execution_id`.

**Tres nuevos endpoints de solo lectura/escritura controlada** en `app_core/presentation/foc_experimentation_api.py`:

- `GET /api/foc/experimentation/comparison-registry` — lista el registro, filtrable por `scenario_id` o `scenario_fingerprint`
- `GET /api/foc/experimentation/comparison-registry/recommend` — dado un `scenario_id`, devuelve la familia comparable más reciente junto con el mensaje literal: *"The system found previous comparable results. To compare the next execution with those results, use the same attack profile, trigger policy, acquisition profile, and scenario family."*
- `POST /api/foc/experimentation/comparison-registry/register-case` — registra retroactivamente un caso preservado existente como `forensic_result_card.json`, reutilizando exactamente el mismo `profile_builder.build_execution_profiles()` que usan las ejecuciones de campaña reales (mismo código, misma garantía de reproducibilidad del `comparison_family_id`), sin copiar evidencia pesada

En el `Forensic Repetition Manager`, cuando se selecciona Level B o C, un panel **Recommended Comparable Experiment** consulta este registro por huella de escenario y expone dos acciones con texto literal exigido:

- **Use Recommended Attack For Comparability** — adopta el `attack_profile_id`, la técnica MITRE, el script de ataque, los parámetros, la política de disparo, la política de adquisición y el `comparison_family_id` recomendados; muestra *"To compare with this previous result, use this attack profile."*
- **Start New Comparison Family** — diverge intencionadamente; muestra *"This execution will create a new comparison family. It can be compared with future executions using the same scenario, attack profile, trigger policy, acquisition profile, and FOC profile."*

Una acción adicional, **Register Existing Case As Result Card**, permite incorporar retroactivamente un caso ya preservado al registro de comparación sin pasar por una campaña.

**`comparison_type` como eje independiente del `status` numérico.** Siguiendo el mismo patrón de tríada de estados ya usado en `foc_causal_reconstruction/status_model.py` (`execution_status` / `reconstruction_state` / `scientific_confidence`), `comparability_service.compare_executions()` añade una segunda clasificación, `comparison_type`, que responde una pregunta distinta a `status`: no "¿los números coincidieron dentro de margen?", sino "¿estas ejecuciones son, por diseño, el mismo experimento?". Se deriva comparando el `comparison_family_id` de los `forensic_result_card.json` de las ejecuciones seleccionadas:

- `direct_family_comparison` — todas las ejecuciones comparten el mismo `comparison_family_id`
- `exploratory_comparison` — los `comparison_family_id` difieren y ninguna ejecución es Level C
- `platform_level_comparison` — los `comparison_family_id` difieren y al menos una ejecución es Level C
- `insufficient_data` — falta el `forensic_result_card.json` de alguna ejecución seleccionada

Cuando `comparison_type !== "direct_family_comparison"`, la Comparability View muestra el texto de cautela literal exigido: *"The selected executions belong to different comparison families. They can be inspected together, but they should not be used as direct forensic reconstruction comparability evidence unless the difference is explicitly accepted as exploratory or platform-level comparison."* Un `direct_family_comparison` puede seguir siendo `Not Comparable` si los números divergieron, y un `exploratory_comparison` puede seguir siendo `Comparable` numéricamente sin ser válido como evidencia de reproducibilidad — los dos ejes se muestran por separado, nunca fusionados en una sola etiqueta.

**Corrección del modelo de fuente para Level B/C.** El frontend (`foc_repetition_manager.html`/`.js`) mostraba `linked source case` como si fuera obligatorio para todos los niveles, contradiciendo el backend, que nunca lo exigió para B/C. La corrección alinea ambas capas:

- `campaign_preflight()` reemplaza, para Level B, la lista anterior de 7 ítems por los 13 ítems exigidos (`scenario_selected`, `active_scenario_exists`, `required_roles_resolved`, `attack_profile_selected`, `automated_attack_script_available`, `detection_stream_available`, `trigger_policy_configured`, `forensic_auto_acquisition_available`, `case_creation_available`, `acquisition_targets_resolved`, `time_sync_check_available`, `baseline_noise_capture_available`, `output_campaign_directory_can_be_created`), sin evaluar nunca `linked_source_case_selected` ni bloquear por "No linked case". Devuelve además `info_notes` con el mensaje literal: *"No linked source case is required for Level B. A new forensic case will be created for each repeated incident execution."*
- `create_campaign()` añade guardas explícitas: Level A sin caso vinculado lanza `"A linked source case is required for Level A. Select a preserved case before creating the campaign."`; Level B/C sin `scenario_id` resoluble lanza `"Scenario ID is required for Level B. Select or auto-detect an active deployed scenario before starting execution."`
- en el formulario, el campo "Linked source case" se reubica dinámicamente: permanece visible y obligatorio en Step 2 para Level A; para Level B/C se traslada al panel de Advanced Mode como **"Optional reference case"**, con el texto *"Optional. This case is only used to copy defaults, thresholds, expected causal model, or comparison-family settings. It is not reused as evidence and is not required for Level B/C."*
- el título de Step 2 pasa a ser dependiente del nivel (`stepTwoTitle` en `LEVEL_META`): *"Select deployed scenario and incident profile"* para Level B, *"Select deployed scenario and redeployment profile"* para Level C
- el resumen de campaña y la tarjeta de ejecución dejan de mostrar "Linked base case"/"Open Base Case Dashboard" para B/C; muestran "Source: Active deployed scenario", "New case policy: A new forensic case will be created for every execution after detection-triggered acquisition.", y "Open Generated Case Dashboard" condicionado a que ya exista un `source_case_id` generado (en otro caso: "Generated case: Not created yet.")

**Bug real detectado durante la verificación funcional, no anticipado en el plan inicial.** `execution_service.load_execution(execution_id)` buscaba el identificador de ejecución (`EXEC-0001`, `EXEC-0002`, …) iterando **todas** las campañas bajo `CAMPAIGNS_ROOT`, pero ese identificador solo es único dentro de una campaña — cada campaña reinicia su numeración en `EXEC-0001`. Esto significa que `compare_executions()`, que es precisamente la función que sostiene la nueva clasificación `comparison_type`, podía resolver silenciosamente la ejecución equivocada si dos campañas distintas compartían el mismo `execution_id` (lo cual ocurre virtualmente siempre). Se confirmó el defecto de forma determinista: dos campañas creadas consecutivamente, ambas con `EXEC-0001`, hacían que `load_execution("EXEC-0001")` devolviera siempre la campaña más reciente listada por el sistema de archivos, independientemente de cuál se pidiera. La corrección añade un parámetro opcional `campaign_id` a `load_execution()` que acota la búsqueda a esa campaña cuando se conoce, y `compare_executions()` lo propaga ahora en cada resolución — sin alterar el comportamiento de los demás llamadores, que no pasan `campaign_id` y conservan la búsqueda global previa.

**Verificación funcional realizada (sin servidor, llamadas Python directas, con limpieza posterior de artefactos de prueba):**

- una ejecución de campaña Level A y un registro retroactivo del mismo caso (`register_existing_case_as_result_card`) producen el **mismo** `comparison_family_id`, confirmando que el identificador es reproducible a partir de los campos de diseño exclusivamente
- forzar manualmente un `comparison_family_id` distinto en un `forensic_result_card.json` produce `comparison_type: "exploratory_comparison"`; dos ejecuciones de la misma familia producen `"direct_family_comparison"`
- una campaña Level B se crea correctamente sin ningún campo de caso vinculado cuando se provee `scenario_id`; sin `scenario_id` lanza el mensaje exacto exigido
- una campaña Level A sin caso vinculado lanza el mensaje exacto exigido
- `python -m py_compile` sobre los seis módulos Python modificados, y verificación de correspondencia 1:1 entre los `id` de DOM referenciados desde JS y los declarados en el HTML, en ambas vistas (`foc_repetition_manager.html`, `foc_reconstruction_comparability.html`)

**Límite de alcance, declarado explícitamente.** Esta iteración no construye un motor de ejecución de ataques real para Level B/C dentro de `foc_experimentation` — ese motor sigue sin existir, tal como se documenta en la sección *Campaign levels* de este mismo módulo. `trigger_policy_id`, `acquisition_profile_id`, `analysis_profile_id` y `foc_profile_id` se representan como constantes de versión fija (`"default_kolla_lime_tshark_v1"`, etc.) en lugar de una configurabilidad inexistente. El valor científico de incluirlos en el hash del `comparison_family_id` es que, el día en que alguno de esos pipelines cambie materialmente, su cadena de versión cambiará y los resultados antiguos y nuevos dejarán de tratarse silenciosamente como comparables.

#### Evidence-Based Hypothesis Support and Forensic Storyline module (2026-06-23)

This round refines the temporal model, makes the multi-vector acquisition mismatch explicit, and replaces the lightweight `Evidence Support Extract` with a much more rigorous, atom-level forensic reasoning layer. None of it runs automatically: every heavy step stays strictly on-demand, exactly like the rest of this dashboard.

**Temporal confidence is now four distinct fields, not one.** The previous model derived a single `temporal_confidence_state` purely from the clock-offset window, which produced an apparent contradiction: `max clock offset: 0s`, `synchronized: true`, yet `temporal_confidence: limited`. `uncertainty/budget.py` now exposes `node_clock_synchronization_status`, `evidence_timestamp_availability`, `evidence_timestamp_resolvability`, and `causal_temporal_ordering_confidence` (with an explicit `causal_temporal_ordering_reason` and a static `temporal_model_note`: *"A synchronized infrastructure does not automatically mean that all forensic artifacts contain usable timestamps for causal ordering."*). The combined confidence takes the **worst** of the clock-based state and the timestamp-availability/resolvability state, computed from the causal graph's own edges (3 of 8 edges in this case have a declared-but-unresolved temporal check) — it is no longer capped by clock offset alone. `temporal_confidence_state` is kept as a backward-compatible alias of the new combined field.

**Multi-vector acquisition-trigger mismatch is now explicit.** When the acquisition trigger is host/FIM-oriented and the causal path is OT/Modbus-oriented, `trigger_vs_causal_path` now carries `mismatch_label: "multi-vector_acquisition_trigger_mismatch"` and the verbatim message: *"The preserved case was triggered by a host or FIM-oriented alert, while the causal reconstruction evaluates an OT Modbus path... This is not an error. It is a scientific limitation and should be reported as such."*

**New module: Evidence-Based Hypothesis Support** (`app_core/infrastructure/foc_reconstruction/evidence_support/`), replacing `evidence_support_extract.py`'s orchestration (its two generic helpers, `_build_hypotheses`/`_LAYER_LABELS`, are still reused). It performs real per-layer triage — never reanalysis, never re-execution of forensic tools — over already-preserved/derived artifacts:

- **Memory**: parses already-written Volatility3 plugin text output (`vol3_pslist.txt`, `vol3_sockstat.txt`, `vol3_bash.txt`) per dump.
- **Network**: re-checks Modbus packet fields via a read-only `tshark` subprocess (`mbtcp.trans_id`, `modbus.func_code`, `modbus.write_reference_num`, etc.) over the preserved pcaps — for this case, this produces a direct, packet-level negative result: **zero write-function packets across all 10 preserved pcaps**, surfaced as explicit counter-evidence rather than hidden.
- **Disk**: bounded reads of already-recovered `passwd`/`auth.log`/`bash_history` files.
- **OT**: function-code aggregates from `ot_findings.json` — this case shows only read-function codes (1, 3), no write code, a second independent confirmation of the network-layer finding.
- **Alerts**: IDS signature hits (including the `"...Modbus write multiple registers"` signature, explicitly flagged as a signature-name claim, not a packet-level confirmation) plus the reused trigger/causal-path mismatch.
- **Timeline**: causal-graph-anchored event matching (not a raw dump of the case's 350 timeline events), plus a third independent confirmation that `ot:non_write_function` dominates with zero `ot:write_function` events.
- **Custody / Causal graph**: reuse the dashboard's existing integrity summary and the causal graph's own edges directly.

Each extracted observation becomes an **evidence atom** (`atom_id`, `evidence_layer`, `support_direction` ∈ `{supports, partially_supports, contradicts, neutral, not_evaluable}`, `support_strength`, `timestamp_status`, `limitation`, `raw_reference`, …) — 51 atoms for this case, all traceable to a real source file, none fabricated. Atoms are routed to the specific causal edge(s) they are topical evidence for (not merely bucketed by shared layer), then classified per edge into `confirmed_by_multiple_layers / supported_by_single_layer / partially_supported / inferred / contradicted / not_evaluable / temporally_unresolved`. The global support level is computed with a hard rule: it can never reach `strong_support` unless at least two relations are cross-layer-confirmed, zero are contradicted, and zero are temporally unresolved — for this case it resolves to **`moderate_support`**, matching the required scientific conclusion exactly (network write-absence + OT read-only codes + the trigger/causal mismatch all register as real contradictions on specific edges, while protocol-presence relations remain multi-layer confirmed).

Produces 7 derived outputs under `derived/evidence_support/`: `evidence_atoms.jsonl`, `evidence_triage_report.json`, `cross_layer_support_matrix.json`, `hypothesis_support_report.json`, `forensic_storyline.json` (7 atom-backed steps, each with `supporting_atoms`/`timestamp_status`/`limitation`), `claimability_report.json` (supported / partially supported / unsupported-or-not-yet-claimable, including `"Direct OT alert to forensic acquisition link."`), and `counter_evidence_report.json`. `derived/executive/evidence_support_extract.json` is no longer written separately — the executive summary's stub reads `hypothesis_support_report.json` directly.

Runs as a background job reusing the dashboard's existing job primitives (`_new_job`/`_set_job`/`_RUNNING_JOB_THREADS`) behind `POST /api/foc/evidence-support/run` (skip-if-current) and `/regenerate` (force), polled via the existing `/api/foc/lifecycle/job-status` endpoint — no new polling mechanism. Five new GET endpoints serve the generated reports read-only, never triggering generation. Staleness is checked against eleven source artifacts (not just the causal graph alone, as the prior module did), with explicit `not_generated` / `stale` / `current` states surfaced in the UI exactly like every other lifecycle artifact.

The dashboard's `Evidence Support Extract` section is replaced by `Evidence-Based Hypothesis Support`, with five cards: hypothesis support summary, an 8-layer × 6-column contribution matrix, the atom-backed storyline (each step has a "View supporting evidence" toggle), the claimability boundary, and evidence gaps/counter-evidence — all lazy-loaded only on `View Details`, reusing the existing stale-banner and `.run-action-btn` delegation patterns.

Nothing in this round touches acquisition, preservation, the original `manifest.json`/`chain_of_custody.log`, attack execution, detection, trigger selection, or the underlying memory/network/disk/OT analysis engines — `tshark` and the Volatility3/Sleuthkit text parsers are invoked read-only against already-acquired pcaps and already-written plugin output, never against raw dumps or disk images, and only on explicit user demand.

#### Endurecimiento científico de la Scientific Evidence Lifecycle Dashboard (2026-06-23)

Esta iteración no rehace la vista; corrige incoherencias detectadas y añade una sola pieza nueva, deliberadamente ligera.

**Corrección de raíz (el cambio de mayor impacto):** `_build_causal_summary` resolvía el ground truth desde `bundle["scenario_ground_truth"]`, que es el snapshot de atestación preservado y usa un esquema distinto (sin clave `attack_expected`). Esto rompía silenciosamente la selección del ataque real y producía en cascada exactamente las incoherencias reportadas: protocolo `unknown` mostrado como `confirmed`, `target_plc` apuntando a `FUXA_Instance` (que es SCADA/HMI, no un PLC), y una afirmación falsa de alineación entre trigger y causal path. La corrección resuelve el ground truth desde la misma ruta que el módulo de reconstrucción causal ya validó (`causal_status.ground_truth_summary.ground_truth_path`), con fallback seguro si no está disponible.

**Incoherencias corregidas:**
- Se separan explícitamente "last multilayer analysis / last causal reconstruction" (instantánea del resumen ejecutivo) de "current job / live pipeline status" (estado en vivo), con una nota de conflicto cuando un job está corriendo mientras el resumen aún refleja la ejecución anterior.
- `Trigger Path vs Causal Attack Path` ya no afirma alineación cuando el causal path es `not_available`; ahora distingue tres estados: alineado, desalineado (con el mensaje específico host/FIM vs OT Modbus), y "no puede confirmarse".
- El botón `Open` de artefactos nunca se habilita si el artefacto no existe o su tamaño no pudo determinarse (verificación reforzada en backend y frontend).
- Los avisos de obsolescencia (`is_stale`) del resumen ejecutivo y de la reconstrucción causal incluyen ahora un botón explícito de regeneración (`Regenerate Executive Summary` / `Regenerate Causal Reconstruction`); nunca se regenera automáticamente.
- Corregido un bug de Python donde un offset de reloj genuinamente `0.0` segundos se mostraba como `"unknown"` por el patrón `valor or "unknown"` (0.0 es falsy en Python).

**Nuevo: Evidence Support Extract.** Artefacto derivado y ligero en `derived/executive/evidence_support_extract.json`, generado por `evidence_support_extract.py`. No reanaliza PCAPs, dumps de memoria, discos ni exports OT, y no ejecuta ninguna herramienta forense: normaliza lo que el grafo causal y los hallazgos multicapa ya calcularon. Produce:
- una hipótesis forense explícita (`H1`), específica de Modbus/OT cuando el ground truth lo indica
- soporte por capa (`network`, `memory`, `disk`, `ot`, `alerts`, `timeline`, `custody`, `analysis`, `cross_layer`) en la escala `strong_support` / `moderate_support` / `weak_support` / `no_support` / `contradicted` / `not_evaluable`
- hallazgos normalizados, cada uno trazable 1:1 a un edge causal (mismo `edge_id`) o a un hallazgo cruzado existente
- una evaluación final de soporte global con narrativa científica generada a partir de datos reales, sin inventar precisión que no existe

El resumen ejecutivo solo carga un *stub* barato del extracto (estado, nivel de soporte global, conteos); el detalle completo (hipótesis, soporte por capa, tabla de hallazgos) se carga bajo demanda mediante `GET /api/foc/evidence-support-extract` al pulsar `View Details`. La generación (`POST /api/foc/lifecycle/generate-evidence-support-extract`) es síncrona porque solo lee artefactos ya derivados (~1.5s medido), nunca se ejecuta automáticamente al abrir la vista.

Ningún cambio de esta iteración toca adquisición, preservación, `manifest.json`/`chain_of_custody.log` originales, ejecución de ataques, detección, selección de trigger, ni los motores de análisis subyacentes; solo se leen sus salidas ya escritas, más el grafo causal y los hallazgos multicapa ya generados.

#### Profesionalización del Causal Reconstruction Cockpit (2026-06-22)

Esta iteración corrige inconsistencias detectadas en la primera versión del cockpit y lo alinea con el plan técnico FOC causal and uncertainty:

- Se separan tres estados independientes (`execution_status`, `reconstruction_state`, `scientific_confidence`) para que `Progress: 100%` nunca se interprete como "reconstrucción causal fuerte".
- Se corrige la contradicción entre el panel `Derived Outputs` (que mostraba `not_available`) y `Raw artifacts access` (que mostraba las rutas reales): ambos paneles leen ahora el mismo mapa de disponibilidad calculado una sola vez en el backend.
- Se corrige un bug real: el evaluador de memoria leía la clave `dumps_analysed` (no existe) en lugar de `dumps_analyzed`, por lo que el edge de análisis multicapa quedaba permanentemente `degraded` aunque el análisis de memoria hubiera sido efectivo.
- Un edge solo puede quedar `recovered` con `temporal_status` en `supported` o `not_required`; un `temporal_status: unknown` ahora degrada el edge explícitamente en vez de marcarlo como recuperado.
- El ratio de integridad se separa en `graph_scope_integrity_ratio` (artefactos usados por el grafo) y `case_wide_integrity_ratio` (validación de hash a nivel de manifest completo), cada uno con su fórmula explicada.
- La ventana de incertidumbre se muestra también en segundos, con una frase interpretativa explícita sobre el impacto en el orden temporal de los edges.
- Se añaden dos edges Modbus-específicos (`network_modbus_write`, `plc_or_scada_state_observation`) derivados de `network_findings.json` y `ot_findings.json` reales, sin inventar registro/valor a nivel de paquete.
- `causal_status.json` pasa a ser la fuente ligera que lee la UI por defecto; el reporte completo (grafo, incertidumbre, markdown) se carga perezosamente solo cuando el analista despliega esa sección.
- El reporte markdown se reestructura en 11 secciones fijas, incluyendo `Next Required Actions`.

Ningún cambio de esta iteración toca adquisición, preservación, `manifest.json`/`chain_of_custody.log` originales, ejecución de ataques, detección, selección de trigger, ni los motores de análisis subyacentes (Volatility, TSK, tshark, exportación OT); solo se leen sus salidas ya escritas.

#### Endurecimiento científico y de latencia del Causal Reconstruction Cockpit (2026-06-22)

Esta segunda iteración no rehace el trabajo anterior: endurece puntos científicos concretos del modelo de edges y corrige la mayor fuente de latencia detectada, manteniendo el mismo límite de "no modificar" adquisición, preservación, ejecución de ataques, detección, selección de trigger ni los motores de análisis subyacentes.

- **Latencia**: se detectó que `foc-reconstruction/attestations/alert_correlation.json` (~101 MB, 71.261 registros) se reparseaba sin caché en cada poll de `/api/foc/causal/status`. Se añade una caché en memoria con invalidación por `mtime` (correcta por construcción ante cambios reales) más un TTL de 30s como red de seguridad. El resultado medido: ~1.5-3s en frío frente a ~8ms en caliente dentro del mismo proceso del servidor.
- El edge `attack_execution → ot_modbus_write` ya no puede quedar `recovered` solo con `attack_attestation`; ahora también exige `network_modbus_observation` (tráfico Modbus realmente observado).
- Tres edges que antes declaraban `temporal_status: not_required` por omisión (sin `timestamp_ref` declarado) ahora declaran sus referencias temporales reales (`detection_observed_at`, `alert_observed_at`). Con los datos reales del caso (regla de detección sin `enabled_at`, correlación de alertas sin timestamp absoluto), el resultado honesto es `temporal_status: unknown`, que la regla estructural ya existente degrada explícitamente en vez de dejarlo pasar como `recovered` por omisión.
- Cuando el offset de reloj preservado hace que el orden temporal sea poco fiable, se añaden dos frases explícitas en `uncertainty_report.json::temporal` (`temporal_warning`, `temporal_caution`) y se muestran en la cabecera del cockpit, no solo en el detalle de incertidumbre.
- La integridad por edge se separa en `graph_artifact_integrity_status` (solo los artefactos que ese edge usa) y `case_wide_integrity_status` (validación de manifest a nivel de caso completo); `integrity_status` se mantiene como alias del primero por compatibilidad con CSV/markdown existentes.
- `memory_analysis_useful` ya no se conforma con `dumps_analyzed > 0`: ahora también exige al menos un resultado con `status: completed` y `completed_plugins` no vacío. Si hay dumps pero ningún plugin efectivo, el edge queda `degraded` con el motivo `"Memory analysis exists, but no effective plugin output was produced."`.
- Se añaden dos endpoints de solo lectura, `GET /api/foc/causal/uncertainty` y `GET /api/foc/causal/graph-summary` (este último limitado a 15 nodos / 20 edges, con `truncated: true` si una escena futura excede el límite), para que cada sección del cockpit cargue solo lo que necesita en vez de depender del reporte combinado.
- Los edges Modbus a nivel de función/registro/valor de paquete siguen sin implementarse: ni `network_findings.json` ni `ot_findings.json` extraen hoy ese detalle a nivel de paquete, y añadir el edge sin esa base sería inventar evidencia. Queda documentado como trabajo futuro que depende de los parsers de red/OT, fuera del alcance de esta iteración.

Ningún cambio de esta iteración toca adquisición, preservación, `manifest.json`/`chain_of_custody.log` originales, ejecución de ataques, detección, selección de trigger, ni los motores de análisis subyacentes; solo se leen sus salidas ya escritas, más el archivo `scenario_ground_truth.json` (cambios aditivos) y los artefactos bajo `derived/reconstruction/`.

### FOC performance and loading behavior

The FOC dashboard now uses a lighter delivery path so the user-facing latency is reduced without removing reconstruction content.

The current behavior is:

- the frontend requests a single aggregated payload from `GET /api/foc/dashboard`
- the backend keeps a short-lived cache for that payload so repeated refreshes do not rebuild the same state immediately
- the event stream no longer forces an eager full reload for every single notification; reloads are briefly debounced so bursts of FOC events do not trigger repeated complete renders
- the page shows a lightweight loading indicator while the initial reconstruction payload is being assembled, so the operator can see that the view is loading instead of assuming it is blocked

This optimization does not remove any FOC panel or any reconstruction artifact. It only reduces redundant JSON reads, repeated state assembly, and unnecessary full rerenders.

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

The dashboard does not treat these layers as equivalent. In particular:

- structural availability does not imply evidential completeness
- evidential indexing does not imply forensic analysis
- forensic analysis does not imply semantic interpretation

This prevents the reconstruction layer from overstating the maturity of an experiment simply because artifacts exist on disk.

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

### Evidence-class semantics

The reconstruction layer also distinguishes between several artifact classes inside the forensic space:

- **acquisition metadata**
  - custody logs, digest files, capture metadata, synchronization metadata
- **preserved evidence**
  - primary preserved artifacts such as PCAP, raw disk, memory dump, or OT export
- **forensic inputs**
  - preserved contextual inputs such as scenario snapshots or tool-state snapshots
- **analysis outputs**
  - technical analysis directories such as Volatility or TSK outputs

This distinction is necessary because not every indexed artifact should be interpreted as primary evidence. A case may contain rich metadata and preserved inputs without yet containing technical forensic analysis or explicit alert-to-evidence linkage.

### Chronology versus detection surface

The dashboard distinguishes between two related but non-equivalent temporal views:

- **Timeline / Lifecycle and Incident Sequence**
  - the complete reverse-time chronology of the experiment
  - includes lifecycle transitions, tool instrumentation, attack execution, detections, escalation, and forensic pipeline events
- **Alerts and Events / Detection and Escalation Surface**
  - a filtered detection-oriented surface
  - focuses on alerts, triage, DFIR escalation, and case creation without repeating the full offensive chronology

This distinction reduces analytical ambiguity. The timeline answers the question **what happened and in which order**, while the detection surface answers **what the platform detected, how it classified the event, and whether escalation followed**.

The primary timeline view also aggregates repeated detection events so that the user does not have to inspect thousands of near-identical alerts one by one. Aggregation uses the detection signature, node, agent, rule, source, destination, and a time bucket in order to preserve operational meaning while improving readability.

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

The causal graph uses the structural scenario model as its visual base. Instead of showing abstract relationship IDs only, it uses the IT/OT node composition of the active scenario and overlays attack and detection activity on top of that topology. This makes the graph more interpretable for hybrid scenarios involving victim, monitor, PLC, and SCADA nodes.

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

The score is intentionally conservative. A high score requires more than artifact presence. In particular:

- attack-to-alert linkage is not treated as confirmed if it is only inferred
- case and custody presence do not compensate for missing alert-to-evidence linkage
- forensic reconstruction is not treated as complete until technical analysis outputs exist
- semantic interpretation is not treated as generated until technical forensic outputs exist first

This means the reconstruction layer distinguishes between:

- what is indexed
- what is linked
- what is analyzed
- what is confirmed
- what remains unresolved

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

Typical high-value unresolved states include:

- a case exists but is not linked to alerts
- evidence is preserved but not related to a triggering alert
- detections are available but attack correlation is only inferred
- analysis has not yet been executed on preserved evidence
- semantic interpretation has not yet been generated from technical findings

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

### Correlation quality semantics

The reconstruction layer distinguishes between several correlation levels when linking alerts to attacks or other entities:

- **confirmed**
  - the relation is strongly supported by the indexed sources
- **inferred_high**
  - the relation is likely, based on target or timing alignment
- **inferred_medium**
  - the relation is plausible, but weaker
- **inferred_low**
  - the relation is tentative
- **unresolved**
  - no reliable relation could be established

This distinction is essential for scientific acceptability because the dashboard must not present inferred correlations as confirmed findings.

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

### FOC Reconstruction Comparability View

The **FOC Reconstruction Comparability View** (`foc_reconstruction_comparability.html`) is a dedicated comparison surface for already-generated experimental executions. It does not create new runs, does not modify evidence, and does not alter any reconstruction logic. Its sole purpose is to compare execution profiles that have already been generated by the platform and determine whether their forensic reconstructions are scientifically comparable.

![FOC Reconstruction Comparability](Images_readme/FOC_Reconstruction_Comparability.png)

The view is organized around three responsibilities:

**Execution selection and readiness**

The left panel lists preserved forensic cases with their reconstruction state (e.g., `COMPLETED WITH RECONSTRUCTION`). The operator selects two or more executions from the same campaign. Before the comparison can run, the view evaluates a set of readiness conditions:

- scenario container defined
- at least two executions registered
- execution profiles available for each selected run
- ground truth sealed for the campaign
- baseline noise profile available
- CPR and WCPR available for comparison

Each condition is shown as `PASSED` or `PENDING`, with an explanation of what is still missing.

**Comparison job and decision surface**

Once the readiness conditions are satisfied, the operator triggers a background comparison job. The **Comparison Job Status** panel tracks the job state in real time. When the job completes, the **Decision Surface** panel presents the comparability verdict:

- `COMPARABLE` — the forensic reconstructions are sufficiently similar across the selected executions given the declared baseline noise tolerance
- `NOT COMPARABLE` — the reconstructions diverge beyond the declared threshold, and the specific diverging metrics are identified
- `INSUFFICIENT DATA` — the comparison cannot proceed because one or more required profiles are missing

The decision surface also exposes:
- what passed and what remains limited in each dimension
- which specific metrics diverged and by how much
- what the operator should inspect or fix before re-running the comparison

**Scientific story mode and technical mode**

The view offers two reading modes. Scientific Story Mode narrates the comparison in natural language — what is being compared, what comparable means in this context, and what the result implies for the paper's reproducibility claims. Technical Mode exposes the raw comparison matrix, artifact paths, and advanced metric details for expert inspection.

The **Methodological Basis** panel at the bottom-left makes the comparison framework explicit: it shows the declared scenario scenario blueprint, the baseline noise tolerance thresholds, and the comparability rules used to reach the verdict. This prevents the comparison from being a black box — the reader can always trace the verdict back to the specific thresholds and metrics that produced it.

---

## FORGE-VI Scientific Dashboard

The **FORGE-VI Scientific Dashboard** (`forge_vi_scientific_dashboard.html`) is the scientific experimentation view of the platform. It presents the full quantitative and qualitative analysis of a completed experimental campaign, including causal path recoverability, pipeline coverage, evidence integrity, and edge-level reproducibility across all experimental runs.

![FORGE-VI Scientific Dashboard — End-to-End Forensic Workflow](Images_readme/End_to_End_Forensic_Workflow.png)

The dashboard is read-only with respect to the platform. It reads the outputs of already-completed experimental campaigns and presents them through a structured scientific lens. It does not execute attacks, acquire evidence, or modify any reconstruction artifact.

### Campaign header

At the top of the view, the campaign header identifies the active experimental context:

- **Campaign ID** — unique campaign identifier (e.g., `CMP-20260707-000220-CBFB`)
- **Scenario ID** — normalized scenario identifier (e.g., `scn-b83dbbfb`)
- **N executions** — total number of experimental runs in the campaign
- **Cases sealed** — number of runs that produced a sealed forensic case

This header also carries a one-line scientific description: *Forensic Observational Context — Causal Path Recoverability and Experimental Reproducibility. Evaluated campaign · read-only scientific view.*

### KPI strip

The KPI strip presents the most important aggregate metrics of the campaign:

| KPI | Scientific meaning |
|-----|-------------------|
| **Executions** | Total number of evaluated experimental runs |
| **Cases sealed** | Runs where `intervention_status = completed`, i.e., full forensic preservation was achieved |
| **SHA-256 coverage** | Mean integrity ratio across all runs — fraction of primary artifacts with a verified hash |
| **CPR** | Causal Path Recoverability — fraction of expected causal edges that were recovered across all runs |
| **Expected edges** | Total number of causal edges declared in the scenario ground truth |
| **Stable rec.** | Number of causal edges recovered in 100% of runs |
| **CPR stability** | Whether CPR is stable (σ = 0) or variable across runs |

### Experimental Pipeline — End-to-End Forensic Workflow

The pipeline section shows the **operational coverage** of the end-to-end forensic workflow across all runs. Each pipeline stage corresponds to a structural layer of the experiment:

1. **Deploy & Scenario** — scenario declaration and infrastructure deployment
2. **Attack** — ATT&CK-aligned attack execution
3. **Detection** — network and host-based detection coverage
4. **OT State** — industrial control state observation (pre/post)
5. **Alert** — alert generation and indexing
6. **Forensic Case** — forensic case creation and sealing
7. **Preservation** — evidence preservation (memory, disk, network, OT)
8. **Analysis** — multilayer forensic analysis completion

Each stage is colour-coded:
- **Blue** — fully covered across all runs
- **Orange** — partially covered or degraded in some runs
- **Grey** — absent or not reached

This gives an immediate visual reading of which stages of the experimental chain succeeded consistently, which were degraded, and which were not captured.

### Causal Path Recoverability section

The CPR section is the scientific core of the dashboard. It presents the causal recoverability of the experiment at two levels of resolution.

**Causal Path Recoverability donut**

The donut chart shows the aggregate edge-state distribution across all runs:

- **Recovered** (green) — edges where all required evidence was preserved and linked
- **Ambiguous** (amber) — edges where evidence exists but causal linkage is incomplete or uncertain
- **Degraded** (orange) — edges where coverage was partial
- **Missing** (red) — edges with no recoverable evidence

The CPR percentage displayed at the centre is the binary metric: `recovered_edges / total_edges`. Each recovered edge contributes `1/total` to the CPR score. Non-recovered edges contribute zero, regardless of partial evidence.

**Actual CPR contribution per edge**

Beneath the donut, a horizontal strip shows each causal edge (`e1` through `e8`) with its individual CPR contribution:

- a recovered edge contributes `12.5%` to CPR (for an 8-edge causal graph)
- a non-recovered edge contributes `0%`

The colour of each cell reflects the dominant edge state across all runs. This strip makes the CPR formula transparent and directly inspectable.

The eight causal edges modelled in the platform are:

| Edge | Causal relation |
|------|----------------|
| e1 | Attack execution → OT Write |
| e2 | OT Write → Network Modbus traffic |
| e3 | Network Modbus traffic → Detection surface |
| e4 | OT Write → PLC state observation |
| e5 | Detection surface → Alert observation |
| e6 | Alert observation → Forensic case |
| e7 | Forensic case → Preserved case evidence |
| e8 | Preserved case evidence → Multilayer analysis |

**Edge State Reproducibility table**

The reproducibility table shows, for each causal edge, the distribution of edge states across all `N` experimental runs:

- **Dominant state** — the state observed in the majority of runs (e.g., `rec`, `amb`)
- **Run distribution bar** — a proportional bar showing how many runs produced each state
- **Consistency** — percentage of runs in which the edge held its dominant state

A consistency of 100% for all edges means the experiment is perfectly reproducible — the same causal reconstruction is obtained every time the experiment is executed under the same conditions. This is a direct, quantitative measure of experimental reproducibility that can be cited in a scientific paper.

### Scientific interpretation

The FORGE-VI Scientific Dashboard supports the following scientific claims directly from the displayed data:

- **CPR = 87.5%** — 7 out of 8 expected causal edges were recovered in all 10 runs
- **Consistency = 100%** for all edges — the reconstruction is perfectly reproducible across executions
- **σ(CPR) = 0** — CPR is stable, i.e., no run produced a different causal reconstruction
- **e5 (Detection → Alert) is consistently ambiguous** — detection-to-alert linkage was observable but not fully traceable in any of the 10 runs, indicating a systematic evidence gap rather than a random failure
- **Cases sealed = 10/10** — all experimental runs produced a sealed forensic case with complete preservation

These results are grounded in preserved forensic artifacts, not in simulated or inferred data.

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

## 8. FORGE-VI scientific experimentation and truthful reporting

The platform now includes a dedicated **scientific experimentation and truthful reporting layer** for controlled repeatability studies. Its purpose is not to beautify results or hide uncertainty. Its purpose is to state, as precisely as possible:

- what was actually executed
- what evidence was actually preserved
- what was only declared
- what was computed from existing artifacts
- what remains unavailable
- what must be rerun if a final claim is required

This layer is implemented on top of preserved artifacts, FOC outputs, experimentation workspaces, scientific reports, and comparison registries. It does **not** replace acquisition or analysis. It reads them and reports their real state.

### 8.1. Scientific campaign levels

FORGE-VI distinguishes three campaign levels, but the current scientifically mature scope is concentrated on **Level A** and **Level B**.

- **Level A**
  - repeated analysis and reconstruction over the **same sealed case**
  - no new acquisition
  - no new attack execution
  - used to evaluate analysis and reconstruction stability over unchanged evidence

- **Level B**
  - repeated execution of the **same incident inside the same deployment**
  - each repetition creates a **new forensic case**
  - each resulting case can then be processed by **Level A-style analysis**
  - used to evaluate incident-to-case repeatability inside a stable deployment

- **Level C**
  - redeployment-aware experimentation
  - intended for destroy/redeploy/re-execute studies
  - currently documented and scaffolded, but still outside the present final evaluation scope

Very important:

```text
Level B includes Level A analysis over each generated Level B case.
```

This means the reporting layer explicitly separates:

- `standalone Level A`
- `analysis over Level B case`
- `Level B cases`

These denominators must never be silently pooled.

### 8.2. Honest denominator model

All scientific outputs must carry a visible denominator.

The platform now explicitly distinguishes:

- `N_A_total`
- `N_A_accepted`
- `N_A_excluded`
- `N_A_over_Level_B_cases`
- `N_B_total`
- `N_B_accepted`
- `N_B_excluded`

This is a scientific requirement, not a UI detail. For example:

```text
mean ± sample standard deviation over n=2 accepted Level B cases
```

is acceptable when only two accepted Level B cases exist.

By contrast:

```text
mean ± std over N_B=6
```

is not acceptable unless six accepted homogeneous Level B cases really exist.

### 8.3. Truthful data categories

The reporting layer uses explicit categories so declared values are never misreported as observed evidence.

The current model distinguishes:

- `directly observed`
- `declared but not packet-confirmed`
- `computed from existing artifacts`
- `not computed by current pipeline`
- `not available in current artifacts`
- `not applicable under active acquisition profile`
- `partial verification`
- `full verification`

Examples:

- a Modbus function declared in the attack profile but not confirmed in preserved packets remains:
  - `declared but not packet-confirmed`
- a latency derived from `pipeline_events.jsonl` is:
  - `computed from existing artifacts`
- an OT export timing field when no OT export was preserved is:
  - `not available in current artifacts`
- manifest verification when large artifacts were skipped is:
  - `partial verification`

### 8.4. Truthful reporting packages

The platform can now generate **truthful scientific audit packages** directly from existing artifacts, without repeating acquisition or changing the analysis engines.

Current package families include:

- **FORGE-VI Level B Table Reconstruction**
  - reconstructs Level B paper tables from current artifacts
  - generates:
    - `FORGE-VI_LevelB_Table_Reconstruction_Report.md`
    - `FORGE-VI_LevelB_Table_Values.json`
    - `FORGE-VI_LevelB_Data_Availability_Matrix.csv`
    - `FORGE-VI_LevelB_Table_Gap_Report.md`

- **FORGE-VI Level A + Level B Truthful Evaluation**
  - audits Level A and Level B together under strict scientific language
  - generates:
    - `FORGE-VI_LevelA_LevelB_Truthful_Evaluation_Report.md`
    - `FORGE-VI_LevelA_LevelB_Truthful_Table_Values.json`
    - `FORGE-VI_LevelA_LevelB_Truthful_Data_Provenance.csv`
    - `FORGE-VI_LevelA_LevelB_Truthful_Data_Availability_Matrix.csv`
    - `FORGE-VI_LevelA_LevelB_Truthful_Gap_Report.md`
    - `FORGE-VI_LevelA_LevelB_Truthful_Paper_Tables.md`
    - `FORGE-VI_LevelA_LevelB_Rerun_Readiness_Plan.md`

These packages are stored under:

```text
app_core/infrastructure/forensics/evidence_store/validation_reports/
```

and are also exposed in the `FOC Paper Evidence` interface.

### 8.5. What the current reporting layer can already do

Without changing acquisition or analysis, the platform can already:

- discover current Level A and Level B campaigns
- distinguish standalone Level A from analysis over Level B cases
- index Level B repetitions by campaign, repetition, run, and case
- reconstruct incident specification from existing execution artifacts
- summarize preserved artifacts per case
- report manifest and custody state
- derive timing metrics from `pipeline_events.jsonl`
- report time synchronization state
- report causal reconstruction summaries and relation-level states
- report `CPR` and `Weighted CPR` from preserved reconstruction outputs
- build gap reports, data-availability matrices, and rerun-readiness plans

It can also distinguish between:

- what is suitable for a **preliminary audit**
- what is suitable for a **final paper table**
- what requires only **reporting refinement**
- what requires **analysis changes**
- what requires **acquisition/preservation changes**
- what requires a **fresh campaign**

### 8.6. Evidence preservation semantics

The scientific reporting layer does not collapse all evidence checks into a single green status.

Instead, it separates five technical preservation dimensions:

- **Network evidence preservation**
  - preserved PCAPs
  - rolling PCAP segments
  - imported incident-window context
  - hashes and provenance
  - overlap with the incident window

- **Trigger alert preservation**
  - trigger event
  - trigger-to-case binding
  - normalized alert context
  - Suricata identifiers when observed
  - raw alert preservation state
  - Wazuh trigger mapping state

- **Industrial / OT evidence preservation**
  - OT export
  - PLC/SCADA state records
  - Modbus-specific observations
  - industrial timing and provenance

- **Host evidence preservation**
  - memory dumps
  - disk snapshots
  - host-level logs and provenance

- **Manifest and custody verification**
  - manifest presence
  - custody log presence
  - hash validation coverage
  - skipped artifacts
  - missing artifacts
  - custody-chain state

The platform does **not** silently convert a failed or absent OT export into a passed industrial-evidence check.

### 8.7. Integrity semantics are explicit

The platform now treats manifest and custody integrity as a multi-part statement rather than a binary success flag.

Scientifically important distinctions include:

- `manifest_verification_mode`
- `full_rehash_performed`
- `large_artifact_skip_enabled`
- `manifest_verification_attempted_artifacts`
- `manifest_verified_artifacts`
- `manifest_missing_artifacts`
- `custody_chain_valid`
- `integrity_verification_ratio`

This matters because:

- a case may have a valid custody chain
- and still only partial manifest verification
- because large artifacts were skipped

Therefore the reporting layer must never present:

```text
full verification
```

if the real state is:

```text
partial verification, because large artifacts were skipped
```

unless the statement is explicitly limited to custody-chain validity only.

### 8.8. OT causality is constrained by preserved evidence

The causal layer uses scenario ground truth as an expected model, but it does not treat ground truth as proof.

This is especially important in hybrid IT/OT cases.

For example:

- a Modbus write may be declared in the attack profile
- protocol presence may be observed in network artifacts
- but if no preserved OT export or PLC/SCADA state observation exists, a relation that depends on OT state confirmation must remain:
  - `missing`

It must not be softened into:

- `degraded`

unless a different preserved evidence source explicitly supports that relation.

This applies directly to edges such as:

```text
edge_ot_write_to_plc_state_observation
```

when the current artifacts contain no preserved OT export.

### 8.9. Current scientifically verified status of the available artifacts

The present artifact base has already been audited by the truthful evaluation package.

At the time of this README update, the verified state is:

- `N_A_total = 0`
  - no standalone Level A campaign exists in current artifacts
- `N_A_over_Level_B_cases = 4`
  - two Level B cases
  - two nested dry-run Level A analytical iterations per case
- `N_B_accepted = 2`
  - accepted Level B denominator remains preliminary only

Therefore:

```text
The current Level B artifacts are usable for preliminary reporting over n=2 accepted cases,
but they are not sufficient to support a final N_B=6 evaluation.
```

And the current truthful decision remains:

```text
Decision E: both fresh Level A and fresh Level B campaigns are required.
```

because:

- no standalone Level A campaign exists
- Level B accepted denominator is only `n=2`
- OT/industrial preservation is incomplete
- packet-level Modbus confirmation is incomplete
- defensible Wazuh trigger mapping is incomplete

### 8.10. When a fresh campaign is mandatory

The platform explicitly treats some fixes as **comparability-breaking**.

This means current preliminary cases must not be pooled with future post-change campaigns if the following are altered:

- acquisition or preservation behavior
- OT export preservation
- causal relation definitions
- relation weights
- metadata persistence used for comparability
- analysis or reconstruction logic that changes case metrics or relation states

In those situations:

- current cases remain valid as **preliminary audit artifacts**
- but a **fresh homogeneous campaign** is required for final paper claims

### 8.11. DFIR AUTO safety model during scientific execution

The platform now enforces a stricter separation between:

- background DFIR AUTO preservation
- campaign-controlled scientific workflows

During a running `Level A`, `Level B`, or `Level C` scientific workflow:

- the operator conflict prompt for creating a second DFIR AUTO case must not appear
- new background case creation must not silently coexist with a campaign-controlled heavy case

Outside scientific execution, if DFIR AUTO detects a new alert while a preserved case already exists, the platform can explicitly ask the operator whether to:

- keep the current case only
- delete the current case and create a new one
- allow a new case to coexist with the previous one

This decision path is auditable and is intended only for non-scientific runtime, not for active A/B/C experimentation.

### 8.12. Execution-mode honesty in Level A

The reporting layer also makes a distinction between:

- full re-execution of analytical stages
- dry-run analytical iterations
- linked existing case mode
- cached or linked outputs reused read-only

This matters because a Level A row that completes in a very short time may still be scientifically useful as a repeatability audit, but it must not be described as a full fresh analysis if it actually operated in:

```text
dry_run linked_existing_case
```

The truthful reporting package therefore carries fields such as:

- `analysis_execution_mode`
- `full_analysis_executed`
- `cached_or_linked_outputs_used`

### 8.13. Scientific rule of interpretation

The platform now follows an explicit reporting rule:

```text
A failed or missing value is acceptable if it is real and clearly reported.
A false success is not acceptable.
```

This rule applies to:

- OT preservation
- trigger mapping
- Modbus packet-level confirmation
- manifest verification
- relation support states
- denominator claims
- final paper readiness decisions

In practical terms, the platform is now designed to support:

- operational experimentation
- preservation and forensic analysis
- FOC-based reconstruction
- Level A and Level B scientific auditing
- truthful paper-table reconstruction from existing artifacts
- rerun-readiness planning when the current artifacts are not yet final-paper defensible

This is the current scientific state of FORGE-VI inside NICS CyberLab: not a promise of perfect evidence, but a framework that makes the real state of evidence, analysis, reconstruction, and limitation explicit.

### 8.14. Level B real execution orchestrator

Level B now executes a real controlled incident, not only a workspace scaffold. The distinction is explicit and enforced at the UI level:

```text
Run Dry-Run Execution  →  creates workspace, profiles, and plan artifacts only.
                           No attack, no detection wait, no case, no acquisition.

Run Real Level B Execution  →  arms DFIR auto, launches the selected attack,
                                waits for a real alert, creates a new forensic case,
                                acquires evidence in volatility order, runs the full
                                analysis/reconstruction chain, and registers a real result card.
```

The orchestrator (`app_core/infrastructure/foc_experimentation/level_b_orchestrator.py`) never marks an execution as successful unless:

- a real alert matching the attack's expected signatures was observed within the configured detection timeout
- a brand-new forensic case was created (never reuses a previous case as evidence)
- memory, network context, and disk artifacts were acquired (disk is best-effort / degraded, not fatal)
- multilayer analysis, causal reconstruction, and executive summary completed
- a real `forensic_comparison_profile.json` and `forensic_result_card.json` were generated from the actual case bundle

If no alert arrives within the detection timeout, the phase is marked `failed_detection` and no forensic case is created. The execution is never marked successful in that scenario.

The real execution requires typed confirmation `OK` before the attack is launched, consistent with the platform-wide policy for irreversible or infrastructure-touching actions (`delete_generated_case_artifacts`, `destroy_full_scenario`). `Start Selected Campaign` remains dry-run-only for Level B — it does not chain real attacks automatically.

Stage overrides in `attach_real_case_to_execution()` correct the `stage_statuses` for the phases that genuinely ran: `attack_executed`, `detection_observed`, `trigger_selected`, `acquisition_executed`, `evidence_preserved` move from `completed_with_degradation` (the linked-existing-case label) to `completed`, reflecting first-hand execution by the orchestrator.

### 8.15. Disk acquisition privilege model

Disk acquisition (`acquire_disk_kolla_libvirt.sh`) uses `sudo` locally on the compute node to access the hypervisor (virsh/libvirt/docker) for VM disk snapshots. Memory acquisition (LiME) uses SSH to the VM and does not require local sudo. This difference is structurally significant:

- memory acquisition works immediately if SSH keys and network routes are in place
- disk acquisition requires a dedicated sudoers NOPASSWD rule for the acquisition script

The platform enforces this via a single scoped rule:

```
Cmnd_Alias NICS_DFIR_DISK_HELPER = /bin/bash <repo>/app_core/infrastructure/forensics/scripts/acquire_disk_kolla_libvirt.sh *
younes ALL=(root) NOPASSWD: NICS_DFIR_DISK_HELPER
```

The script uses `/bin/bash <script>` explicitly (not `<script>` directly) in the re-exec and probe paths, because the Cmnd_Alias covers the `/bin/bash <script> *` form. `start_dashboard.sh` installs this rule automatically at section `[2.8/6]`, asking for the operator password once and never again.

The prerequisite check in `forensics_api.py` probes the script-specific command first (`sudo -n /bin/bash <script> __nics_probe__`). The generic `sudo -n true` check is a fallback only — a NOPASSWD rule covering a specific script will fail the generic test even while disk acquisition works correctly. The earlier order (generic check first, script-specific second) was the root cause of the persistent `sudo_noninteractive_unavailable` blocker despite a correctly installed rule.

### 8.16. FORGE-VI Level C workflow metrics exporter

The platform includes a dedicated exporter (`tools/forge_vi_paper_metrics_exporter.py`) that reads only verified on-disk artifacts and produces paper-ready outputs covering the full FORGE-VI workflow chain:

```text
Deploy/Redeploy → Validate → Execute → Detect → Acquire →
Preserve → Analyze → Reconstruct → Compare
```

The exporter generates seven files in `paper_exports/FORGE-VI/`:

| File | Content |
|------|---------|
| `FORGE-VI_LevelC_Workflow_Checks.csv/json` | Boolean check per run + aggregate N/N, with source_file + source_key per field |
| `FORGE-VI_LevelC_Operational_Metrics.csv` | Latencies and sizes: mean ± SD |
| `FORGE-VI_LevelC_Reconstruction_Metrics.csv` | Edges, CPR, wCPR per run |
| `FORGE-VI_LevelC_Comparison_Metrics.csv` | FSR invariant stability across runs |
| `FORGE-VI_LevelC_Paper_Tables.tex` | LaTeX table, copy-paste ready |
| `FORGE-VI_LevelC_Field_Source_Map.csv` | source_file + source_key for every field |

Design rules enforced by the exporter:

- **CPR appears only as a reconstruction diagnostic**, not as a global workflow metric. The workflow table uses boolean phase checks; CPR occupies its own `Reconstruct` row explicitly labeled `diagnostic only`.
- **Missing fields are never filled manually**. Fields without a verified source are marked `missing_from_existing_reports`. The `workflow_phase_summary.json` stub written per case lists the missing fields and the suggested target file for each, so the next pipeline run can persist them and the exporter will pick them up.
- **Every field has a declared source**. The `Field_Source_Map.csv` documents `source_file` and `source_key` for every extracted value. Cross-run derived values (FSR stability, CPR stability) are labeled `derived across all cases`.
- **Run classification is explicit**: intended runs, executed runs, accepted scientific runs, diagnostic/failed runs, excluded runs, and exclusion reasons are all separate columns.

The exporter is accessible from the `foc_paper_evidence.html` dashboard via the `Generate Level C Workflow Metrics` button (section FORGE-VI Audit), backed by `POST /api/foc/paper-evidence/level-c/workflow-metrics/run`. On page load, the existing generated files are listed automatically via `GET /api/foc/paper-evidence/level-c/workflow-metrics/files`.

**Fields currently missing from existing artifacts (require pipeline instrumentation):**

```text
teardown_completed          → metadata/workflow_phase_summary.json
redeploy_completed          → metadata/workflow_phase_summary.json
same_topology_instantiated  → metadata/workflow_phase_summary.json
deployment_time_s           → metadata/workflow_phase_summary.json
redeployment_time_s         → metadata/workflow_phase_summary.json
validation_gate_passed      → metadata/workflow_phase_summary.json
segmentation_verified       → metadata/workflow_phase_summary.json
sensor_liveness_verified    → metadata/workflow_phase_summary.json
plc_scada_reachable         → metadata/workflow_phase_summary.json
validation_time_s           → metadata/workflow_phase_summary.json
trigger_inside_attack_window → metadata/trigger_alert_binding.json
comparison_family_match     → derived/experimentation/forensic_result_card.json
```

These fields will be populated automatically by the exporter once the deployment and validation phases of the pipeline write them to `metadata/workflow_phase_summary.json` during each run.

---

## 📝 Acknowledgments

This repository has been partially supported by the project "CiberIA: Investigación e Innovación para la Integración de Ciberseguridad e Inteligencia Artificial" (Proyecto C079/23), financed by "European Union NextGeneration-EU, the Recovery Plan, Transformation and Resilience", through INCIBE. It has also been partially supported by the project SecAI (PID2022-139268OB-I00) funded by the Spanish Ministerio de Ciencia e Innovacion, and Agencia Estatal de Investigacion.
