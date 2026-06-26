# Scientific Demo Report

This document is a reviewer-facing scientific demo report built from a real preserved forensic case already present in the platform workspace. It is not a generic user manual. Every claim below is tied to preserved artifacts, generated reports, or lightweight repetition/comparison outputs that can be inspected locally.

## Objective of the demo

The objective of this demo is to show what NICS CyberLab currently provides as a forensic reconstruction framework under explicit experimental conditions, using:

- one real preserved case
- the FOC Reconstruction dashboard
- the FOC Evidence Lifecycle dashboard
- the FOC Repetition Manager
- the FOC Comparability View
- the implemented attack catalog

The goal is not to claim perfect or universal reproducibility. The goal is to show:

- what evidence was preserved
- what evidence was analyzed
- what causal relations were recovered
- what remains partial, degraded, or missing
- whether repeated reanalysis over the same preserved case remains comparable

## Selected preserved case

The selected preserved case is:

- Case directory: `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324`
- Internal case ID: `case-1a8add06`
- Case creation time: `2026-06-25T15:23:24Z`
- Scenario ID: `scn-b83dbbfb`
- Scenario name: `industrial_file`
- Selected attack profile in reconstruction artifacts: `atk-6402b8e1`
- Selected MITRE technique: `T0831`
- Selected attack name: `Modbus Register Manipulation`

This case is the active preserved case referenced by:

- [app_core/infrastructure/forensics/evidence_store/_active_case.txt](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/_active_case.txt)

## Experimental context

The preserved case represents a controlled OT-oriented scenario where the reconstruction artifacts identify:

- attack family: `T0831 Manipulation of Control`
- protocol: `modbus_tcp`
- target: `PLC_Instance` / `PLC`
- expected OT operation: `write_multiple_registers`
- declared register: `4`
- declared expected value: `30`

The case-level evidence lifecycle summary states that the case is:

- overall status: `completed_with_degradation`
- evidence lifecycle status: `preserved_and_analyzed`
- multilayer analysis status: `completed`
- causal reconstruction status: `completed_with_degradation`
- forensic reconstruction confidence: `partial`
- causal interpretation confidence: `limited`

Primary source artifacts for this report:

- [manifest.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/manifest.json)
- [analysis/forensic_analysis_report.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/forensic_analysis_report.json)
- [derived/executive/evidence_lifecycle_summary.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/executive/evidence_lifecycle_summary.json)
- [derived/reconstruction/reconstruction_metrics.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/reconstruction_metrics.json)
- [derived/reconstruction/causal_graph.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/causal_graph.json)
- [derived/evidence_support/hypothesis_support_report.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/evidence_support/hypothesis_support_report.json)

## Dashboards used

This report uses the scientific outputs consumed by:

1. `FOC Reconstruction`
2. `FOC Evidence Lifecycle`
3. `FOC Repetition Manager`
4. `FOC Reconstruction Comparability View`
5. `Attacks`

## Evidence preserved

The case manifest declares `83` artifacts. The evidence inventory confirms the presence of all main layers required for a multilayer forensic study.

### Preserved evidence summary

| Layer | Count | Evidence type |
|---|---:|---|
| Network | 3 | preserved PCAPs |
| OT exports | 3 | preserved Modbus/OT exports |
| Memory | 3 | LiME memory dumps |
| Disk | 3 | final raw disk images |
| Disk support | 3 + 3 | disk metadata + disk SHA256 files |
| Memory support | 3 + 3 | memory metadata + memory SHA256 files |
| Custody | 22 | custody log artifacts |
| Time sync | 2 | time synchronization artifacts |
| IR inputs | 15 | preserved IR/operator inputs |

Representative preserved evidence paths:

- Network:
  - `network/per_vm/a495cfe7-b55b-41d0-95bf-78f9093f7fe2/pcap_a495cfe7-b55b-41d0-95bf-78f9093f7fe2_R1_20260625_152352Z.pcap`
  - `network/per_vm/8c0c86c9-2c69-424b-9080-f6c07d798787/pcap_8c0c86c9-2c69-424b-9080-f6c07d798787_R1_20260625_152421Z.pcap`
  - `network/per_vm/16583180-627d-4c40-bd65-aa9db704d75c/pcap_16583180-627d-4c40-bd65-aa9db704d75c_R1_20260625_152450Z.pcap`
- OT exports:
  - `industrial/ot_export_a495cfe7-b55b-41d0-95bf-78f9093f7fe2_R1_20260625_152352Z.json`
  - `industrial/ot_export_8c0c86c9-2c69-424b-9080-f6c07d798787_R1_20260625_152421Z.json`
  - `industrial/ot_export_16583180-627d-4c40-bd65-aa9db704d75c_R1_20260625_152450Z.json`
- Memory:
  - `memory/memdump_10.0.2.9_20260625_152512Z.lime`
  - `memory/memdump_10.0.2.22_20260625_152650Z.lime`
  - `memory/memdump_10.0.2.172_20260625_152834Z.lime`
- Disk:
  - `disk/a495cfe7-b55b-41d0-95bf-78f9093f7fe2_20260625_153018Z.disk.final.raw`
  - `disk/8c0c86c9-2c69-424b-9080-f6c07d798787_20260625_153341Z.disk.final.raw`
  - `disk/16583180-627d-4c40-bd65-aa9db704d75c_20260625_153712Z.disk.final.raw`

## FOC Reconstruction results

The FOC Reconstruction dashboard contributes the structural and evidential reconstruction context for one execution. It does not by itself prove full causal completeness.

### Structural/evidential FOC state

The current FOC dashboard status for `scn-b83dbbfb` is:

- FOC status: `valid`
- Structural/evidential completeness: `complete`
- FOC readiness score: `96.42`
- Structural maturity: `complete`
- Operational maturity: `mostly_available`
- Evidential maturity: `available`
- Forensic maturity: `completed`
- Semantic maturity: `not_generated`
- Causal reconstruction ready: `false`

Key FOC component scores:

- Scenario BOM: `15 / 15`
- Tools BOM: `15 / 15`
- Timeline: `10 / 10`
- Sources: `10 / 10`
- Hashes: `10 / 10`
- Node bindings: `10 / 10`
- Attack→Alert: `5.67 / 10`
- Alert→Evidence: `0.75 / 10`
- Evidence/Custody: `10 / 10`
- Analysis outputs: `10 / 10`

Scientific interpretation:

- the scenario structure is well reconstructed
- tooling and preserved sources are strongly indexed
- integrity/custody linkage is strong
- attack-to-alert linkage is only partial
- alert-to-evidence linkage is weak
- a high FOC readiness score does not mean that the causal explanation is complete

### Causal reconstruction results for the selected case

Case-level causal reconstruction outputs are present and completed with degradation:

- Expected causal edges: `8`
- Recovered causal edges: `4`
- Degraded causal edges: `2`
- Missing causal edges: `2`
- Ambiguous causal edges: `0`
- CPR: `0.5`
- Weighted CPR: `0.4863`
- Recoverability label: `partially_recoverable`
- Reconstruction confidence: `0.6844`
- Scientific confidence: `limited`

Recovered relations:

1. `T0831 attack execution -> Unauthorized Modbus write`
2. `Unauthorized Modbus write -> Observed Modbus write traffic`
3. `Unauthorized Modbus write -> PLC/SCADA state observation`
4. `Preserved case evidence set -> Multilayer forensic analysis`

Degraded relations:

1. `Observed Modbus write traffic -> Modbus detection surface`
2. `Modbus detection surface -> Observed correlated alerts`

Missing relations:

1. `Observed correlated alerts -> Triggered forensic intervention`
2. `Triggered forensic intervention -> Preserved case evidence set`

Why the degraded/missing edges matter:

- temporal ordering could not be resolved for some network/detection/alert edges
- the expected forensic intervention selector could not be matched strongly enough
- alert-to-evidence linkage remains weaker than custody-to-evidence linkage

### Reconstruction uncertainty

The uncertainty report shows:

- node synchronization status: `synchronized`
- worst measured node offset: `0.07 ms`
- uncertainty window: approximately `2.0 s`
- evidence timestamp availability: `partial`
- evidence timestamp resolvability: `full`
- causal temporal ordering confidence: `limited`
- case-wide integrity ratio: `0.9277`
- case-wide integrity status: `partial`

Scientific interpretation:

- the environment clocks were synchronized
- however, synchronized clocks do not guarantee that all relevant forensic artifacts expose usable timestamps for causal ordering
- causal temporal confidence is limited because timestamp availability is partial, not because the environment clocks were drifting

### Hypothesis support

The evidence support layer evaluates hypothesis `H1`:

> A controlled unauthorized Modbus manipulation was executed against the PLC and produced observable effects across network, OT, detection, acquisition, preservation, and forensic analysis layers.

Result:

- global support level: `moderate_support`
- global confidence: `moderate`
- supporting evidence atoms: `12`
- partially supporting evidence atoms: `8`
- contradictory evidence atoms: `3`
- missing required evidence atoms: `3`
- final claimability status: `the hypothesis can receive moderate support, not absolute causality`

### Final scientific interpretation from reconstruction

What the reconstruction dashboard contributes scientifically:

- it ties one preserved execution to an explicit scenario and attack context
- it shows which causal relations are recovered and which are only partial or missing
- it exposes uncertainty and integrity limitations rather than hiding them
- it supports an evidence-based partial OT causal explanation
- it does not claim full packet-level or full intervention-level causality

## Evidence Lifecycle results

The evidence lifecycle dashboard contributes the full path from preserved evidence to analyzed outputs and final scientific conclusion.

### Preservation and integrity/custody state

- Evidence lifecycle status: `preserved_and_analyzed`
- Evidence items declared: `83`
- Custody events: `25`
- Missing artifacts: `0`
- Hash-validated artifacts: `77`
- Custody chain valid: `true`

Important limitation:

- the three memory dumps and the three large final raw disk images are not rehashed again during integrity validation to avoid excessive latency
- their manifest-preserved hashes are trusted unless direct validation is feasible

### Acquisition trigger and alert evidence

The current case was triggered through:

- selected trigger: `ALERTA: Ping Detectado`
- trigger type: `alert`
- triggering alert rule: `1000001`
- trigger selection method: `fallback_prior_alert`
- candidate triggers evaluated: `51`
- stronger trigger available: `false`

Alert evidence summary:

- total alerts indexed: `696`
- alerts inside selected case window: `126`
- alerts outside case window: `570`
- confirmed attack-alert correlations in FOC detection summary: `30 / 1302`

Scientific interpretation:

- alert evidence exists and is abundant
- the selected forensic trigger is not an ideal OT-specific trigger
- the case therefore supports preserved acquisition and later analysis, but with a weaker alert-to-evidence chain than the custody and analysis layers

### Network evidence

Network analysis status: `completed`

- PCAPs analyzed: `3`
- Network tool: `tshark`
- One preserved PCAP contained `5411` total frames and `5411` Modbus frames
- Another preserved PCAP contained `16` total frames and `16` Modbus frames

Cross-layer finding produced by the platform:

> Preserved PCAP evidence and OT exports both indicate Modbus activity for this case.

This is enough to support observed Modbus activity, but not enough to claim full packet-level register/value precision for all causal statements.

### Memory evidence

Memory analysis status: `completed`

- Memory dumps analyzed: `3 / 3`
- Memory layer usefulness: `useful`
- Compatible symbols available: `yes`
- Kernel banners extracted: `yes`

Each dump completed the same Volatility 3 plugin set:

- `banners`
- `pslist`
- `sockstat`
- `lsmod`
- `check_syscall`
- `bash`

Memory therefore contributes useful host-level and process-level evidence and is not a failed or placeholder layer in this case.

### Disk evidence

Disk analysis status: `completed`

- Disk images analyzed: `6`
- Disk toolchain: `sleuthkit`

Produced outputs include:

- `mmls.txt`
- `fsstat.txt`
- `bodyfile.txt`
- `timeline.csv`
- `strings_head.txt`
- recovered evidence such as `passwd`

Disk evidence therefore contributes real post-acquisition forensic outputs, not only preserved raw images.

### OT evidence

OT export analysis status: `completed`

- OT export files analyzed: `3`
- Observed OT export records: `80`, `74`, and `0`
- Observed function codes: `3` and `1`
- Observed operation class: `non_write_function: 154`

Scientific interpretation:

- OT exports support that OT state was preserved and parsed
- they do not fully confirm register/value causality at the packet-precision level needed for stronger causal claims

### Timeline and cross-layer evidence

- Unified forensic timeline status: `completed`
- Timeline findings: `228`
- Cross-layer findings count: `1`

The multilayer analysis summary further reports:

- layers expected: `15`
- layers completed: `15`
- layers with useful output: `15`
- layers partial: `0`
- layers failed: `0`
- layers skipped: `0`

### Final scientific interpretation from lifecycle

What the lifecycle dashboard contributes scientifically:

- it proves that a complete preserved-and-analyzed case exists
- it exposes preservation, custody, integrity, time sync, network, memory, disk, OT, alerts, timeline, and cross-layer outputs in one place
- it shows that multilayer analysis succeeded technically
- it shows that technical completion still does not imply full causal completeness

## Repetition results

For the repetition demo, lightweight Level A reanalysis was used instead of heavy Level B re-execution. This is methodologically appropriate for showing analysis repeatability over the same preserved evidence.

Selected campaign:

- Campaign ID: `CMP-20260625-202744-EC4E`
- Source mode: `linked_existing_case`
- Campaign status: `completed_with_degradation`
- Technical outcome: `completed`
- Scientific outcome: `completed_with_degradation`
- Comparison readiness: `ready`
- Execution count: `6`

Selected repetitions for the demo:

| Repetition | Execution time | Source case | Status | Comparison family |
|---|---|---|---|---|
| `EXEC-0004` | `2026-06-26T22:08:45.988473+00:00` | `case-1a8add06` | `completed_with_degradation` | `family-be5078ab82847874` |
| `EXEC-0005` | `2026-06-26T22:08:57.090499+00:00` | `case-1a8add06` | `completed_with_degradation` | `family-be5078ab82847874` |
| `EXEC-0006` | `2026-06-26T22:08:57.182935+00:00` | `case-1a8add06` | `completed_with_degradation` | `family-be5078ab82847874` |

Stable findings across these Level A repetitions:

- same source case: `case-1a8add06`
- same evaluation level: `A`
- same comparison family: `family-be5078ab82847874`
- same CPR: `0.5`
- same Weighted CPR: `0.4863`
- same recovered/degraded/missing edge counts: `4 / 2 / 2`
- same global support level: `moderate_support`
- same claimability conclusion: `moderate support, not absolute causality`

Stable scientific limitations across these repetitions:

- semantic reconstruction not generated
- one or more expected causal edges remain missing
- some causal edges cannot be temporally ordered
- Modbus packet-level register/value precision remains partial
- case-wide integrity remains partial

Scientific interpretation:

- Level A reanalysis did not improve the base case
- it also did not introduce random analytical drift
- the analytical outputs remained stable across repeated reanalysis of the same preserved evidence

## Comparison results

Selected comparison:

- Comparison ID: `comparison-1f8d8ef6e067`
- Compared executions: `EXEC-0005` vs `EXEC-0006`
- Comparison result path: `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/comparisons/comparison-1f8d8ef6e067/comparability_result.json`

Comparison result:

- Status: `Comparable With Degradation`
- Comparison type: `direct_level_a_repeatability_comparison`
- Direct comparison valid: `true`
- Exploratory only: `false`
- Scenario drift: `false`

Compared metrics:

- Delta CPR allowed: `0.125`
- Delta Weighted CPR allowed: `0.10`
- Max |ΔCPR|: `0.0`
- Max |ΔWCPR|: `0.0`
- Max support-rank shift: `0`

Stable evidence and reconstruction layers across the compared repetitions:

- preserved case reference
- scenario context
- comparison family
- causal reconstruction counts
- weighted causal score
- hypothesis support level
- conclusion class

What remained limited, but stably limited:

- degraded causal edges
- partial case-wide integrity

Scientific interpretation:

- the compared Level A repetitions are not identical because the platform assumes scientific comparability, not byte-level identity
- in this specific pair, the normalized comparison outputs are numerically stable
- the result is degraded because the base case itself is scientifically limited
- this is therefore evidence of analytical repeatability with inherited limitations, not a technical failure

## Attack profiles implemented

The platform currently exposes `30` attack profiles:

- `22` Enterprise-oriented profiles
- `7` ICS-oriented profiles
- `1` composite Enterprise+ICS validation chain
- `8` profiles explicitly marked for DFIR escalation
- `4` profiles that require rollback by design

### Attack profile used by the demo case

The preserved demo case aligns with:

- Attack profile ID: `atk-6402b8e1`
- Technique: `T0831`
- Display concept: `Modbus Register Manipulation`
- Detection engine: `Suricata + Wazuh`
- Expected effect: controlled unauthorized Modbus write against the PLC
- Expected preserved artifacts: PLC state before/after, Modbus transaction log, PCAP, Suricata events, Wazuh alerts, rollback log, forensic case event

This attack is particularly useful for the project because it can generate:

- network evidence
- OT evidence
- alert evidence
- timeline evidence
- causal reconstruction candidates

### Catalog summary

The implemented attack catalog spans:

- reconnaissance
- unauthorized access
- FIM/integrity manipulation
- exfiltration
- OT/ICS manipulation
- multi-vector validation chains
- host discovery and command execution
- file discovery, collection, archiving, deletion, masquerading, obfuscation, and tool-disable simulation

Compact catalog view:

| Attack ID | MITRE | Domain | Display name | Expected forensic layers |
|---|---|---|---|---|
| `T1595_ACTIVE_SCANNING_ICMP_RECON` | `T1595` | Enterprise | ICMP Reconnaissance | network, alerts, timeline |
| `T1046_NETWORK_SERVICE_DISCOVERY_PORT_SCAN` | `T1046` | Enterprise | Port Scan Reconnaissance | network, alerts, timeline |
| `T1110_001_SSH_PASSWORD_GUESSING` | `T1110.001` | Enterprise | Unauthorized SSH Attempt | alerts, timeline |
| `T1565_001_STORED_DATA_MANIPULATION_FIM` | `T1565.001` | Enterprise | Controlled File Tamper | alerts, disk/file, timeline |
| `T1048_EXFILTRATION_OVER_ALTERNATIVE_PROTOCOL` | `T1048` | Enterprise | Data Exfiltration | network, alerts, disk/file, timeline |
| `T0831_MANIPULATION_OF_CONTROL_MODBUS` | `T0831` | ICS | Modbus Register Manipulation | network, alerts, ot |
| `CHAIN_MULTI_VECTOR_DETECTION_VALIDATION` | `MULTIPLE` | Enterprise + ICS | Multi-Vector Validation | network, alerts, ot, timeline |
| `T1105_INGRESS_TOOL_TRANSFER` | `T1105` | Enterprise | Ingress Tool Transfer | network, alerts, disk/file, timeline |
| `T1570_LATERAL_TOOL_TRANSFER` | `T1570` | Enterprise | Lateral Tool Transfer | network, timeline |
| `T0846_ICS_REMOTE_SYSTEM_DISCOVERY` | `T0846` | ICS | ICS Remote System Discovery | network, alerts |
| `T0861_POINT_AND_TAG_IDENTIFICATION` | `T0861` | ICS | Point and Tag Identification | network, alerts, ot, timeline |
| `T0802_AUTOMATED_COLLECTION` | `T0802` | ICS | Automated Collection | host |
| `T0877_IO_IMAGE` | `T0877` | ICS | I/O Image Acquisition | network, alerts, ot, host |
| `T0836_MODIFY_PARAMETER` | `T0836` | ICS | Modify Parameter | network, alerts, ot |
| `T1692_001_UNAUTHORIZED_COMMAND_MESSAGE` | `T1692.001` | ICS | Unauthorized Command Message | network, alerts, ot |
| `T1078_VALID_ACCOUNTS_SSH_LOGIN` | `T1078` | Enterprise | Valid Accounts SSH Login | alerts, host |
| `T1082_SYSTEM_INFORMATION_DISCOVERY` | `T1082` | Enterprise | System Information Discovery | host, timeline |
| `T1016_SYSTEM_NETWORK_CONFIGURATION_DISCOVERY` | `T1016` | Enterprise | System Network Configuration Discovery | timeline |
| `T1049_SYSTEM_NETWORK_CONNECTIONS_DISCOVERY` | `T1049` | Enterprise | System Network Connections Discovery | host, timeline |
| `T1057_PROCESS_DISCOVERY` | `T1057` | Enterprise | Process Discovery | host, timeline |
| `T1033_SYSTEM_OWNER_USER_DISCOVERY` | `T1033` | Enterprise | System Owner or User Discovery | host, timeline |
| `T1087_ACCOUNT_DISCOVERY` | `T1087` | Enterprise | Account Discovery | timeline |
| `T1083_FILE_AND_DIRECTORY_DISCOVERY` | `T1083` | Enterprise | File and Directory Discovery | disk/file, timeline |
| `T1005_DATA_FROM_LOCAL_SYSTEM` | `T1005` | Enterprise | Data from Local System | disk/file, timeline |
| `T1560_ARCHIVE_COLLECTED_DATA` | `T1560` | Enterprise | Archive Collected Data | disk/file, timeline |
| `T1070_004_FILE_DELETION` | `T1070.004` | Enterprise | File Deletion | alerts, disk/file, timeline |
| `T1059_COMMAND_AND_SCRIPTING_INTERPRETER` | `T1059` | Enterprise | Command and Scripting Interpreter | host |
| `T1036_MASQUERADING` | `T1036` | Enterprise | Masquerading | alerts, disk/file, timeline |
| `T1027_OBFUSCATED_FILES_OR_INFORMATION` | `T1027` | Enterprise | Obfuscated Files or Information | alerts, disk/file, timeline |
| `T1562_001_DISABLE_OR_MODIFY_TOOLS_SIMULATED` | `T1562.001` | Enterprise | Disable or Modify Tools (Simulated) | alerts, timeline |

## Cross-dashboard scientific interpretation

Across all four scientific dashboards, the case supports the following coherent interpretation:

1. A real preserved OT-oriented forensic case exists and is analyzable.
2. Preservation, custody, integrity, timeline, network, memory, disk, OT, and alert layers are available and technically usable.
3. The multilayer analysis completed successfully and produced useful outputs across all expected layers.
4. The case supports a partial causal reconstruction of a controlled Modbus manipulation scenario.
5. The hypothesis is moderately supported, not absolutely proven.
6. Repeated Level A reanalysis over the same preserved case remains numerically stable.
7. The comparison layer therefore supports methodological repeatability of the analytical pipeline over the same evidence.

What weakens the case scientifically is not the absence of preserved evidence in general, but specific linkage and precision limitations:

- weak alert-to-evidence traceability
- missing or unresolved forensic intervention linkage
- partial timestamp availability for some causal edges
- partial packet-level confirmation of Modbus register/value precision
- semantic reconstruction not yet generated

## What the project proves

Based on this real case and its repetitions, the project currently proves:

- it can preserve a real multilayer forensic case across network, memory, disk, OT, alerts, time sync, and custody layers
- it can run a complete multilayer analysis over that case
- it can expose scientific limitations explicitly instead of collapsing them into a generic success flag
- it can recover part of the expected causal structure and quantify that recovery with CPR and Weighted CPR
- it can measure uncertainty, integrity completeness, and hypothesis support
- it can reanalyze the same preserved case repeatedly and show stable normalized forensic comparison results
- it can compare repeated executions without claiming byte-level identity

## What the project only partially supports

The current demo case only partially supports:

- full causal closure from alert to forensic intervention
- strong OT-specific trigger selection
- full packet-level Modbus register/value precision
- full semantic interpretation
- absolute causal claimability

In other words, the platform supports:

- partial causal explanation
- moderate hypothesis support
- strong evidential processing
- limited causal confidence

## Current limitations

The current implementation and the selected case still show real limitations:

1. Semantic reconstruction is not generated yet.
2. Two of eight expected causal relations remain missing.
3. Two additional causal relations remain degraded because temporal order could not be resolved.
4. Alert→evidence linkage is weak at the FOC readiness layer.
5. The selected forensic trigger is a fallback alert (`ALERTA: Ping Detectado`), not a strong OT-specific trigger.
6. The case-wide integrity status is partial because large binaries are not rehashed during validation.
7. Packet-level Modbus register/value precision is only partially supported.
8. The executive lifecycle summary may remain marked `stale` even when newer causal artifacts already exist; this is a dashboard/report synchronization limitation, not evidence loss.
9. Scientific memory currently allows later reanalysis registrations to overwrite the lightweight case-to-execution association for the preserved case; immutable origin provenance should be hardened.

## Reviewer-facing conclusions

Reviewer-facing conclusion:

NICS CyberLab already supports a defendable forensic reconstruction workflow based on preserved evidence, multilayer analysis, quantified causal reconstruction, uncertainty reporting, and methodological repeatability checks.

The strongest claim supported by the current demo is:

> Under documented experimental conditions, the platform can preserve and analyze a real OT-oriented case, recover part of the expected causal structure, quantify what remains degraded or unsupported, and show that repeated reanalysis of the same preserved case yields comparable normalized reconstruction results.

The project should not currently claim:

- universal reproducibility
- complete causal certainty
- full semantic reconstruction
- perfect alert-to-evidence traceability
- packet-level OT causality in every detail

The scientifically honest claim is narrower and stronger:

> The platform is a reproducible forensic reconstruction framework under explicit experimental conditions, with measurable evidence lifecycle outputs, repeatable Level A reanalysis, and traceable cross-execution comparison, while keeping uncertainty, degradation, and unsupported claims visible.

## Appendix

### Case and report IDs

- Preserved case directory: `CASE-20260625-152324`
- Internal case ID: `case-1a8add06`
- Scenario ID: `scn-b83dbbfb`
- Analysis ID: `analysis-23e5e40342a0`
- Selected repetition campaign: `CMP-20260625-202744-EC4E`
- Selected comparison: `comparison-1f8d8ef6e067`

### Key artifact paths

- [manifest.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/manifest.json)
- [analysis/forensic_analysis_report.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/forensic_analysis_report.json)
- [analysis/analysis_status.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/analysis_status.json)
- [analysis/01_integrity_custody/integrity_custody_report.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/01_integrity_custody/integrity_custody_report.json)
- [analysis/03_network/network_findings.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/03_network/network_findings.json)
- [analysis/04_memory/memory_findings.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/04_memory/memory_findings.json)
- [analysis/05_disk/disk_findings.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/05_disk/disk_findings.json)
- [analysis/06_ot/ot_findings.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/06_ot/ot_findings.json)
- [analysis/07_alerts/alert_findings.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/07_alerts/alert_findings.json)
- [analysis/09_timeline/unified_forensic_timeline.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/09_timeline/unified_forensic_timeline.json)
- [derived/reconstruction/causal_graph.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/causal_graph.json)
- [derived/reconstruction/reconstruction_metrics.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/reconstruction_metrics.json)
- [derived/reconstruction/uncertainty_report.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/uncertainty_report.json)
- [derived/evidence_support/hypothesis_support_report.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/evidence_support/hypothesis_support_report.json)
- [derived/executive/evidence_lifecycle_summary.json](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/executive/evidence_lifecycle_summary.json)
- [repetition execution EXEC-0005 result card](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/level_A/EXEC-0005/forensic_result_card.json)
- [repetition execution EXEC-0006 result card](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/level_A/EXEC-0006/forensic_result_card.json)
- [comparability result](/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/comparisons/comparison-1f8d8ef6e067/comparability_result.json)

### Screenshots

Generic dashboard UI screenshots already present in the repository:

- `Images_readme/forensic_acquisition_dashboard.png`
- `Images_readme/forensic_acquisition_dashboard_2.png`
- `Images_readme/forensic_live_traffic_analyzer.png`

These are UI illustrations, not primary scientific evidence artifacts. For reviewer defense, the JSON/MD artifacts listed above should be treated as the primary evidence base.
