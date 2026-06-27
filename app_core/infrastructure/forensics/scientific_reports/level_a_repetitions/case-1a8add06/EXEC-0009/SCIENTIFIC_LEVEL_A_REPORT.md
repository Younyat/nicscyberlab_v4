# Level A Scientific Report

- Generated at: `2026-06-27T10:29:36.065513+00:00`
- Campaign ID: `CMP-20260625-202744-EC4E`
- Execution ID: `EXEC-0009`
- Preserved case ID: `case-1a8add06`
- Report directory: `app_core/infrastructure/forensics/scientific_reports/level_a_repetitions/case-1a8add06/EXEC-0009`

## Executive scientific summary

This report audits a Level A repetition over the same preserved case. It reuses the same preserved evidence set in read-only mode and evaluates analytical repeatability rather than incident replay. The preserved case shows **15 / 15** analysis layers with useful output, a causal recovery of **4 / 8** expected relations, and a repeatability comparison status of **Comparable With Degradation**.

The scientific position is therefore limited but defensible: the Level A repetition shows stable analytical behavior over the preserved case, while causal completeness remains partial where alert-to-intervention, intervention-to-preservation, timestamp ordering, or packet-level Modbus specificity are not fully supported.

## Level A repetition scope

- Same preserved case: yes
- Same preserved evidence set: yes
- New attack launched: no
- New scenario execution: no
- New heavy preservation: no
- Scientific purpose: verify analytical repeatability over preserved evidence, not universal reproducibility.

## Preserved case identity

- Case ID: `case-1a8add06`
- Scenario ID: `scn-b83dbbfb`
- Source case name: `CASE-20260625-152324`
- Summary status: `stale`
- Integrity status: `completed`
- Case-wide integrity ratio: `0.9277`

## Evidence inventory

- Evidence available: `True`
- Available layers: `network, memory, disk, ot_exports, alerts, chain_of_custody, time_sync`
- Inventory summary: `{'case_digest': 16, 'custody_log': 22, 'disk_metadata': 3, 'disk_raw': 3, 'disk_sha256_file': 3, 'industrial_ot_export_modbus_tcp': 3, 'ir_input': 15, 'ir_snapshot': 1, 'memory_lime': 3, 'memory_metadata': 3, 'memory_sha256_file': 3, 'pcap': 3, 'pcap_metadata': 3, 'time_sync': 2}`

## Multilayer analysis results

- Execution status: `completed`
- Analysis confidence: `strong`
- Layers completed: `15` / `15`
- Useful output layers: `15`
- Main limitation: `Semantic reconstruction has not been generated.`

## Memory analysis results

- Memory dumps analyzed: `3`
- Interpretation: memory analysis completed and produced reusable Volatility-based outputs for the preserved dumps included in this case.

## Network analysis results

- PCAPs analyzed: `3`
- Modbus specificity summary: `The evidence supports the presence of Modbus/TCP activity toward the PLC. However, register-level and value-level causal precision remain partial because packet-level parsing does not fully confirm all Modbus parameters.`
- Packet-level limitation: `Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.`

## Disk analysis results

- Disk images analyzed: `6`
- Interpretation: disk analysis completed and contributed preserved filesystem and bodyfile outputs to the unified timeline and causal reconstruction.

## OT analysis results

- OT files analyzed: `3`
- OT evidence position: `partial`
- OT limitation: `function code, register, value, and OT state relation.`

## Alert and trigger analysis

- Alerts summarized: `696`
- Selected trigger: `ALERTA: Ping Detectado`
- Trigger source: `alert`
- Trigger selection method: `fallback_prior_alert`
- Trigger limitation: The operational acquisition trigger must not be treated as complete causal proof of the OT incident path.

## Timeline reconstruction

- Timeline entries: `228`
- Cross-layer findings: `1`

### Narrative storyline

- story step: Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here.
- story step: Protocol presence confirmed at packet level, but no write-function code (5/6/15/16) packet was found in this pcap.
- story step: IDS signature name asserts a write; not confirmed at packet level (see network layer counter-evidence).
- story step: OT export aggregates contain only read-function tallies; no setpoint or write-value content exists in this dataset.
- story step: Case-wide manifest validation is partial (0.9277); some artifacts remain hash-unvalidated.
- story step: IDS signature name asserts a write; not confirmed at packet level (see network layer counter-evidence).
- story step: Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here.

## Causal reconstruction results

- Causal status: `completed_with_degradation`
- Expected causal edges: `8`
- Recovered causal edges: `4`
- Degraded causal edges: `2`
- Missing causal edges: `2`
- CPR: `0.5`
- Weighted CPR: `0.4863`
- Reconstruction confidence: `0.6844`
- Causal interpretation confidence: `limited`
- Main limitation: `One or more expected causal edges remain missing because required preserved evidence is unavailable or not linked.`

### Recovered, degraded, and missing relations

- `edge_attack_execution_to_ot_write`: status=`recovered` | reason=`All required evidence (attack_attestation, network_modbus_observation) is present, temporal order is supported, graph-scope integrity is verified.`
- `edge_ot_write_to_network_modbus_write`: status=`recovered` | reason=`All required evidence (network_modbus_observation) is present, temporal order is not_required, graph-scope integrity is verified.`
- `edge_network_modbus_write_to_detection_surface`: status=`degraded` | reason=`Temporal order could not be verified because required timestamps could not be resolved; this edge cannot be classified as recovered.`
- `edge_ot_write_to_plc_state_observation`: status=`recovered` | reason=`All required evidence (plc_state_observation) is present, temporal order is not_required, graph-scope integrity is verified.`
- `edge_detection_surface_to_alert_observation`: status=`degraded` | reason=`Temporal order could not be verified because required timestamps could not be resolved; this edge cannot be classified as recovered.`
- `edge_alert_observation_to_forensic_case`: status=`missing` | reason=`No preserved forensic intervention matched the expected selector.`
- `edge_forensic_case_to_preserved_case_evidence`: status=`missing` | reason=`No preserved forensic intervention matched the expected selector.`
- `edge_preserved_case_evidence_to_multilayer_analysis`: status=`recovered` | reason=`All required evidence (manifest, chain_of_custody, forensic_analysis_report, analysis_visual_summary, memory_analysis_useful) is present, temporal order is supported, graph-scope integrity is verified.`

## Hypothesis support results

- Global support level: `moderate_support`
- Final claimability status: `the hypothesis can receive moderate support, not absolute causality.`
- Main limitation: `Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here.`

## Level A repeatability and comparison results

- Comparison status: `Comparable With Degradation`
- Comparison type: `direct_level_a_repeatability_comparison`
- Max |ΔCPR|: `0.0`
- Max |ΔWCPR|: `0.0`
- Max support-rank shift: `0`

## Evidence-to-claim audit table

| Claim ID | Status | Confidence | Claim |
| --- | --- | --- | --- |
| `CLAIM-LEVELA-SCOPE-READONLY` | `supported` | `strong` | This report is a Level A reanalysis of the same preserved case and does not represent a new attack, new scenario execution, or new heavy preservation event. |
| `CLAIM-LEVELA-MULTILAYER-COMPLETED` | `supported` | `strong` | The preserved case has complete multilayer analytical coverage with useful outputs across the expected layers. |
| `CLAIM-LEVELA-NETWORK-MODBUS` | `partial` | `moderate` | Network evidence confirms Modbus/TCP activity, but the current extraction layer does not fully prove packet-level register and value precision. |
| `CLAIM-LEVELA-MEMORY-COMPLETED` | `supported` | `strong` | Memory analysis completed successfully and produced reusable Volatility-based outputs for all preserved dumps included in this case. |
| `CLAIM-LEVELA-TRIGGER-LIMITATION` | `partial` | `moderate` | The operational acquisition trigger is not a complete causal proof of the OT incident path and must be interpreted separately from OT causal evidence. |
| `CLAIM-LEVELA-ALERT-INTERVENTION-PRESERVATION-CHAIN` | `partial` | `limited` | The alert-to-intervention-to-preservation chain is not fully proven by the preserved artifacts in this case. |
| `CLAIM-LEVELA-CAUSAL-PARTIAL` | `partial` | `moderate` | The causal reconstruction is partial rather than complete: some expected causal relations were recovered, some remain degraded, and some remain missing. |
| `CLAIM-LEVELA-HYPOTHESIS-MODERATE` | `partial` | `moderate` | The reconstructed incident hypothesis currently receives moderate support, not absolute causality. |
| `CLAIM-LEVELA-CPR-STABLE` | `supported` | `strong` | This Level A repetition can be compared with previous Level A executions using CPR and Weighted CPR drift metrics derived from the generated comparison profiles. |

## Limitations and degraded states

- Semantic reconstruction has not been generated.
- One or more expected causal edges remain missing because required preserved evidence is unavailable or not linked.
- Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable.
- Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here.
- 2 causal edges remain degraded due to partial support.
- Case-wide integrity remains partial.

## Scientific conclusion

The preserved evidence supports a partial causal-forensic reconstruction of a controlled OT incident. The evidence processing coverage is strong because the multilayer analysis completed and produced useful outputs across 15 layers. The causal reconstruction recovered 4 of 8 expected causal relations and degraded 2 relations due to partial or inferred evidence. The hypothesis receives moderate support, not strong support. Causal temporal ordering confidence is limited, case-wide integrity status is partial, and the stated Modbus/trigger limitations remain. The normalized Evidence Support Extract assesses the controlling hypothesis as moderate support.

The correct scientific interpretation for this Level A run is therefore:

The preserved case provides strong evidence preservation and complete multilayer analytical coverage. The Level A repetition shows stable analytical repeatability over the same preserved case. However, the causal reconstruction remains partial where alert-to-intervention, intervention-to-preservation, or Modbus register/value confirmation are not fully supported by the available evidence.

## Source files used for this report

- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/03_network/network_findings.json` | network_analysis | role: network_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/04_memory/memory_findings.json` | memory_analysis | role: memory_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/05_disk/disk_findings.json` | disk_analysis | role: disk_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/06_ot/ot_findings.json` | ot_analysis | role: ot_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/07_alerts/alert_findings.json` | alerts_analysis | role: alerts_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/09_timeline/unified_forensic_timeline.json` | timeline_analysis | role: timeline_analysis extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/10_findings/cross_layer_findings.json` | cross_layer_findings | role: cross_layer_findings extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/forensic_analysis_report.json` | analysis_report | role: multilayer analysis completeness and layer outputs
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/analysis/visual/analysis_visual_summary.json` | analysis_visual_summary | role: layer usefulness and indexed outputs
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/chain_of_custody.log` | chain_of_custody | role: custody validation and preservation linkage
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/evidence_support/claimability_report.json` | claimability_report | role: supported, partial, unsupported claim structure
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/evidence_support/counter_evidence_report.json` | counter_evidence_report | role: contradictions and counter-evidence review
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/evidence_support/forensic_storyline.json` | forensic_storyline | role: semantic readable storyline
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/evidence_support/hypothesis_support_report.json` | hypothesis_support | role: hypothesis support and claimability evaluation
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/executive/evidence_lifecycle_summary.json` | evidence_lifecycle_summary | role: evidence_lifecycle_summary extraction
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/causal_graph.json` | causal_graph | role: edge-level causal audit and degraded/missing relation review
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/causal_status.json` | causal_status | role: causal reconstruction status
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/reconstruction_metrics.json` | causal_metrics | role: causal recovery metrics
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/derived/reconstruction/uncertainty_report.json` | uncertainty_report | role: temporal and integrity uncertainty interpretation
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/manifest.json` | case_manifest | role: case identity and preserved artifact inventory
- `app_core/infrastructure/forensics/evidence_store/CASE-20260625-152324/metadata/time_sync.json` | time_sync_metadata | role: time_sync_metadata extraction
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/comparisons/comparison-b14887501661/comparability_report.md` | comparability_report | role: human-readable comparison report
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/comparisons/comparison-b14887501661/comparability_result.json` | comparability_result | role: Level A repeatability comparison status and drift metrics
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/comparisons/comparison-b14887501661/comparison_matrix.json` | comparison_matrix | role: execution row comparison matrix
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/level_A/EXEC-0009/analysis_repeatability_profile.json` | analysis_repeatability_profile | role: Level A repeatability metrics
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/level_A/EXEC-0009/forensic_comparison_profile.json` | comparison_profile | role: Level A execution comparison profile
- `app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260625-202744-EC4E/level_A/EXEC-0009/forensic_result_card.json` | forensic_result_card | role: lightweight Level A result card
