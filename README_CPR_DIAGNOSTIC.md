# FORGE-VI — Causal Reconstruction Diagnostic: CPR = 0.500

**Campaign:** CMP-20260707-000220-CBFB  
**Date:** 2026-07-07  
**N repetitions evaluated:** 6 (EXEC-0001 – EXEC-0006)  
**CPR:** 0.500 (4 recovered / 8 expected edges) — stable, σ = 0.000  
**WCPR:** 0.4863  
**Recoverability label:** `partially_recoverable`  

This document is a precise technical diagnostic of the causal reconstruction results.
It is intended to support the scientific discussion section of the paper.
It does not modify results or force any edge to a state not supported by evidence.

---

## 1. The eight causal edges: state, evidence, and decision source

The ground-truth causal graph declares eight directed edges (e1–e8).
Their states are **identical across all six repetitions** (std = 0.0), which means the result
reflects a structural property of the current platform configuration, not run-to-run variance.

The decision algorithm is in:
`app_core/infrastructure/foc_causal_reconstruction/evaluators/edge_evaluator.py`

Decision tree (simplified):

```
if missing_evidence                         → missing
elif temporal_status in {ambiguous,
                         contradicted}      → ambiguous
elif any requirement degraded or ambiguous  → degraded
elif temporal_status == unknown             → degraded   ← key constraint
else                                        → recovered

structural guarantee:
  if support_status == recovered
     AND temporal_status not in {supported,
                                 not_required}  → downgrade to degraded
```

---

### e1 — Attack Execution → OT Modbus Write

| Field | Value |
|---|---|
| Edge ID | `edge_attack_execution_to_ot_write` |
| **State** | **recovered** |
| Required evidence | `attack_attestation`, `network_modbus_observation` |
| Evidence found | Both present. FC=16 (write_multiple_registers) confirmed in OT export. 8 FC=16 records across 3913+ total Modbus records. |
| Missing evidence | None |
| Temporal status | `not_required` |
| Decision source | `causal_graph.json` in each retained bundle → `support_status: recovered` |
| Authoritative file | `derived/reconstruction/causal_graph.json`, `analysis/06_ot/ot_findings.json` |

---

### e2 — OT Modbus Write → Observable Network Traffic

| Field | Value |
|---|---|
| Edge ID | `edge_ot_write_to_network_modbus_write` |
| **State** | **recovered** |
| Required evidence | `network_modbus_observation` |
| Evidence found | Modbus TCP traffic confirmed in `network_findings.json`. IT→OT conduit 192.168.100.x → 10.0.2.22:502. |
| Missing evidence | None |
| Temporal status | `not_required` (network traffic is observational corollary of the OT write, not a downstream effect that requires ordering) |
| Decision source | `causal_graph.json` → `support_status: recovered` |

---

### e3 — Observable Network Traffic → Detection Surface ⚠️ DEGRADED

| Field | Value |
|---|---|
| Edge ID | `edge_network_modbus_write_to_detection_surface` |
| **State** | **degraded** |
| Required evidence | `attack_attestation`, `detection_attestation` |
| Evidence found | Both artifacts present. Wazuh rule 910836102 matched. Suricata active on the monitored segment. |
| Missing evidence | None (semantic gate passed) |
| **Temporal status** | `unknown` |
| **Degradation reason** | The timestamp linking the network-level Modbus event (sourced from the PCAP incident window) to the Wazuh detection surface event cannot be resolved with sufficient precision. The network event timestamp comes from the rolling PCAP import (`network_context_manifest.json`), while the Wazuh detection timestamp is logged via the SIEM collector with second-level granularity. The two clocks are not normalized to the same reference in `normalized_causal_timestamps.json` for this sub-event pair. The causal evaluator cannot verify that the detection surface observation occurred **after** the network event, so it applies the `unknown → degraded` rule. |
| Timestamps present | PCAP anchor: `2026-07-07T01:10:30Z` (case window midpoint). Wazuh alert: `2026-07-07T01:10:30.017+0000`. The ~17 ms difference is within SIEM polling granularity — causality cannot be inferred. |
| Timestamps missing | Sub-event timestamp for the moment the Modbus packet was **observed by the IDS/SIEM pipeline** (distinct from the moment the alert was emitted). Suricata event timestamp at rule match is not exported to the normalized timestamp chain. |
| Clock sync state | `temporal_sync_status` verified for nodes, but max clock offset exists across VM nodes; offset is not propagated into the causal edge evaluator for this pair. |
| **Root cause classification** | **Temporal granularity limitation + IDS/SIEM timestamp normalization gap.** The evidence exists. The causal link is semantically valid. The degradation is a deliberate conservative decision by the evaluator: it does not infer temporal order it cannot verify. |
| Authoritative files | `causal_graph.json` → `temporal_status: unknown`; `normalized_causal_timestamps.json`; `metadata/time_sync.json`; `network/traffic_preserved/network_context_manifest.json` |

---

### e4 — OT Modbus Write → PLC State Observation

| Field | Value |
|---|---|
| Edge ID | `edge_ot_write_to_plc_state_observation` |
| **State** | **recovered** |
| Required evidence | `ot_findings`, `attack_attestation` |
| Evidence found | `ot_findings.json` confirms FC=16 payload reached PLC (10.0.2.22:502). 8 write_multiple_registers events confirmed in 3913+ OT export records. |
| Missing evidence | None |
| Temporal status | `not_required` |
| Decision source | `causal_graph.json` → `support_status: recovered` |

---

### e5 — Detection Surface → Alert Observation ⚠️ DEGRADED

| Field | Value |
|---|---|
| Edge ID | `edge_detection_surface_to_alert_observation` |
| **State** | **degraded** |
| Required evidence | `detection_attestation`, `alert_correlation` |
| Evidence found | Both present. Wazuh emitted alert ID `9c70837b8a1d4c06ab19c2b9d5cc8ae0` (EXEC-0002), severity HIGH, rule 86601 ("ALERTA: Ping Detectado") matched by the alert collector; rule 910836102 ("NICS CyberLab ICS Modbus write multiple registers") matched by the trigger selector. 33 alerts indexed. |
| Missing evidence | None (semantic gate passed) |
| **Temporal status** | `unknown` |
| **Degradation reason** | The timestamp chain from the detection surface event (moment the IDS/SIEM pipeline registers the Modbus anomaly as a detection surface hit) to the alert observation event (moment the orchestrator polls and matches the qualifying alert) is not fully normalized. `normalized_causal_timestamps.json` records `alert_observed_at_utc` but does not record `detection_surface_event_at_utc` as a separate, independently sourced timestamp. The two events are represented by the same timestamp, making temporal ordering non-inferrable (the evaluator sees a zero-delta, which it classifies as `unknown` rather than `supported`). |
| Timestamps present | `alert_observed_at_utc: 2026-07-07T01:10:30.017+0000`. Detection attestation timestamp: same value (propagated from alert). |
| Timestamps missing | An independent `detection_surface_hit_at_utc` sourced from the IDS engine log (Suricata or Wazuh manager log) before the alert is emitted and polled. |
| Detection trigger detail | Rule 910836102 selected via `reason_for_selection: fallback_prior_alert`, score=410, 10,102 candidates evaluated. The use of a fallback selection means the trigger was matched retrospectively from the alert store, not from a live Suricata event stream — this is why the IDS-level and SIEM-level timestamps collapse to the same value. |
| **Root cause classification** | **IDS/SIEM timestamp normalization gap + retrospective trigger selection strategy.** The detection surface was active and generated a qualifying alert. The degradation reflects that the platform's current alert-polling model does not export the IDS-engine-level timestamp separately from the SIEM alert timestamp. This is a **methodological decision in the acquisition profile**, not a failure of detection. |
| Authoritative files | `causal_graph.json` → `temporal_status: unknown`; `normalized_causal_timestamps.json`; `metadata/pipeline_events.jsonl` → `alert` event; `detection_trigger_profile.json` → `reason_for_selection: fallback_prior_alert` |

---

### e6 — Alert Observation → Forensic Case ❌ MISSING

| Field | Value |
|---|---|
| Edge ID | `edge_alert_observation_to_forensic_case` |
| **State** | **missing** |
| Required evidence | Explicit causal link: `triggering_alert_id` → `case_id` in a shared artifact that the causal selector can resolve |
| **Evidence in forensic_intervention.json** | `triggering_alert_id: 9c70837b8a1d4c06ab19c2b9d5cc8ae0`, `case_id: case-4bd7a2e5`. **Both fields exist in the file.** |
| **Why missing then?** | The causal edge evaluator expects the link between alert and forensic case to be asserted through the **`alert_correlation.json` or `alert_correlation_summary.json` artifact under the `analysis/` layer**, where the alert ID is cross-referenced against the case ID with a confirmed causal binding. In the current artifacts, `alert_findings.json` indexes 33 alerts by Wazuh rule 86601 (ICMP ping), not by rule 910836102 (Modbus write) — the qualifying trigger rule. The selector cannot resolve the alert→case link through the analysis layer because the alert indexed in `alert_findings.json` belongs to a different Wazuh rule than the one selected by `detection_trigger_profile.json`. |
| Evidence present but not linked | `forensic_intervention.json` → `triggering_alert_id` field. `pipeline_events.jsonl` → `alert` event with matching timestamp. `chain_of_custody.log` → case creation event. `case_manifest_link.json` → case_id present. |
| Evidence absent | A cross-reference entry in the analysis-layer alert correlation output that binds rule 910836102 alert → `case-4bd7a2e5` in a form the causal evaluator can traverse. |
| **Root cause classification** | **Evidence present but not linked causally.** The alert that triggered acquisition (rule 910836102, Modbus write) and the alerts indexed by the post-preservation analysis layer (rule 86601, ICMP ping) are **different Wazuh rules**. The analysis layer runs over preserved alert artifacts and finds rule 86601 alerts. The trigger selector matched rule 910836102 via fallback. The causal evaluator cannot close the alert→case link because the analysis-layer output and the trigger-layer output reference different alert rule IDs. This is **not a bug in evidence preservation** — both artifacts exist. It is a **semantic gap between the trigger selection strategy (fallback, rule 910836102) and the post-analysis alert indexing (rule 86601)**. |
| Authoritative files | `metadata/forensic_intervention.json` → `triggering_alert_id`, `triggering_alert_rule_id: 86601`; `analysis/07_alerts/alert_findings.json` → rule 86601 alerts only; `detection_trigger_profile.json` → `selected_trigger_rule: 910836102`; `causal_graph.json` → `support_status: missing`, `missing_evidence: [alert_to_case_causal_link]` |

---

### e7 — Forensic Case → Preserved Case Evidence ❌ MISSING

| Field | Value |
|---|---|
| Edge ID | `edge_forensic_case_to_preserved_case_evidence` |
| **State** | **missing** |
| Required evidence | Explicit causal link: `case_id` → `preserved_case_directory` → `manifest.json` in a form the causal selector can resolve as a directed artifact dependency |
| Evidence present | `manifest.json` present. `chain_of_custody.log` present (21 entries, SHA256-chained). Memory artifacts (3 VMs, 4.3 GB). 20 PCAP segments. OT export (3916 records). `forensic_intervention.json` → `preserved_evidence_categories` present. `disk: false` (acquisition error on all 10 repetitions). |
| **Why missing?** | The causal evaluator expects a structured `case_to_evidence_binding` record in the analysis layer that declares `case_id → artifact_category → artifact_path → hash` as a verified directed dependency. This binding is generated by the evidence-linkage sub-module **only when disk acquisition succeeds**. Because `disk: false` in `forensic_intervention.json` for all 10 repetitions of the current campaign, the sub-module marks the case→evidence link as incomplete and the causal selector cannot promote the edge to `recovered` or `degraded` — it resolves to `missing`. |
| Evidence present but not linked | `chain_of_custody.log` contains acquisition events for memory and network. `manifest.json` lists memory and network artifacts. The case→evidence causal link exists in practice (case was created, evidence was preserved) but the structured binding artifact expected by the evaluator was not generated due to disk failure. |
| **Root cause classification** | **Acquisition strategy limitation + evidence present but not linked.** Disk acquisition failed in all repetitions (`disk=error` in acquisition completion status). The causal evaluator's binding sub-module requires disk acquisition completion to generate the `case_to_evidence_binding` record. Memory and network evidence is correctly preserved and chained, but the edge evaluation logic treats the absent disk binding as a missing causal artifact and classifies the edge as `missing`. This is a **conservative methodological decision**: the evaluator does not infer a complete case→evidence link when one acquisition category failed, even if others succeeded. |
| Note on temporal_status | The CPR aggregate reports `temporal_status: supported` for this edge (the causal ordering of case creation → preservation is verified), but the missing evidence gate fires before temporal evaluation reaches the state assignment step. |
| Authoritative files | `metadata/forensic_intervention.json` → `preserved_evidence_categories.disk: false`; `manifest.json`; `chain_of_custody.log`; `causal_graph.json` → `support_status: missing`, `missing_evidence: [case_to_evidence_binding]` |

---

### e8 — Preserved Case Evidence → Multilayer Analysis

| Field | Value |
|---|---|
| Edge ID | `edge_preserved_case_evidence_to_multilayer_analysis` |
| **State** | **recovered** |
| Required evidence | `forensic_analysis_report`, `analysis_visual_summary`, `memory_findings` |
| Evidence found | All present. 12–14 analysis layers executed over preserved artifacts. Memory findings, network findings, OT findings, alert findings, integrity/custody report — all indexed. |
| Missing evidence | None |
| Temporal status | `supported` |
| Decision source | `causal_graph.json` → `support_status: recovered` |

---

## 2. Degraded edges (e3, e5) — detailed temporal breakdown

| Field | e3 (Network → Detection) | e5 (Detection → Alert) |
|---|---|---|
| Temporal status | `unknown` | `unknown` |
| Evidence semantically present | Yes | Yes |
| Timestamps in `normalized_causal_timestamps.json` | `alert_observed_at_utc` | `alert_observed_at_utc` |
| Missing timestamp | `network_event_observed_at_utc` (IDS-level) | `detection_surface_hit_at_utc` (SIEM-engine-level) |
| Timestamp granularity | 1 ms (PCAP anchor) vs 1 s (Wazuh event) | Sub-ms (orchestrator poll) vs 1 s (SIEM event) |
| Clock sync uncertainty | max_clock_offset not propagated to edge evaluator | Same |
| Uncertainty window applied | Evaluator does not apply a fuzzy window: `unknown` is the hard result when ordering cannot be verified | Same |
| IDS/SIEM source | Wazuh (HIDS/SIEM) + Suricata (network IDS) | Wazuh alert collector |
| Retrospective trigger | Rule 910836102 matched via `fallback_prior_alert`, collapsing IDS-level and SIEM-level timestamps to same value | Same fallback mechanism |
| **Root cause** | Suricata does not export its rule-match timestamp to `normalized_causal_timestamps.json` | `detection_surface_hit_at_utc` not recorded as distinct from `alert_observed_at_utc` |
| **What would fix it** | Export Suricata event timestamp at rule-match level to the timestamp normalizer, independent of SIEM alert emission | Record `detection_surface_event_at_utc` from Wazuh manager log (before alert is polled by the orchestrator) as a separate field |

---

## 3. Missing edges (e6, e7) — artifact existence vs. causal linkage

### Does `forensic_intervention.json` exist?

**Yes.** Path (EXEC-0002 example):
```
app_core/infrastructure/forensics/evidence_store/repetition_campaigns/
CMP-20260707-000220-CBFB/level_B/EXEC-0002/
retained_case_lightweight_bundle/case-4bd7a2e5/
metadata/forensic_intervention.json
```

Content includes: `triggering_alert_id`, `triggering_alert_rule_id: 86601`, `case_id`, `intervention_started_at`, `selected_actions`, `preserved_evidence_categories`, `intervention_status: completed`.

### Why is e6 still missing?

The causal evaluator resolves the alert→case link through the **analysis-layer alert correlation artifact**, not through `forensic_intervention.json` directly. The analysis layer indexes alerts by Wazuh rule 86601 (ICMP ping), while the trigger was matched by rule 910836102 (Modbus write). These are two different Wazuh rules. The evaluator finds no analysis-layer artifact that binds rule 910836102 alert → case_id, so the edge is classified as `missing`.

**The intervention happened. The causal link artifact for the specific trigger rule is absent from the analysis layer.**

### Why is e7 still missing?

The case was created and evidence was preserved (memory + network). The `case_to_evidence_binding` structured record expected by the evaluator is generated only when disk acquisition completes. Disk acquisition failed (`disk: false`) in all 10 repetitions of the current campaign due to VM-level disk I/O errors. The evaluator applies a conservative gate: incomplete acquisition category → no binding record → edge `missing`.

**Evidence for memory and network is present and chained. The edge is missing because the binding sub-module requires full acquisition success to emit the structured linkage artifact.**

---

## 4. Cause classification per edge

| Edge | State | Primary cause | Secondary cause |
|---|---|---|---|
| e1 | recovered | — | — |
| e2 | recovered | — | — |
| e3 | degraded | Temporal granularity limitation | IDS/SIEM timestamp normalization gap (Suricata event not exported to normalizer) |
| e4 | recovered | — | — |
| e5 | degraded | IDS/SIEM timestamp normalization gap | Retrospective trigger selection strategy (fallback collapses timestamps) |
| e6 | missing | Evidence present but not linked (different Wazuh rules in trigger vs. analysis layer) | Retrospective trigger selection strategy |
| e7 | missing | Acquisition strategy limitation (disk failure) | Evidence present but not linked (binding sub-module gated on full acquisition) |
| e8 | recovered | — | — |

---

## 5. Workflow execution verification

| Step | Executed | Status | Evidence |
|---|---|---|---|
| Controlled OT attack (T0831 Modbus write) | ✅ | Completed each repetition | `attack_attestation.json`, attack output directories |
| Alert / trigger observation | ✅ | Wazuh HIGH alert matched (rule 910836102 via fallback) | `detection_trigger_profile.json`, `pipeline_events.jsonl` → `alert` event |
| Acquisition profile selection | ✅ | `default_kolla_lime_tshark_v1` | `forensic_intervention.json` → `acquisition_profile_id` |
| Memory-first acquisition (LiME) | ✅ | 3 VMs, ~4.3 GB each repetition | `manifest.json`, `pipeline_events.jsonl` → `memory_preserved` |
| Rolling PCAP incident-window import | ✅ | 20 segments per repetition, 120 s context window | `network_context_manifest.json`, `pipeline_events.jsonl` |
| Memory preservation | ✅ | Sealed and hashed | `chain_of_custody.log`, `manifest.json` |
| Disk preservation | ❌ | Failed all 10 repetitions (`disk=error`) | `forensic_intervention.json` → `preserved_evidence_categories.disk: false` |
| Network preservation | ✅ | PCAP context preserved | `manifest.json` → network entries |
| OT export preservation | ✅ | 3913+ Modbus records including 8 FC=16 writes | `ot_findings.json`, `manifest.json` → industrial entries |
| Alert preservation | ✅ | 33 alerts indexed (rule 86601) | `alert_findings.json` |
| Manifest | ✅ | Present and verified | `manifest.json` |
| Chain of custody | ✅ | 21 entries, SHA256-chained | `chain_of_custody.log` |
| Post-preservation analysis | ✅ | 12–14 layers executed | `forensic_analysis_manifest.json` |
| Causal reconstruction | ✅ | Ran to completion, CPR=0.500 | `causal_graph.json`, `FORGE-VI_LevelC_CPR_Aggregate.json` |

---

## 6. Consistency with the platform's experimental philosophy

The platform does not impose a binary success/failure judgment on the forensic workflow. It reports:

- **Recovered** — the causal link is evidentially supported with resolved temporal ordering.
- **Degraded** — the causal link is semantically valid and evidence exists, but temporal ordering or evidence quality is insufficient for a full recovery classification. The uncertainty is preserved explicitly.
- **Missing** — the causal link cannot be asserted from the available artifact set, either because a required artifact is absent or because a binding between existing artifacts could not be resolved by the current analysis-layer logic.

The CPR=0.500 result is **methodologically consistent** with this philosophy:

- The platform preserves and reports uncertainty rather than smoothing it.
- e3 and e5 are degraded because the evaluator encountered `temporal_status: unknown`, not because detection failed. Detection worked. The degradation reflects a current limitation in timestamp export granularity from Suricata and the Wazuh event pipeline.
- e6 and e7 are missing not because forensic intervention did not occur, but because the **causal linking artifacts** expected by the evaluator were either absent (disk binding) or mismatched at the rule-ID level (alert correlation). The platform correctly identifies this as an unresolved causal link.
- CPR=0.500 is stable (std=0.0) across six independent repetitions, which confirms that the result reflects **structural properties of the current configuration**, not run-to-run variance or noise.

Changing the acquisition profile, the trigger selection strategy, the Suricata timestamp export, or the disk acquisition target would be legitimate experimental interventions that could shift CPR — and the platform would report any change honestly.

---

## 7. Technical conclusion

### What worked correctly

- Full volatile-first acquisition pipeline (memory → network import → OT export) executed successfully across all repetitions.
- Attack execution and OT-layer causal chain (e1, e2, e4) fully recovered with high confidence.
- Post-preservation multilayer analysis (e8) fully recovered.
- Chain of custody, manifest, and integrity verification passed.
- CPR result is reproducible and stable (std=0.0 over 6 reps).

### What was degraded (e3, e5)

Temporal ordering of Network→Detection→Alert could not be verified. Evidence is present. The degradation is caused by:

1. Suricata rule-match timestamp not exported to the normalized timestamp chain.
2. The fallback trigger selection strategy collapses the IDS-engine-level and SIEM-polling-level timestamps to the same value, making temporal ordering non-inferrable.

### What was missing (e6, e7)

Two causal link artifacts could not be resolved:

1. **e6:** The alert that triggered acquisition (Wazuh rule 910836102) was not indexed by the analysis-layer alert correlation output (which indexed rule 86601 alerts). The trigger→case binding artifact was absent from the analysis layer.
2. **e7:** Disk acquisition failed in all repetitions. The `case_to_evidence_binding` record, gated on full acquisition completion, was never generated. Memory and network evidence is correctly preserved.

### Most probable causes

| Cause | Affects |
|---|---|
| Disk acquisition error (VM I/O level) | e7 missing |
| Fallback trigger selection (rule 910836102) not indexed by post-analysis alert layer (rule 86601) | e6 missing |
| Suricata event timestamp not exported to `normalized_causal_timestamps.json` | e3 degraded |
| No independent `detection_surface_hit_at_utc` field in timestamp normalizer | e5 degraded |

### What to change in the next campaign to test CPR improvement (without altering results artificially)

| Change | Expected effect |
|---|---|
| Fix disk acquisition at VM level (storage, LiME + dd target) | e7: `missing → degraded` or `recovered` if binding record is generated |
| Align post-analysis alert indexing to include rule 910836102 (not only rule 86601) | e6: `missing → degraded` or `recovered` if alert→case binding resolves |
| Export Suricata rule-match timestamp as `suricata_event_at_utc` to the timestamp normalizer | e3: `degraded → recovered` if temporal ordering can be verified |
| Record `detection_surface_hit_at_utc` from Wazuh manager log independently of SIEM poll timestamp | e5: `degraded → recovered` if the IDS-level and SIEM-level timestamps can be separated |

If all four changes succeed, theoretical upper bound is **CPR = 1.000** (8/8 recovered).
Each change is independently testable and produces a verifiable, auditable delta in CPR.

---

## Key files referenced

| Purpose | Path |
|---|---|
| CPR aggregate result | `paper_exports/FORGE-VI/FORGE-VI_LevelC_CPR_Aggregate.json` |
| Edge-level CPR detail | `paper_exports/FORGE-VI/FORGE-VI_LevelC_CPR_Edge_Matrix.json` |
| CPR diagnostics | `paper_exports/FORGE-VI/FORGE-VI_LevelC_CPR_Diagnostics.json` |
| Causal graph (per execution) | `…/retained_case_lightweight_bundle/<case_id>/derived/reconstruction/causal_graph.json` |
| Edge decision logic | `app_core/infrastructure/foc_causal_reconstruction/evaluators/edge_evaluator.py` |
| Forensic intervention | `…/metadata/forensic_intervention.json` |
| Trigger profile | `…/level_B/<exec_id>/detection_trigger_profile.json` |
| Normalized timestamps | `…/metadata/normalized_causal_timestamps.json` |
| Pipeline events | `…/metadata/pipeline_events.jsonl` |
| Chain of custody | `…/chain_of_custody.log` |
| Alert findings | `…/analysis/07_alerts/alert_findings.json` |
| OT findings | `…/analysis/06_ot/ot_findings.json` |
| Level B structured metrics | `…/validation_reports/level_b_repetition_report_2026-07-07T000229.258093_0000/level_b_structured_metrics.json` |
