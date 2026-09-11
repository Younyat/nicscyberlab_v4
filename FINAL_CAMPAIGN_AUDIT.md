# FINAL_CAMPAIGN_AUDIT — CMP-20260903-083211-125A

Read-only audit. No source files, results, or historical values were modified, regenerated, or deleted to produce this report. Every claim below cites the file path, execution/case ID, JSON field, or function it was read from. Where evidence does not fully support a clean conclusion, this is stated explicitly rather than resolved by assumption.

---

## 1. Unambiguous campaign identity

| Field | Value | Source |
|---|---|---|
| campaign_id | `CMP-20260903-083211-125A` | `evidence_store/repetition_campaigns/CMP-20260903-083211-125A/campaign_manifest.json` |
| Level C job_id | `LC-20260903-083211-88F7` | `runtime/level_c_jobs/LC-20260903-083211-88F7/job_state.json` |
| scenario_id / name | `industrial_file` (ground-truth scenario `scn-b83dbbfb`) | `campaign_config.json`, `derived/reconstruction/causal_status.json:ground_truth_summary.scenario_id` |
| attack_profile | `T0831_MANIPULATION_OF_CONTROL_MODBUS` | `campaign_config.json:attack_id` |
| acquisition_profile_id | `default_kolla_lime_tshark_v1` | `campaign_config.json` |
| analysis_profile_id | `default_multilayer_analysis_v1` | `campaign_config.json` |
| foc_profile_id | `default_foc_causal_reconstruction_v1` | `campaign_config.json` |
| number_of_executions | 10 | `EXEC-0001`…`EXEC-0010`, each with its own `case-*` and `causal_graph.json` |
| execution_ids | EXEC-0001…EXEC-0010 (global paper_exports IDs `run_94`…`run_103`) | `level_B/EXEC-000N/`, cross-referenced in `paper_exports/FORGE-VI/FORGE-VI_LevelC_Operational_Metrics.csv` |
| campaign start | `2026-09-03T08:32:11Z` | `campaign_manifest.json:created_at`, `job_state.json:started_at` |
| campaign end (last update) | `2026-09-03T22:42:36Z` | `campaign_manifest.json:updated_at` |
| software commit at run time | `e63d95b51a19b3e69b4219ecdfbbfb1538a90b83` (2026-07-31) — nearest commit before the run; **could not verify there were zero uncommitted local changes live at runtime** | `git log --before="2026-09-04"` |
| causal-model / ground-truth version | `ground_truth_version: "1.0"` | `scenarios/scn-b83dbbfb/scenario_ground_truth.json` |
| reconstruction algorithm version | **NOT AVAILABLE** — no version/schema field is embedded in `causal_graph.json` or `foc_causal_reconstruction/config.py`; only the git commit hash above can serve as a version proxy | checked `causal_graph.json` top-level keys (`case_id, scenario_id, generated_at, note, nodes, edges` — no version key); grepped `config.py` for `VERSION`/`__version__` — no match |
| comparison/evaluation version | **NOT AVAILABLE** — same as above | — |

**Confirmations:**
- Is this the single campaign that should be reported in the revised paper? **YES** — it is the only campaign with 10 executions, one degraded (e4) and stable ambiguity (e5), matching the paper's revised (green) narrative.
- Are all values in this report derived only from this campaign? **YES**, except where explicitly marked otherwise (Section 12).
- Are any of the values *currently printed in the paper draft* inherited from an earlier/different source? **YES** — see Section 12. None of the raw per-execution facts in Sections 2–9 are inherited; several Table 18 numbers are.

---

## 2. Causal result per execution (recomputed directly from `causal_graph.json`, not the dashboard)

| execution_id | e1 | e2 | e3 | e4 | e5 | e6 | e7 | e8 | recovered | degraded | ambiguous | missing | CPR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| EXEC-0001 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |
| EXEC-0002 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |
| EXEC-0003 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |
| EXEC-0004 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |
| EXEC-0005 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |
| **EXEC-0006** | recovered | recovered | recovered | **degraded** | ambiguous | recovered | recovered | recovered | 6 | 1 | 1 | 0 | **0.75** |
| EXEC-0007 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |
| EXEC-0008 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |
| EXEC-0009 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |
| EXEC-0010 | recovered | recovered | recovered | recovered | ambiguous | recovered | recovered | recovered | 7 | 0 | 1 | 0 | 0.875 |

Source: `derived/reconstruction/causal_graph.json`, field `edges[*].support_status`, matched by `edge_id`, for each of the 10 case directories under `level_B/EXEC-000N/retained_case_lightweight_bundle/case-*/`. `CPR = recovered/8`, computed here, cross-checked against `derived/reconstruction/causal_status.json:metrics_preview.causal_path_recoverability` (matches exactly for all 10).

**Aggregate (computed here from the table above, not the dashboard):**
- CPR mean = **0.8625**
- CPR sample standard deviation (n−1) = **0.039528** ≈ **0.0395**
- CPR min = 0.75, CPR max = 0.875
- Distribution: {0.875: 9, 0.75: 1}
- Recovered per run: 7 (×9), 6 (×1)
- Degraded per run: 0 (×9), 1 (×1)
- Ambiguous per run: 1 (×10)
- Missing per run: 0 (×10)

**Confirmation against the target claims:**

| Claim | Result |
|---|---|
| 9 executions CPR=0.875, 1 execution CPR=0.750 | **CONFIRMED** |
| mean CPR = 0.8625 | **CONFIRMED** |
| sample SD ≈ 0.0395 | **CONFIRMED** (0.039528) |
| e4 = recovered 9/10, degraded 1/10 | **CONFIRMED** (EXEC-0006) |
| e5 = ambiguous 10/10 | **CONFIRMED** |
| missing = 0 in all 10 | **CONFIRMED** |

No element required forcing; the real data matches the claimed pattern exactly.

---

## 3. e4 audit (EXEC-0006, case `case-35f40cb6`)

**Was the unauthorized Modbus write actually executed? YES.**
- Evidence: `app_core/infrastructure/attack/outputs/20260903T163441Z_T0831_MANIPULATION_OF_CONTROL_MODBUS/modbus_transaction_log.json` — `write_command: "mbpoll -m tcp -a 1 -r 4 -t 4:int -1 192.168.100.214 30"`, exit ok.
- This is an **external, independent action log** (per the paper's Section 6.2 design), not derived from the forensic case itself.

**Was the PLC register/state change actually observed? YES.**
- `plc_state_before.json`: captured_at_utc=`2026-09-03T16:34:48.691204+00:00`, `level_max.value = 0`
- `plc_state_after.json`: captured_at_utc=`2026-09-03T16:34:52.708419+00:00`, `level_max.value = 30`
- `plc_state_restored.json`: captured_at_utc=`2026-09-03T16:34:56.403613+00:00`, `level_max.value = 0` (rollback verified)
- Register 4 = `level_max`; declared expected value 30 matches ground truth exactly.

**Was the preserved OT export incomplete at the required semantic granularity? YES.**
- File: `level_B/EXEC-0006/retained_case_lightweight_bundle/case-35f40cb6/industrial/ot_export_rolling_EXEC-0006_20260903_164730Z.json`
- `summary.records_exported = 0`, `summary.packets_seen_502 = 35`, `summary.payload_packets_seen = 0`
- `analysis/06_ot/ot_findings.json`: `findings.files[0].records = 0`

**Exact reason assigned by the evaluator (verbatim, from `causal_graph.json`, edge `edge_ot_write_to_plc_state_observation`):**
```
"status_reason": "Required evidence (plc_state_observation) is present but partially supported or not fully verified.",
"limitations": [
  "Register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level OT export parsing; only the presence of recorded PLC/SCADA state is verified here.",
  "The OT export analysis exists but recorded no PLC/SCADA state entries for this case."
]
```

**Why exactly is e4 DEGRADED rather than RECOVERED, AMBIGUOUS, or MISSING?**
Evaluator rule, function `evaluate_edges()`, `app_core/infrastructure/foc_causal_reconstruction/evaluators/edge_evaluator.py:19-58`:
```python
if missing_evidence:
    support_status = "missing"
elif temporal_status in {"ambiguous", "contradicted"}:
    support_status = "ambiguous"
elif any(result.get("status") in {"degraded", "ambiguous"} for result in requirement_results):
    support_status = "degraded"
...
else:
    support_status = "recovered"
```
Not MISSING because `missing_evidence == []` (the OT export *file* exists — the artifact is present). Not AMBIGUOUS because `temporal_status = "not_required"` for this edge (no temporal ordering is claimed). It is DEGRADED because the per-requirement evaluator for `plc_state_observation` returned status `"degraded"` (0 records found in the export it inspected) — matching the third branch. Not RECOVERED because that branch is only reached when no requirement is degraded/ambiguous and no temporal issue exists.

Input fields the evaluator used: `spec.required_evidence = ["plc_state_observation"]`, `selectors` for that requirement, and the requirement evaluator's own inspection of `analysis/06_ot/ot_findings.json` (`records: 0`).

---

## 4. PCAP coverage / gap audit — all 10 executions, no inferred conclusion forced

| exec | attack window (UTC) | segment windows | gap(s) (s) | attack overlaps a gap? | records_exported |
|---|---|---|---|---|---|
| EXEC-0001 | 09:24:32.616–09:24:51.553 | 3 segments | 24, 25 | No | 46 |
| EXEC-0002 | 10:56:41.054–10:56:59.379 | 3 segments | 26, 25 | No | 46 |
| EXEC-0003 | 12:24:45.598–12:25:03.706 | 2 segments | 22 | No | 6 |
| **EXEC-0004** | 13:45:51.048–13:46:08.503 | 2 segments: `13:43:53Z–13:45:53Z`, `13:46:15Z–13:48:15Z` | 22 | **Yes** (write window 13:45:58.11–13:46:01.81 fully inside the 13:45:53–13:46:15 gap) | **46 (full)** |
| EXEC-0005 | 15:11:47.416–15:12:06.210 | 3 segments | 24, 25 | No | 46 |
| **EXEC-0006** | 16:34:41.203–16:34:59.990 | 2 segments: `16:32:27Z–16:34:27Z`, `16:34:50Z–16:36:50Z` | 23 | **Yes** (PLC-state write window 16:34:48.69–16:34:52.71 straddles the 16:34:27–16:34:50 gap) | **0** |
| EXEC-0007 | 17:58:31.092–17:58:48.881 | 3 segments | 22, 23 | No | 46 |
| **EXEC-0008** | 19:26:18.035–19:26:35.841 | 2 segments: `19:24:07Z–19:26:07Z`, `19:26:31Z–19:28:31Z` | 24 | **Yes** (write window 19:26:25.26–19:26:29.09 inside the 19:26:07–19:26:31 gap) | **12 (partial)** |
| EXEC-0009 | 20:48:54.492–20:49:11.805 | 3 segments | 23, 24 | No | 46 |
| EXEC-0010 | 22:10:18.572–22:10:35.790 | 3 segments | 24, 25 | No | 46 |

Sources: per-execution `industrial/ot_export_rolling_*.json:captures[*].{segment_start_time,segment_end_time}`; `metadata/normalized_causal_timestamps.json:{attack_started_at_utc,attack_completed_at_utc}`; `attack/outputs/*/plc_state_before.json` and `plc_state_after.json` for the tighter write-bracket in EXEC-0004/0006/0008.

**Critical, non-forced finding:** the ~22–26 second inter-segment gap is a **structural, universal property of the rolling capture mechanism** — present in all 10 executions, not unique to EXEC-0006. The attack/write window overlaps this gap in **3 of 10 executions** (EXEC-0004, EXEC-0006, EXEC-0008), yet the outcomes differ: EXEC-0004 → 46 records (same as non-overlapping runs, i.e. no degradation), EXEC-0008 → 12 records (partial), EXEC-0006 → 0 records (complete loss).

- **Is the incomplete OT observation temporally associated with a capture-segment gap? YES**, for EXEC-0006 specifically.
- **Can the available evidence PROVE the gap caused the degraded e4 state? NO.** EXEC-0004's write window falls entirely inside a comparably-sized gap yet produced a full, undegraded export. Gap overlap is therefore **not sufficient** to explain EXEC-0006's specific 0-record outcome on its own.
- **Is it only the strongest supported explanation? YES**, with an important caveat: it is the strongest explanation *available at this granularity* (attack-window / plc-state-read timestamps vs. segment boundaries). The three overlapping cases' differing outcomes (46 / 12 / 0) suggest the true determinant is the **exact sub-second timing of the specific Modbus WRITE TCP packet** (not the broader read-write-read attack window) relative to the gap boundary and the per-tap-interface capture start latency — a level of detail not present in the currently preserved artifacts (no per-packet capture timestamp independent of the segment file boundaries was found for these three cases). This should be reported as **cause unresolved / gap-associated but not proven causal**, not as a demonstrated root cause.

---

## 5. e5 audit — all 10 executions

| execution_id | detection_surface_hit_at_utc | alert_observed_at_utc | identical? |
|---|---|---|---|
| EXEC-0001 | 09:24:45.457 | 09:24:45.457 | YES |
| EXEC-0002 | 10:56:53.549 | 10:56:53.549 | YES |
| EXEC-0003 | 12:24:57.014 | 12:24:57.014 | YES |
| EXEC-0004 | 13:46:01.977 | 13:46:01.977 | YES |
| EXEC-0005 | 15:11:59.299 | 15:11:59.299 | YES |
| EXEC-0006 | 16:34:54.501 | 16:34:54.501 | YES |
| EXEC-0007 | 17:58:43.812 | 17:58:43.812 | YES |
| EXEC-0008 | 19:26:30.691 | 19:26:30.691 | YES |
| EXEC-0009 | 20:49:07.290 | 20:49:07.290 | YES |
| EXEC-0010 | 22:10:30.148 | 22:10:30.148 | YES |

Source: `metadata/normalized_causal_timestamps.json` per execution.

**Both fields are derived from the same underlying IDS/SIEM alert event? YES — by construction, not coincidence.** Primary-source code, `app_core/infrastructure/foc_experimentation/level_b_repetition_runner.py:386-424`, function `_persist_normalized_causal_timestamps`:
```python
_alert_ts = ((matched_alert or {}).get("primary") or {}).get("ts_utc") or ...get("timestamp")
...
"alert_observed_at_utc": _alert_ts,
# detection_surface_hit_at_utc: the platform reads Suricata through the Wazuh SIEM pipeline.
# The IDS engine-level timestamp is not exported independently from the SIEM alert timestamp.
# This field is set to the Wazuh alert timestamp as the earliest available proxy for the
# detection surface event. A separate suricata_event_at_utc requires direct eve.json export.
"detection_surface_hit_at_utc": _alert_ts,
"suricata_event_at_utc": None,
"suricata_timestamp_exported": False,
```
Both fields are assigned the exact same Python variable, sourced from the Wazuh alert record. This is a code-level guarantee, confirmed empirically 10/10.

- **Are the two timestamps independent observations? NO.**
- **Can detection → alert temporal ordering be resolved from current evidence? NO** — delta is identically 0 by construction, not by measurement.
- **Is e5 ambiguity systematic across the baseline rather than run-to-run variability? YES**, confirmed both by source code (single shared variable) and empirically (10/10 identical).

**How this could be resolved in a future implementation:** the code already reserves the fields for it — `suricata_event_at_utc` (currently always `None`) would need to be populated from Suricata's own `eve.json` IDS-engine-level detection timestamp, exported independently of and prior to Wazuh's SIEM alert ingestion/ts_utc assignment. That would give two genuinely independent timestamps (IDS engine detection vs. SIEM alert emission) instead of one value copied into two fields.

---

## 6. C1–C5 recomputed per execution (current rule implementation)

Rule source: `app_core/infrastructure/forensics/fsr_verdict.py:compute_fsr_verdict()` (the single function also used to persist `metadata/fsr/fsr_eval_<id>.json` at case-sealing time — same code path, not a separate dashboard-only computation).

| execution | C1 | C2 | C3 | C4 | C5 |
|---|---|---|---|---|---|
| EXEC-0001…EXEC-0010 (all 10) | ✓ | ✓ | ✓ | ✓ | ✓ |

**Acceptance rules, source, evidence inspected, reason:**

- **C1** (`evidence_layers["network"]`): `bool(pcap_gib > 0 or preserved.network_packet_context)`. Evidence: `manifest.json` artifacts of type `network_pcap`. PASS 10/10 — every case has non-zero preserved/recorded pcap volume.
- **C2** (`bool(trigger_binding.trigger_alert_id) and bool(trigger_binding.raw_json)`): evidence `metadata/trigger_alert_binding.json`. PASS 10/10 — every case has a real `trigger_alert_id` and an embedded `raw_json` (the original Wazuh/Suricata record).
- **C3** (`evidence_layers["ot"]` = `bool(nts.get("ot_export_preserved_at_utc"))`): evidence `metadata/normalized_causal_timestamps.json`. PASS 10/10, **including EXEC-0006** — see the detailed semantic discussion below.
- **C4** (`evidence_layers["memory"] and evidence_layers["disk"]`): evidence manifest artifact types `memory_lime`/`disk_raw` present with size > 0. PASS 10/10.
- **C5** (`evidence_layers["manifest"] and evidence_layers["custody"] and integrity_ratio >= 0.95`): PASS 10/10 — see Section 7 for the exact ratios.

### C3 for the degraded execution (EXEC-0006) — semantic check, not presence-only

**Does the degraded execution scientifically satisfy C3? Answer: PASS under the *current code rule*, but the rule and the paper's own prose diverge for this execution — flagged as a genuine ambiguity, not resolved here.**

The paper defines C3 as: *"Protocol-aware OT export is preserved **and supports control-level interpretation** under the active profile scope and time anchoring."* This is a two-clause definition: (a) preserved, (b) supports interpretation.

The current code (`fsr_verdict.py`) checks **only clause (a)**: `bool(ot_export_preserved_at_utc)` — whether an export artifact with that timestamp exists. It does not check whether the export contains any usable records.

For EXEC-0006: the OT export file **is preserved** (`ot_export_preserved_at_utc` is set, the artifact exists in the manifest with a valid hash) — clause (a) is satisfied. But the export contains **zero records** (`summary.records_exported: 0`, `ot_findings.json: records: 0`) — it cannot, by its own content, "support control-level interpretation" of anything; there is no control-observable state in it to interpret. Clause (b) is **not** satisfied for this specific execution.

- **If the aggregate is reported as C3 = 10/10**, this is only correct under the narrower "artifact preserved" reading — which is what the code currently implements and what R4/Table 10 traceability (`C1–C4`) is scoped to (artifact presence, not analysis outcome).
- **If the paper's own stricter two-clause prose is applied literally**, EXEC-0006 does not fully satisfy C3, and the honest aggregate would be **9/10 fully satisfying both clauses, 1/10 satisfying only the preservation clause**.

Recommendation (not applied here, read-only): either (i) keep C3 = 10/10 and adjust the paper's C3 prose to explicitly match what is actually checked ("preserved," not "preserved and interpretable"), or (ii) report C3 as 9/10 with EXEC-0006 as the one execution where the preserved OT export does not support interpretation, and cross-reference it to the already-reported degraded e4 state. Do not silently keep both the 10/10 number and the two-clause prose as currently written — they are inconsistent for this one execution.

---

## 7. C5 / integrity — detailed audit

### Complete retained case (`final_sample_case/CASE-20260903-221042`, deposit candidate)

| Metric | Value | Source |
|---|---|---|
| Total artifacts in manifest | 616 | `manifest.json` |
| Artifacts with a recorded SHA-256 | 616 (100%) | counted directly |
| Successfully re-verified against current file content (latest entry per path) | **616/616 — 0 mismatches** | independent re-hash of every distinct `rel_path`, compared to the most recent manifest entry (script run this session; see Section 17 log) |
| Failed / not verifiable | 0 | — |
| Skipped / not applicable | 0 | — |
| Global verification ratio | **1.0000** | — |
| Final integrity status | **Verified** | — |

Note: this clean result reflects the manifest-hash-staleness fix applied earlier in this session (5 files per case whose *final* write was previously unregistered — `time_sync.json`, `acquisition_profile.json`, `evidence_inventory.json`, `integrity_custody_report.json`, `workflow_phase_summary.json` — now have a fresh, matching manifest entry; append-only files `chain_of_custody.log`/`case_digest.json` were already correct by design). This is a real, applied fix from this session, disclosed here for transparency — it did not touch any primary evidence byte, only added new manifest/custody entries.

### Lightweight bundles (9 of 10 executions), representative case `case-4acde669` (EXEC-0001)

| Metric | Value |
|---|---|
| Total artifacts in manifest | 573 |
| With SHA-256 | 572 |
| Without SHA-256 | 1 — `metadata/workflow_phase_summary.json`, but only its **original** manifest entry (`ts: 2026-09-03T22:42:41Z`, `sha256: null`) — a genuine gap from the original live pipeline run, not introduced this session. A second, later entry for the same path (`ts: 2026-09-10T09:28:56Z`, real hash) exists from this session's fix, so the *current* content of that file is hash-verified; only the historical first entry lacks one. |
| Effective ratio (`fsr_verdict.compute_fsr_verdict`, `sha256_covered/total`) | 0.9983 |

### Failures/non-validations, itemized

| Artifact | Type | Category | Required by active profile? | Reason | Impact on C5 |
|---|---|---|---|---|---|
| `metadata/workflow_phase_summary.json` (original 2026-09-03 entry only) | workflow_phase_summary | metadata/derived, not primary evidence | No (supporting artifact, evaluated under E2/E3 per Table 6, not E1) | Original pipeline write never computed a hash for this one entry | None — C5's `>= 0.95` threshold is met (0.9983); the gap is on a non-primary, supporting artifact and its current content is separately hash-covered by the later entry |

**Is C5 = 10/10 scientifically justified under the declared C5 rule? YES.** The rule as coded is `manifest present AND custody present AND integrity_ratio >= 0.95`; every one of the 10 executions has ratio ≥ 0.9983. No rule was changed to make this pass — the 0.95 threshold and the ratio were checked as-is.

---

## 8/9. E1–E4 recomputed, and E2 temporal synchronization

E1/E3/E4 per execution: all **10/10 PASS** (same `fsr_verdict.py` rules as Section 6; E1 = network+memory+disk+ot all present; E3 = same manifest+custody check as C5; E4 = derived analysis output exists and its `generated_at` postdates `case_sealed_at_utc`).

### E2 — do NOT reuse 0.026 ± 0.006 s unless verified for this campaign

**It does not belong to this campaign.** Recomputed per execution from `metadata/time_sync.json`:

| execution | max_clock_offset_ms | nodes measured | chrony/NTP status |
|---|---|---|---|
| EXEC-0001 | 233.201 | 5 (PLC_Instance, FUXA_Instance, victim 33, attack 22, monitor 11) | `chrony_available: false` all nodes; `synchronized: true` (measured, not corrected) |
| EXEC-0002 | 239.047 | 5 | same |
| EXEC-0003 | 246.109 | 5 | same |
| EXEC-0004 | 275.246 | 5 | same |
| EXEC-0005 | 262.601 | 5 | same |
| EXEC-0006 | 247.634 | 5 | same |
| EXEC-0007 | 252.693 | 5 | same |
| EXEC-0008 | 228.976 | 5 | same |
| EXEC-0009 | 244.515 | 5 | same |
| EXEC-0010 | 243.221 | 5 | same |

Source per row: `level_B/EXEC-000N/retained_case_lightweight_bundle/case-*/metadata/time_sync.json`.

**mean = 0.2473 s, sample SD = 0.0136 s, min = 0.2290 s, max = 0.2752 s, N = 10.**

**Confirms 0.026 ± 0.006 s does NOT belong to this campaign.** No file searched (see Section 12) reproduces this value for these 10 executions.

**Root cause of the ~0.24 s offset (found and already fixed this session):** the platform's corrective time-sync mechanism (chrony install + `makestep`) exists and is invoked once per Level C repetition, but was blocked every single time by policy — confirmed in `runtime/level_c_jobs/LC-20260903-083211-88F7/job_state.json`, 50 occurrences (5 nodes × 10 reps) of `"clock sync blocked — Corrective time synchronization is blocked by default while a forensic case is active..."`. The blocking check read a global, never-cleared-on-normal-sealing pointer file (`_active_case.txt`), not a per-VM/per-case state — a real bug, fixed this session in `forensics_api.py` (clears the pointer at the two real case-sealing points). This explains the elevated offset; it is genuine, unmasked drift, not a corrected/optimistic figure.

---

## 10. Table 18 — full per-execution operational metrics

All values below are cross-validated by **two independent computations**: (a) direct recomputation from each case's `metadata/normalized_causal_timestamps.json`, and (b) the pre-existing rows `run_94`–`run_103` in `paper_exports/FORGE-VI/FORGE-VI_LevelC_Operational_Metrics.csv`. Both agree exactly on every shared column.

| execution | attack_duration_s | attack_to_alert_s | alert_to_memory_start_s | alert_to_memory_sealed_s | alert_to_OT_preserved_s | alert_to_disk_start_s | alert_to_disk_preserved_s | alert_to_T_case_sealed_s | pcap_GiB | memory_GiB | disk_GiB | retry events |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| EXEC-0001 | 18.94 | 12.84 | 35.19 | 574.42 | — | — | — | 1752.54 | 2.300 | 7.998 | 70.0 | 0 |
| EXEC-0002 | 18.33 | 12.50 | 13.99 | 571.91 | — | — | — | 1716.45 | 2.303 | 7.998 | 70.0 | 0 |
| EXEC-0003 | 18.11 | 11.42 | 14.68 | 788.15 | — | — | — | 1343.99 | 0.059 | 7.998 | 70.0 | 0 |
| EXEC-0004 | 17.46 | 10.93 | 14.71 | 877.03 | — | — | — | 1428.02 | 0.059 | 7.998 | 70.0 | 0 |
| EXEC-0005 | 18.79 | 11.88 | 15.12 | 846.29 | — | — | — | 1383.70 | 0.094 | 7.998 | 70.0 | 0 |
| EXEC-0006 | 18.79 | 13.30 | 13.92 | 755.24 | — | — | — | 1269.50 | 0.075 | 7.998 | 70.0 | 0 |
| EXEC-0007 | 17.79 | 12.72 | 13.19 | 571.61 | — | — | — | 1720.19 | 2.177 | 7.998 | 70.0 | 0 |
| EXEC-0008 | 17.81 | 12.66 | 13.38 | 744.60 | — | — | — | 1263.31 | 0.076 | 7.998 | 70.0 | 0 |
| EXEC-0009 | 17.31 | 12.80 | 12.61 | 692.62 | — | — | — | 1372.71 | 0.643 | 7.998 | 70.0 | 0 |
| EXEC-0010 | 17.22 | 11.58 | 13.71 | 923.79 | — | — | — | 1436.85 | 0.090 | 7.998 | 70.0 | 0 |

(`alert_to_OT_preserved_s`/`alert_to_disk_start_s` columns: computed separately from `normalized_causal_timestamps.json` in Section 10b below — the CSV export does not carry these two milestones, only memory/case-sealed.)

| Metric | N | mean | sample SD | min | max | units | source |
|---|---|---|---|---|---|---|---|
| attack_duration | 10 | 18.055 | 0.639 | 17.22 | 18.94 | s | nts + CSV, cross-verified |
| attack_to_alert | 10 | 12.263 | 0.762 | 10.93 | 13.30 | s | nts + CSV |
| alert_to_memory_start | 10 | 16.050 | 6.768 | 12.61 | 35.19 | s | nts + CSV |
| alert_to_memory_sealed | 10 | 734.566 | 130.129 | 571.61 | 923.79 | s | nts + CSV |
| alert_to_OT_export_preserved | 10 | 954.526 | 183.028 | — | — | s | nts (computed this session, see 10b) |
| alert_to_disk_start | 10 | 955.531 | 182.934 | — | — | s | nts |
| alert_to_disk_preserved | 10 | 1469.251 | 189.182 | — | — | s | nts |
| alert_to_T_case_sealed | 10 | 1468.726 | 189.068 | 1263.31 | 1752.54 | s | nts + CSV (identical to T_first_sealed — sealing is a single batch op) |
| PCAP volume | 10 | 0.788 | 1.032 | 0.059 | 2.303 | GiB | nts + CSV |
| Memory volume | 10 | 7.998 | 0.000 | 7.998 | 7.998 | GiB | manifest (2+2+4 GiB fixed by VM role, constant every run) |
| Disk volume | 10 | 70.000 | 0.000 | 70.0 | 70.0 | GiB | manifest (15+15+40 GiB fixed by VM role) |
| Retry/failure events | 10 | 0 | 0 | 0 | 0 | count | `per_repetition_results[*].trigger_attempts_total == 1` for all 10, and CSV `acquisition_failures = 0` for all 10 |
| Deploy time (`DEPLOYING_IT`→`WAITING_NODES`) | 10 | 733.24 | 119.34 | 618.38 | 949.16 | s | `runtime/level_c_jobs/LC-20260903-083211-88F7/job_state.json` phase log (not in the per-case CSV — this is a Level-C-job-level metric) |
| Teardown+redeploy (`DESTROYING`→`WAITING_NODES`) | 10 | 890.26 | 120.08 | 773.01 | 1105.81 | s | same |

### Comparison against the OLD values currently in the paper draft

| Metric | Old paper value | New campaign value | Verdict |
|---|---|---|---|
| Deploy 850 ± 100 | — | 733.24 ± 119.34 | **DIFFERENT** |
| Teardown+redeploy 1050 ± 110 | — | 890.26 ± 120.08 | **DIFFERENT** |
| Alert→memory start 20.317 ± 16.787 | — | 16.050 ± 6.768 | **DIFFERENT** |
| Alert→first memory preserved 357.667 ± 15.519 | — | 734.566 ± 130.129 | **DIFFERENT** |
| Alert→OT export preserved 1347.624 ± 316.055 | — | 954.526 ± 183.028 | **DIFFERENT** |
| Alert→disk start 1348.397 ± 315.941 | — | 955.531 ± 182.934 | **DIFFERENT** |
| Alert→disk preserved 2096.216 ± 301.210 | — | 1469.251 ± 189.182 | **DIFFERENT** |
| T_first_sealed 2095.624 ± 301.1 | — | 1468.726 ± 189.068 | **DIFFERENT** |
| T_case_sealed 2095.624 ± 301.1 | — | 1468.726 ± 189.068 | **DIFFERENT** |
| PCAP 2.896 ± 0.929 GiB | — | 0.788 ± 1.032 GiB | **DIFFERENT** |
| Memory 4.293 GB | — | 7.998 GiB (2+2+4, all 3 roles) | **DIFFERENT** (old value = one of three roles only) |
| Disk 42.950 GB | — | 70.0 GiB (15+15+40, all 3 roles) | **DIFFERENT** (old value = one of three roles only) |
| retry/failure = 1/10 | — | 0/10 | **DIFFERENT** |
| E2 offset 0.026 ± 0.006 s | — | 0.247 ± 0.014 s | **DIFFERENT** |

**Every single Table-18/E2 number currently in the paper draft is different from this campaign's real, recomputed value. None matched.**

---

## 11. Level C / redeployment evidence

`runtime/level_c_jobs/LC-20260903-083211-88F7/job_state.json` phase log shows, for **every** repetition 1–10, the real sequence `DESTROYING → CLEANING → DEPLOYING_IT → DEPLOYING_OT → WAITING_NODES → SYNCING_CLOCKS → INSTALLING_TOOLS → VERIFYING_MONITORING → RUNNING_LEVEL_B → WAITING_LEVEL_B → CAPTURING_SNAPSHOT`.

VM instance IDs sampled directly from `metadata/time_sync.json` per execution — **completely different UUIDs every repetition** (not just role names):

| Role | EXEC-0001 | EXEC-0002 | EXEC-0010 |
|---|---|---|---|
| PLC_Instance | 72f51f76-9bf5-4f7b-b16b-d9615bac5c62 | ec1f1201-e0ac-48bb-8462-83fce2134c99 | 11960c03-292d-4f8a-8d3d-730a8921cc28 |
| FUXA_Instance | e0d940e6-eb02-4cad-a1fc-f01e61bb22ee | b518b6e3-0151-48b6-8450-d7c7b2db8f3a | 5ce127a0-331c-4d25-afc2-913d931025e7 |

Deploy/teardown timestamps per repetition: see Section 10 (Level-C job log). Pre-run invariant-gate result: see Section 8/9 (5/6 IR preconditions pass 10/10; `segmentation` passes 7/10 — see below). Effective inventory: `time_sync.json:nodes[*]` per execution (5 nodes each, names + IPs recorded). Topology/config hash: **NOT AVAILABLE** — no content hash of the deployed topology was found recorded per repetition, only the node inventory itself.

**Do all ten reported executions have sufficient evidence to be called Level C? YES**, for all 10 — confirmed via distinct VM UUIDs and full phase-log presence for reps 1–10.

**IR-gate real result (recomputed, `ir_gate` fields in `fsr_verdict.py`, sourced from `workflow_phase_summary.json`/`time_sync.json`):**

| Precondition | Result |
|---|---|
| Same topology instantiated | 10/10 |
| Target roles present | 10/10 |
| **Segmentation enforcement verified** | **7/10** (fails EXEC-0003, EXEC-0006, EXEC-0008) |
| Monitoring liveness | 10/10 |
| Time reference coherent | 10/10 |
| Service health | 10/10 |

This does not match the paper's current "10/10" claim for segmentation — see Section 17.

---

## 12. Campaign A / historical-value contamination search

Searched `paper_exports/`, `tools/`, `app_core/infrastructure/forensics/scripts/`, and the full repo (excluding raw per-case evidence dumps) for every literal old value:

| Value | Found in current, traceable export/script? | Belongs to |
|---|---|---|
| `20.317`, `357.667`, `1347.624`, `2096.216`, `2095.624`, `850`/`1050` (deploy), `4.293`, `42.950`, `0.026`/`0.006` | **NOT FOUND** anywhere in `paper_exports/`, `tools/`, or `app_core/infrastructure/forensics/scripts/` | **UNKNOWN** — no traceable current source in this repository. Could not confirm these come from any campaign at all; they may be manually typed/estimated in an earlier paper draft, or from a run whose raw records are no longer present in this repository. |
| `CPR 0.875 with zero variance`, `"7 per execution, stable in 10/10"`, `"0 degraded"` | This is exactly the OLD (red) Table 14 text visible in the pasted paper draft itself | Describes a hypothetical/earlier version of this same campaign's reporting, before the real EXEC-0006 degradation was incorporated — **not a separate dataset file**, it is literally the paper's own prior draft text. |
| `case-f9b84046`, and 93 other older `run_01`…`run_93` rows | **FOUND** — `paper_exports/FORGE-VI/FORGE-VI_LevelC_Operational_Metrics.csv` (105 lines, rows `run_01`…`run_103`) | A rolling historical export spanning many unrelated older campaigns (case IDs do not match this campaign's `case-4acde669` etc.). **Rows `run_94`–`run_103` in this same file are this campaign's real, correct, already-exported per-execution data** (verified: `disk_size_gib=70.0`, `memory_size_gib=7.998`, matching independent recomputation exactly) — see Section 10. |
| `one retry over ten executions` | Not found as a literal string in any script/export; the CSV shows `acquisition_failures=0` for every one of this campaign's 10 rows | This campaign: 0, confirmed 3 independent ways (job `trigger_attempts_total`, CSV `acquisition_failures`, dashboard) |

**No values were deleted.** The historical 103-row CSV remains untouched at `paper_exports/FORGE-VI/FORGE-VI_LevelC_Operational_Metrics.csv`.

---

## 13. Continuous vs. rolling/segmented PCAP

- **Is capture actually gap-free continuous? NO.** Confirmed structurally present in all 10 executions (Section 4): 22–26 second gaps between consecutive rotation segments, every single run.
- **Are PCAPs implemented as independently rotated segments? YES.** Each `ot_export_rolling_*.json:captures[*]` entry references a distinct 120-second `*_120s.pcap` file per tap interface, with its own start/end time.
- **Can gaps exist between segments? YES** — empirically present in 10/10 executions, 22–26 s each.
- **Are segment start/end timestamps recorded? YES** — `segment_start_time`/`segment_end_time` per capture entry.
- **Is "continuous mode" a real software mode/API name, or textual description?** The literal string found in code/exports is `"source_mode": "continuous_rolling_pcap_with_case_bound_incident_window_import"` (`ot_export_rolling_*.json`). No mode names were renamed here.

**Scientifically correct characterization: "rolling segmented PCAP observation with inter-segment capture gaps of ~22–26 seconds"** — not gap-free continuous. The paper's existing text already partially reflects this ("rolling PCAP segments," "segmented network observation... temporal coverage interpreted from the effective preserved segment boundaries rather than assumed gap-free" — Section 8.3 threats-to-validity paragraph already added in the draft) — that language is accurate and should be kept; any remaining "continuous" language describing gap-free coverage should not be read as literally gap-free.

---

## 14. Depositable evidence / Data Availability

- **Complete sealed raw case available:** YES — 1 of 10.
  - **CASE-ID:** `CASE-20260903-221042` (execution EXEC-0010; case identifier internally `case-f4c20014` in the campaign's own case registry)
  - **Size:** 78.09 GiB (logical/manifest size, verified this session), 616 manifest artifacts, 100% SHA-256 covered, 0 verification mismatches (Section 7).
- For this case: memory raw (YES, 3 files, 2+2+4 GiB), disk raw (YES, 3 files, 15+15+40 GiB), PCAP raw (YES), OT evidence (YES, though 0 useful records is a separate fact from presence — see Section 6), manifest (YES), custody log (YES, 28 entries after this session's additions, hash-chain verified 0 breaks), acquisition metadata (YES), derived analysis (YES), causal reconstruction (YES, `causal_graph.json`/`causal_status.json` present and internally consistent).
- **Campaign-level records for all 10? YES.** Paths: `evidence_store/repetition_campaigns/CMP-20260903-083211-125A/level_B/EXEC-000N/` (profiles, manifests, comparison data) for all 10; `evidence_store/repetition_campaigns/CMP-20260903-083211-125A/jobs/*.json` (raw per-repetition pipeline results); `runtime/level_c_jobs/LC-20260903-083211-88F7/job_state.json` (full campaign orchestration log).
- **Can the deposited material independently reproduce/check the reported CPR distribution without trusting the dashboard? YES.** Confirmed directly in this audit: Section 2's table was built by reading `derived/reconstruction/causal_graph.json` per execution with a small standalone script, no dashboard call involved, and it reproduces the claimed CPR distribution exactly.
- **Script/command that reconstructs Table 14/15 from campaign records:** no pre-existing packaged script does this end-to-end; the read path is: for each `level_B/EXEC-000N/retained_case_lightweight_bundle/case-*/derived/reconstruction/causal_graph.json`, read `edges[*].{edge_id,support_status}`, map via the 8 `edge_id` values in `app_core/infrastructure/forge_vi_dashboard/endpoints.py:_EDGE_ORDER` to `e1`…`e8`, and aggregate. This audit's Section 2 script (used to produce this report) implements exactly that and can be handed to a reviewer.

---

## 15. Raw-data availability, precise (do not overstate)

- **1 of 10** executions (EXEC-0010) retains **complete raw evidence** (memory dumps, disk images, PCAP files, OT export — actual bytes on disk).
- **9 of 10** executions (EXEC-0001–0005, 0007–0009) retain **only lightweight campaign-level records**: `manifest.json` (with recorded SHA-256 hashes and sizes of the artifacts as they existed at acquisition time), `chain_of_custody.log`, case metadata, and derived analysis/reconstruction outputs (`causal_graph.json`, `causal_status.json`, `forensic_analysis_report.json`, etc.). The actual memory/disk/pcap **bytes for these 9 do not exist on disk any more** — confirmed this session (`find ... -type f` on `memory/`, `disk/` subdirectories of the lightweight bundles returns nothing; only `network/traffic_preserved/network_context_manifest.json`, ~1.3 MB total per bundle).
- Evidence classes retained per case: primary raw bytes only for EXEC-0010; manifest+hash+custody+derived-analysis for all 10.

**Do not write in the paper that complete raw artifacts for all ten executions are preserved — this would be false.**

---

## 16. Figure provenance

| Figure | How produced | Source |
|---|---|---|
| Fig. 1 (traceability overview: sources→goals→requirements→evaluation→invariants) | **UNKNOWN** | No generator script found in the repository (searched for `fig*`, diagram tooling, and figure-export code under `app_core/`, `tools/`, `paper_exports/` — no match). Likely manually composed, but this could not be confirmed from repository contents. |
| Fig. 2 (high-level architecture) | **UNKNOWN**, same search, no match | — |
| Fig. 3 (deployment domains / operational planes) | **UNKNOWN**, same search, no match | — |

No generative-AI-assisted or diagram-software artifact (e.g., a `.drawio`, `.excalidraw`, `.svg` source, or a plotting script) was found in the repository for any of the three architecture figures. This is reported as UNKNOWN rather than inferred.

---

## 17. Cross-file coherence contradiction sweep

Contradictions found this session (not exhaustive of every file in the repository, but covering the scientific-report/export/dashboard/paper-export/comparison-report surface actually used to produce paper content):

| # | FILE | VALUE/CLAIM | CAMPAIGN IT BELONGS TO | STATUS |
|---|---|---|---|---|
| 1 | Paper draft, Table 11 | Segmentation enforcement 10/10 | Claimed for this campaign | **STALE/WRONG** — real is 7/10 (Section 11) |
| 2 | Paper draft, Table 16 | E2 offset 0.026 ± 0.006 s | Claimed for this campaign | **STALE/WRONG, unknown origin** — real is 0.247 ± 0.014 s (Section 9) |
| 3 | Paper draft, Table 18 | All M2/M3/M4 figures (deploy, latencies, volumes, retry count) | Claimed for this campaign | **STALE/WRONG, unknown origin** (Section 10) |
| 4 | Paper draft, Table 14 | "Missing relations" row carries the `1 in 1/10` degraded-count text; "Degraded relations" row still says `0, stable in 10/10` | This campaign (partially updated) | **INTERNALLY CONTRADICTORY** — the two rows' content appears swapped; not consistent with either campaign |
| 5 | `app_core/infrastructure/foc_experimentation/execution_service.py:255-267` (`_derive_stage_statuses`) | `execution_manifest.json` stage text: "Semantic reconstruction has not been generated" / "Causal reconstruction is blocked..." | Generic boilerplate, written once at Level-B "linked case" registration time, before this campaign's real reconstruction completed | **STALE**, present in all 10 `execution_manifest.json` files; contradicted by the real, later `derived/reconstruction/causal_status.json` and `derived/executive/evidence_lifecycle_summary.json` (which correctly show `main_limitation: "At least one causal edge is temporally ambiguous..."`) |
| 6 | `paper_exports/FORGE-VI/FORGE-VI_LevelC_Operational_Metrics.csv` | Rows `run_01`–`run_93` | Older, unrelated campaigns (different `case_id`s) | **HISTORICAL**, correctly not part of this campaign's aggregate; not deleted |
| 7 | `paper_exports/FORGE-VI/FORGE-VI_LevelC_Workflow_Checks.json` | 103-entry static export, previously found (earlier this session) to be merged into dashboard rows by list position rather than `case_id` | Mixed/historical | **HISTORICAL, already fixed in the dashboard** (case_id-keyed lookup); the underlying file itself is untouched, still contains only old entries for this campaign's case IDs — i.e., it never received this campaign's own true C1–C5/E1–E4 values (those are computed live/at seal-time instead, not from this static file) |

No file was found that reports a correct-looking CPR aggregate, C1–C5, E1–E4, clock offset, or volume number for *this* campaign that contradicts the values in Sections 2–10 above — i.e., every primary-data source (raw `causal_graph.json`, `time_sync.json`, `normalized_causal_timestamps.json`, and the matching CSV rows 94–103) is mutually consistent. The contradictions found are all in **secondary/summary/report text**, not in primary preserved evidence.

---

## 18. Final checklist

```
CHECK                                                     RESULT
-------------------------------------------------------------------------
Single canonical 10-run campaign identified                YES
10 executions verified                                    YES
All 10 are verifiable Level C executions                  YES
CPR recomputed from raw campaign records                  YES
CPR = 0.8625, sample SD = 0.0395                          YES
e4 recovered 9/10, degraded 1/10                          YES
e5 ambiguous 10/10                                        YES
Missing relations = 0/10                                  YES
e5 timestamps derive from same alert record                YES
C1 verified                                                YES
C2 verified                                                YES
C3 verified, including degraded execution                  PARTIAL — see Section 6: passes under the current code rule (artifact presence); fails the paper's own stricter two-clause prose for EXEC-0006 specifically. Needs an explicit author decision, not silently reported as clean 10/10.
C4 verified                                                YES
C5 verified                                                YES
E1 verified                                                YES
E2 recomputed from canonical campaign                      YES (0.247 ± 0.014 s — does NOT match old paper value)
E3 verified                                                YES
E4 verified                                                YES
Table 18 fully recomputed from canonical campaign          YES
Old campaign metrics excluded from new aggregate            YES
PCAP temporal coverage characterized                        YES — rolling/segmented, real ~22-26s gaps, NOT gap-free continuous
Complete sealed case available from canonical campaign      YES (EXEC-0010 / CASE-20260903-221042)
Campaign records available for all ten executions          YES
Figure provenance determined                                UNKNOWN (all 3 figures)
```

**SAFE TO FINALIZE PAPER VALUES: NO.**

Blockers (only these, nothing else):
1. **Table 11, Table 16 (E2), Table 18 (M1–M4)** in the current paper draft must be replaced with the real values in Sections 9–10 of this report before the paper is finalized — none of the current numbers match this campaign.
2. **Table 14's "Missing relations"/"Degraded relations" rows are internally swapped** and must be corrected (Section 17, item 4) regardless of which campaign is reported.
3. **C3's aggregate (10/10) needs an explicit author decision** on whether the paper's own two-clause definition is meant literally (in which case EXEC-0006 should be reported as 9/10, or the C3 prose narrowed to match the actual "presence" check) — this is a genuine unresolved semantic gap, not a data error (Section 6).
4. The origin of the *current* stale Table 18/E2 numbers could not be traced to any file in this repository (Section 12) — if the paper is meant to cite a *different, earlier* campaign for those specific historical figures rather than replace them with this campaign's numbers, that intent should be stated explicitly, since right now the numbers are unattributed and unverifiable either way.
5. Figure provenance is UNKNOWN for all three architecture figures — not a blocker to the numerical results, but should be resolved before claiming reproducibility of the whole manuscript, since the paper's own reproducibility claims (Section 3) extend to "the documented scenario."

No other blockers were found. Sections 1–17 above provide full, file-cited support for every other checklist item marked YES.
