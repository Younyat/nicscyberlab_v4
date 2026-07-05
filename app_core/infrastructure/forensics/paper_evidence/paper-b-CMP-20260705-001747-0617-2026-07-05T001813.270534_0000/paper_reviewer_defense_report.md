# Paper Evidence Package

## Executive summary

- Report ID: `paper-b-CMP-20260705-001747-0617-2026-07-05T001813.270534_0000`
- Level requested: `B`
- Generated at: `2026-07-05T12:40:53.681789+00:00`
- Source campaign: `CMP-20260705-001747-0617`
- Requested repetitions: `10`
- Completed / partial / failed: `0` / `10` / `0`
- Higher-level comparison status: `Comparable With Degradation`
- Nested Level A completed reports: `9`

## Reviewer-facing interpretation

### What does this level prove?

- Level B proves whether repeated execution of the same controlled incident in the same deployed scenario produces comparable new forensic cases and comparable reconstruction outputs.
- Level B also exposes trigger quality, alert-to-acquisition latency, preservation ordering, and cross-case comparability.

### What does this level not prove?

- Level B does not prove full redeployment reproducibility. That belongs to Level C.

### Cross-case scientific comparison

- Comparison type: `exploratory_comparison_only`
- Comparison status: `Comparable With Degradation`
- Compared executions: `EXEC-0001, EXEC-0002, EXEC-0003, EXEC-0004, EXEC-0005, EXEC-0006, EXEC-0007, EXEC-0008, EXEC-0009, EXEC-0010`

### Operational latency and acquisition

- Alert -> memory start mean/std: `24.9462` / `9.603592`
- Alert -> case sealed mean/std: `1190.805` / `96.968834`

### Nested Level A inside each Level B case

- Each Level B repetition generated a new case and then launched a nested Level A repeatability audit over that preserved case.
- Nested comparison statuses: `Comparable With Degradation, Comparable With Degradation, Not Comparable, Comparable With Degradation, Insufficient Data, Comparable With Degradation, Insufficient Data, not_available, Comparable With Degradation, Comparable With Degradation`

### Which paper tables are supported by this output?

- `TAB-QUAL-POSITIONING`: support=`supported` | concern=`Clarifies what the system is intended to measure and what each module contributes.`
- `TAB-REQ-METRIC-MAP`: support=`supported` | concern=`Addresses reviewer concern that invariants and requirements were not operationalized.`
- `TAB-LEVEL-A-REPEATABILITY`: support=`supported` | concern=`Addresses whether results are stable without changing the preserved evidence.`
- `TAB-DIAGNOSTIC-INDICATORS`: support=`supported` | concern=`Addresses reviewer concern that 100% operational readiness was being conflated with complete causal reconstruction.`
- `TAB-RELATION-STATE-MATRIX`: support=`supported` | concern=`Addresses reviewer concern that abstract counts of recovered/degraded/missing relations lack operational and forensic meaning.`
- `TAB-OPER-LATENCY`: support=`supported` | concern=`Addresses reviewer concern that operational latency and trigger effectiveness were not quantified.`
- `TAB-ARTIFACT-SIZE-COVERAGE`: support=`supported` | concern=`Addresses whether evidence preservation and coverage are measurable rather than assumed.`
- `TAB-FAILURE-DEGRADATION`: support=`supported` | concern=`Directly addresses the reviewer concern about hidden failures and perfect binary success narratives.`
- `TAB-INVARIANT-RECOVERY`: support=`partial` | concern=`Addresses reviewer concern that semantic or forensic invariants were claimed without a concrete runtime operationalization trace.`
- `TAB-LEVEL-B-COMPARABILITY`: support=`supported` | concern=`Addresses reviewer concern that repeatability must include acquisition and preservation, not just reanalysis.`
- `TAB-LEVEL-C-REDEPLOYMENT`: support=`unsupported` | concern=`Addresses reviewer concern about full reproducibility beyond one deployment state.`

### Limitations and degradation

- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: nested Level A scientific report did not complete successfully for this Level B case
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Semantic reconstruction has not been generated.
- warning: Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case.
- warning: Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- warning: Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis.
- warning: Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
- blocker: missing_critical_evidence=ot_export_present_in_manifest
