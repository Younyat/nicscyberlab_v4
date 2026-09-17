# Level B Repetition Report

- Generated at: `2026-09-15T13:49:26.209231+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `3a0a8948a1b6f684462cd789`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `1`
- Nested Level A repetitions per Level B case: `1`
- Completed repetitions: `0`
- Partial repetitions: `1`
- Failed repetitions: `0`

## Higher-Level Level B Comparability

- Comparison status: `Not Comparable`
- Comparison type: `exploratory_comparison_only`
- Compared executions: `EXEC-0001, EXEC-0002`

## Nested Level A Repeatability

- Completed nested reports: `1`
- Failed nested reports: `0`
- Nested comparison statuses: `Insufficient Data`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `20.695` / `0.0`
- Alert -> memory preserved mean/std: `708.22` / `0.0`
- Alert -> case sealed mean/std: `4287.857` / `0.0`
- Total duration mean/std: `4662.475` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.0` / `0.0`
- Weighted recoverability mean/std: `0.0` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `0`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0002`
- Case ID: `case-0396988e`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260915T121653Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `completed`
- Reconstruction status: `blocked_missing_analysis`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Insufficient Data` / `not_enough_generated_level_a_repetitions`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `None` / `None` / `None`
- Relations recovered/degraded/ambiguous/missing: `None` / `None` / `None` / `None`
- Alert -> memory start: `20.695` seconds
- Alert -> case sealed: `4287.857` seconds
- Total repetition duration: `4662.475` seconds
- Warnings: `Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Semantic reconstruction has not been generated. | Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
