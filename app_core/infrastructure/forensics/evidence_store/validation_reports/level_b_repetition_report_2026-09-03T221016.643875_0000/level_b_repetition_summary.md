# Level B Repetition Report

- Generated at: `2026-09-03T22:42:25.912281+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `3a0a8948a1b6f684462cd789`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `1`
- Nested Level A repetitions per Level B case: `1`
- Completed repetitions: `0`
- Partial repetitions: `1`
- Failed repetitions: `0`

## Higher-Level Level B Comparability

- Comparison status: `Insufficient Data`
- Comparison type: `not_available`
- Compared executions: `EXEC-0010`

## Nested Level A Repeatability

- Completed nested reports: `1`
- Failed nested reports: `0`
- Nested comparison statuses: `Insufficient Data`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `13.707` / `0.0`
- Alert -> memory preserved mean/std: `923.793` / `0.0`
- Alert -> case sealed mean/std: `1436.852` / `0.0`
- Total duration mean/std: `1540.091` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.0` / `0.0`
- Weighted recoverability mean/std: `0.0` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `0`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0010`
- Case ID: `case-f4c20014`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260903T221019Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
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
- Alert -> memory start: `13.707` seconds
- Alert -> case sealed: `1436.852` seconds
- Total repetition duration: `1540.091` seconds
- Warnings: `Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Semantic reconstruction has not been generated. | Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Integrity and custody validation supports evidentiary trust in the preserved artifacts; it does not by itself confirm the causal hypothesis. | This was the final repetition of the campaign -- case case-f4c20014 was kept fully intact as a complete result sample instead of being reduced to the lightweight bundle.`
