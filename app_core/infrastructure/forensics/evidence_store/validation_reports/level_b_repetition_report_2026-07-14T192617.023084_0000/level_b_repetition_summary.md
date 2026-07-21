# Level B Repetition Report

- Generated at: `2026-07-14T20:11:53.527674+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `not_available`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `2`
- Nested Level A repetitions per Level B case: `2`
- Completed repetitions: `0`
- Partial repetitions: `0`
- Failed repetitions: `1`

## Higher-Level Level B Comparability

- Comparison status: `Insufficient Data`
- Comparison type: `not_available`
- Compared executions: `not_available`

## Nested Level A Repeatability

- Completed nested reports: `0`
- Failed nested reports: `0`
- Nested comparison statuses: `not_available`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `0.0` / `0.0`
- Alert -> memory preserved mean/std: `0.0` / `0.0`
- Alert -> case sealed mean/std: `0.0` / `0.0`
- Total duration mean/std: `18.184` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.0` / `0.0`
- Weighted recoverability mean/std: `0.0` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `0`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0018`
- Case ID: `not_created`
- Status: `failed`
- Scientific case status: `diagnostic_failed`
- Attack output: `app_core/infrastructure/attack/outputs/20260714T200130Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `10`
- Trigger alert detected: `False`
- Trigger rule/severity: `None` / `unknown`
- Automatic acquisition started: `False`
- Memory / network / disk acquisition: `skipped` / `skipped` / `skipped`
- Analysis status: `failed`
- Reconstruction status: `failed`
- Nested Level A status: `not_available`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `None` / `None` / `None`
- Relations recovered/degraded/ambiguous/missing: `0` / `0` / `0` / `0`
- Alert -> memory start: `None` seconds
- Alert -> case sealed: `None` seconds
- Total repetition duration: `18.184` seconds
- Warnings: `Forensic preservation was never armed because DFIR mode remained OFF during the repeated attack attempts. Alerts may have been observed, but the platform was not in forensic intervention mode.`
- Blockers: `dfir_mode_off_during_trigger_arming`
