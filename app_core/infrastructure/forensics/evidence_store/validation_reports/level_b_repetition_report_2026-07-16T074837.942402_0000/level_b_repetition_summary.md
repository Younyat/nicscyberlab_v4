# Level B Repetition Report

- Generated at: `2026-07-16T11:07:46.896611+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `fbbfc3a04a139edc617da291`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `2`
- Nested Level A repetitions per Level B case: `2`
- Completed repetitions: `0`
- Partial repetitions: `1`
- Failed repetitions: `0`

## Higher-Level Level B Comparability

- Comparison status: `Insufficient Data`
- Comparison type: `not_available`
- Compared executions: `EXEC-0029`

## Nested Level A Repeatability

- Completed nested reports: `0`
- Failed nested reports: `1`
- Nested comparison statuses: `not_available`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `34.167` / `0.0`
- Alert -> memory preserved mean/std: `591.123` / `0.0`
- Alert -> case sealed mean/std: `3367.708` / `0.0`
- Total duration mean/std: `5789.641` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.375` / `0.0`
- Weighted recoverability mean/std: `0.3562` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `5`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0029`
- Case ID: `case-b5946a11`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260716T075930Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `2`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `partial` / `completed`
- Analysis status: `completed`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `failed`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `skipped`
- Recoverability / weighted / confidence: `0.375` / `0.3562` / `0.4915`
- Relations recovered/degraded/ambiguous/missing: `3` / `0` / `5` / `0`
- Alert -> memory start: `34.167` seconds
- Alert -> case sealed: `3367.708` seconds
- Total repetition duration: `5789.641` seconds
- Warnings: `Only 3 of 8 expected causal edges were fully recovered. The result is useful for audit and degradation analysis, but it must not be presented as strong causal reconstruction. | Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Temporal synchronization is not reliable. The preserved max clock offset is approximately 648.997s, which makes event ordering ambiguous for causal edges whose timestamps fall within the 650.997s uncertainty window. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here. | nested Level A scientific report did not complete successfully for this Level B case | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage. | Post-delete free-space cleanup on fuxa/plc did not fully succeed; the next repetition will retry it before launching the next attack.`
- Blockers: `Mandatory free-space cleanup failed before repetition 2; failed_roles=fuxa,plc.`
