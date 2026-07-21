# Level B Repetition Report

- Generated at: `2026-07-15T05:40:36.553680+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `fbbfc3a04a139edc617da291`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `2`
- Nested Level A repetitions per Level B case: `2`
- Completed repetitions: `0`
- Partial repetitions: `2`
- Failed repetitions: `0`

## Higher-Level Level B Comparability

- Comparison status: `Not Comparable`
- Comparison type: `exploratory_comparison_only`
- Compared executions: `EXEC-0020, EXEC-0021`

## Nested Level A Repeatability

- Completed nested reports: `0`
- Failed nested reports: `2`
- Nested comparison statuses: `not_available, not_available`

## Aggregate Timing Metrics

- `N_B`: `2`
- Alert -> memory start mean/std: `16.9095` / `12.195471`
- Alert -> memory preserved mean/std: `264.4955` / `13.065212`
- Alert -> case sealed mean/std: `993.126` / `33.85203`
- Total duration mean/std: `1928.676` / `9.90798`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.375` / `0.0`
- Weighted recoverability mean/std: `0.3562` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `10`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0020`
- Case ID: `case-dd4145db`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260715T012413Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `2`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `failed` / `partial` / `completed`
- Analysis status: `partial`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `failed`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `skipped`
- Recoverability / weighted / confidence: `0.375` / `0.3562` / `0.4633`
- Relations recovered/degraded/ambiguous/missing: `3` / `0` / `5` / `0`
- Alert -> memory start: `8.286` seconds
- Alert -> case sealed: `969.189` seconds
- Total repetition duration: `1921.67` seconds
- Warnings: `Only 3 of 8 expected causal edges were fully recovered. The result is useful for audit and degradation analysis, but it must not be presented as strong causal reconstruction. | Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Temporal synchronization is not reliable. The preserved max clock offset is approximately 638.581s, which makes event ordering ambiguous for causal edges whose timestamps fall within the 640.581s uncertainty window. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Memory analysis exists, but no effective plugin output was produced. | nested Level A scientific report did not complete successfully for this Level B case | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 2

- Execution ID: `EXEC-0021`
- Case ID: `case-d0d70395`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260715T033741Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `2`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `failed` / `partial` / `completed`
- Analysis status: `partial`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `failed`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.375` / `0.3562` / `0.4633`
- Relations recovered/degraded/ambiguous/missing: `3` / `0` / `5` / `0`
- Alert -> memory start: `25.533` seconds
- Alert -> case sealed: `1017.063` seconds
- Total repetition duration: `1935.682` seconds
- Warnings: `Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Temporal synchronization is not reliable. The preserved max clock offset is approximately 627.933s, which makes event ordering ambiguous for causal edges whose timestamps fall within the 629.933s uncertainty window. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Disk content reflects host/acquisition context, not the OT causal attack path; relation to trigger path is indirect at best. | nested Level A scientific report did not complete successfully for this Level B case | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
