# Level B Repetition Report

- Generated at: `2026-07-15T12:32:17.653225+00:00`
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
- Compared executions: `EXEC-0022, EXEC-0023`

## Nested Level A Repeatability

- Completed nested reports: `0`
- Failed nested reports: `2`
- Nested comparison statuses: `not_available, not_available`

## Aggregate Timing Metrics

- `N_B`: `2`
- Alert -> memory start mean/std: `13.723` / `4.904493`
- Alert -> memory preserved mean/std: `568.5655` / `251.111296`
- Alert -> case sealed mean/std: `2493.6885` / `468.200149`
- Total duration mean/std: `3544.5265` / `462.60552`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.4375` / `0.088388`
- Weighted recoverability mean/std: `0.4144` / `0.082307`
- Degraded relations total: `0`
- Ambiguous relations total: `9`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0022`
- Case ID: `case-957aa122`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260715T072126Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `2`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `partial` / `completed`
- Analysis status: `partial`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `failed`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `skipped`
- Recoverability / weighted / confidence: `0.5` / `0.4726` / `0.5244`
- Relations recovered/degraded/ambiguous/missing: `4` / `0` / `4` / `0`
- Alert -> memory start: `10.255` seconds
- Alert -> case sealed: `2824.756` seconds
- Total repetition duration: `3871.638` seconds
- Warnings: `4 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Temporal synchronization is not reliable. The preserved max clock offset is approximately 639.627s, which makes event ordering ambiguous for causal edges whose timestamps fall within the 641.627s uncertainty window. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Memory analysis exists, but no effective plugin output was produced. | nested Level A scientific report did not complete successfully for this Level B case | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 2

- Execution ID: `EXEC-0023`
- Case ID: `case-aea54afa`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260715T100752Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `2`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `partial` / `completed`
- Analysis status: `partial`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `failed`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.375` / `0.3562` / `0.4558`
- Relations recovered/degraded/ambiguous/missing: `3` / `0` / `5` / `0`
- Alert -> memory start: `17.191` seconds
- Alert -> case sealed: `2162.621` seconds
- Total repetition duration: `3217.415` seconds
- Warnings: `Only 3 of 8 expected causal edges were fully recovered. The result is useful for audit and degradation analysis, but it must not be presented as strong causal reconstruction. | Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Temporal synchronization is not reliable. The preserved max clock offset is approximately 628.478s, which makes event ordering ambiguous for causal edges whose timestamps fall within the 630.478s uncertainty window. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Memory analysis exists, but no effective plugin output was produced. | nested Level A scientific report did not complete successfully for this Level B case | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
