# Level B Repetition Report

- Generated at: `2026-07-21T10:15:41.113855+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `f4d1853b4e08969fab527d26`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `2`
- Nested Level A repetitions per Level B case: `2`
- Completed repetitions: `0`
- Partial repetitions: `2`
- Failed repetitions: `0`

## Higher-Level Level B Comparability

- Comparison status: `Comparable With Degradation`
- Comparison type: `exploratory_comparison_only`
- Compared executions: `EXEC-0005, EXEC-0006`

## Nested Level A Repeatability

- Completed nested reports: `2`
- Failed nested reports: `0`
- Nested comparison statuses: `Comparable With Degradation, Comparable With Degradation`

## Aggregate Timing Metrics

- `N_B`: `2`
- Alert -> memory start mean/std: `14.6705` / `0.376888`
- Alert -> memory preserved mean/std: `578.5905` / `82.221669`
- Alert -> case sealed mean/std: `1673.8585` / `531.340541`
- Total duration mean/std: `3327.0055` / `774.066258`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.5625` / `0.088388`
- Weighted recoverability mean/std: `0.56165` / `0.067812`
- Degraded relations total: `5`
- Ambiguous relations total: `2`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0005`
- Case ID: `case-dbe63124`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260721T071658Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `partial`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Comparable With Degradation` / `direct_level_a_repeatability_comparison`
- Previous heavy case cleaned before next repetition: `skipped`
- Recoverability / weighted / confidence: `0.5` / `0.5137` / `0.5704`
- Relations recovered/degraded/ambiguous/missing: `4` / `3` / `1` / `0`
- Alert -> memory start: `14.404` seconds
- Alert -> case sealed: `1298.144` seconds
- Total repetition duration: `2779.658` seconds
- Warnings: `4 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Temporal synchronization is not reliable. The preserved max clock offset is approximately 0s, which makes event ordering ambiguous for causal edges whose timestamps fall within the 2s uncertainty window. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 2

- Execution ID: `EXEC-0006`
- Case ID: `case-0376b413`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260721T083359Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `partial`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Comparable With Degradation` / `direct_level_a_repeatability_comparison`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.625` / `0.6096` / `0.7123`
- Relations recovered/degraded/ambiguous/missing: `5` / `2` / `1` / `0`
- Alert -> memory start: `14.937` seconds
- Alert -> case sealed: `2049.573` seconds
- Total repetition duration: `3874.353` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
