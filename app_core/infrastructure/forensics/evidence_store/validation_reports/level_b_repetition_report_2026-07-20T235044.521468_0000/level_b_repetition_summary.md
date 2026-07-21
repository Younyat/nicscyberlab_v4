# Level B Repetition Report

- Generated at: `2026-07-21T02:49:25.677927+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `3a0a8948a1b6f684462cd789`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `2`
- Nested Level A repetitions per Level B case: `2`
- Completed repetitions: `0`
- Partial repetitions: `2`
- Failed repetitions: `0`

## Higher-Level Level B Comparability

- Comparison status: `Comparable With Degradation`
- Comparison type: `exploratory_comparison_only`
- Compared executions: `EXEC-0001, EXEC-0002`

## Nested Level A Repeatability

- Completed nested reports: `2`
- Failed nested reports: `0`
- Nested comparison statuses: `Comparable With Degradation, Comparable With Degradation`

## Aggregate Timing Metrics

- `N_B`: `2`
- Alert -> memory start mean/std: `21.8365` / `9.730496`
- Alert -> memory preserved mean/std: `510.8` / `72.059838`
- Alert -> case sealed mean/std: `1700.1195` / `81.827104`
- Total duration mean/std: `3317.216` / `108.936871`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.625` / `0.0`
- Weighted recoverability mean/std: `0.6096` / `0.0`
- Degraded relations total: `4`
- Ambiguous relations total: `2`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0001`
- Case ID: `case-a7742447`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260720T235100Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
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
- Recoverability / weighted / confidence: `0.625` / `0.6096` / `0.712`
- Relations recovered/degraded/ambiguous/missing: `5` / `2` / `1` / `0`
- Alert -> memory start: `28.717` seconds
- Alert -> case sealed: `1757.98` seconds
- Total repetition duration: `3240.186` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 2

- Execution ID: `EXEC-0002`
- Case ID: `case-a81b135c`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260721T012055Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
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
- Recoverability / weighted / confidence: `0.625` / `0.6096` / `0.712`
- Relations recovered/degraded/ambiguous/missing: `5` / `2` / `1` / `0`
- Alert -> memory start: `14.956` seconds
- Alert -> case sealed: `1642.259` seconds
- Total repetition duration: `3394.246` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
