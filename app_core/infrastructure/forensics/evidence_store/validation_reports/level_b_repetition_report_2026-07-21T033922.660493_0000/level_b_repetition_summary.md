# Level B Repetition Report

- Generated at: `2026-07-21T06:25:51.177315+00:00`
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
- Compared executions: `EXEC-0003, EXEC-0004`

## Nested Level A Repeatability

- Completed nested reports: `2`
- Failed nested reports: `0`
- Nested comparison statuses: `Comparable With Degradation, Comparable With Degradation`

## Aggregate Timing Metrics

- `N_B`: `2`
- Alert -> memory start mean/std: `14.0405` / `0.074246`
- Alert -> memory preserved mean/std: `506.243` / `56.854214`
- Alert -> case sealed mean/std: `1609.7355` / `168.50001`
- Total duration mean/std: `3135.9305` / `253.173219`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.625` / `0.0`
- Weighted recoverability mean/std: `0.6096` / `0.0`
- Degraded relations total: `4`
- Ambiguous relations total: `2`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0003`
- Case ID: `case-a0c098fc`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260721T033933Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
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
- Recoverability / weighted / confidence: `0.625` / `0.6096` / `0.7122`
- Relations recovered/degraded/ambiguous/missing: `5` / `2` / `1` / `0`
- Alert -> memory start: `13.988` seconds
- Alert -> case sealed: `1728.883` seconds
- Total repetition duration: `3314.951` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 2

- Execution ID: `EXEC-0004`
- Case ID: `case-e4ee21c5`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260721T050441Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
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
- Recoverability / weighted / confidence: `0.625` / `0.6096` / `0.7122`
- Relations recovered/degraded/ambiguous/missing: `5` / `2` / `1` / `0`
- Alert -> memory start: `14.093` seconds
- Alert -> case sealed: `1490.588` seconds
- Total repetition duration: `2956.91` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
