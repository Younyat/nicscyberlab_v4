# Level B Repetition Report

- Generated at: `2026-07-20T01:43:24.082953+00:00`
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
- Compared executions: `EXEC-0001`

## Nested Level A Repeatability

- Completed nested reports: `1`
- Failed nested reports: `0`
- Nested comparison statuses: `Insufficient Data`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `39.648` / `0.0`
- Alert -> memory preserved mean/std: `621.546` / `0.0`
- Alert -> case sealed mean/std: `1807.486` / `0.0`
- Total duration mean/std: `3440.763` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.625` / `0.0`
- Weighted recoverability mean/std: `0.6096` / `0.0`
- Degraded relations total: `2`
- Ambiguous relations total: `1`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0001`
- Case ID: `case-18995bf6`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260720T002332Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `partial`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Insufficient Data` / `not_enough_generated_level_a_repetitions`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.625` / `0.6096` / `0.7289`
- Relations recovered/degraded/ambiguous/missing: `5` / `2` / `1` / `0`
- Alert -> memory start: `39.648` seconds
- Alert -> case sealed: `1807.486` seconds
- Total repetition duration: `3440.763` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
