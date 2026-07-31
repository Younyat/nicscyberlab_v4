# Level B Repetition Report

- Generated at: `2026-07-28T17:38:53.657372+00:00`
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
- Compared executions: `EXEC-0002`

## Nested Level A Repeatability

- Completed nested reports: `1`
- Failed nested reports: `0`
- Nested comparison statuses: `Insufficient Data`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `47.566` / `0.0`
- Alert -> memory preserved mean/std: `629.829` / `0.0`
- Alert -> case sealed mean/std: `1427.481` / `0.0`
- Total duration mean/std: `3373.934` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.875` / `0.0`
- Weighted recoverability mean/std: `0.8767` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `1`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0002`
- Case ID: `case-9f9b5c30`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260728T161917Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `completed`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Insufficient Data` / `not_enough_generated_level_a_repetitions`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.875` / `0.8767` / `0.8759`
- Relations recovered/degraded/ambiguous/missing: `7` / `0` / `1` / `0`
- Alert -> memory start: `47.566` seconds
- Alert -> case sealed: `1427.481` seconds
- Total repetition duration: `3373.934` seconds
- Warnings: `Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Disk content reflects host/acquisition context, not the OT causal attack path; relation to trigger path is indirect at best. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
