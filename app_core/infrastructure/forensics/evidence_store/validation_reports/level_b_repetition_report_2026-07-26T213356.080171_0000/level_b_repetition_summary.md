# Level B Repetition Report

- Generated at: `2026-07-26T22:56:26.420402+00:00`
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
- Alert -> memory start mean/std: `50.049` / `0.0`
- Alert -> memory preserved mean/std: `630.997` / `0.0`
- Alert -> case sealed mean/std: `1667.218` / `0.0`
- Total duration mean/std: `3390.217` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.875` / `0.0`
- Weighted recoverability mean/std: `0.8767` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `1`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0001`
- Case ID: `case-32000bce`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260726T213411Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
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
- Recoverability / weighted / confidence: `0.875` / `0.8767` / `0.8052`
- Relations recovered/degraded/ambiguous/missing: `7` / `0` / `1` / `0`
- Alert -> memory start: `50.049` seconds
- Alert -> case sealed: `1667.218` seconds
- Total repetition duration: `3390.217` seconds
- Warnings: `7 of 8 expected causal edges were recovered. The reconstruction is mostly supported by preserved evidence, but it still does not establish absolute causality. | Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Temporal synchronization is not reliable. The preserved max clock offset is approximately 0s, which makes event ordering ambiguous for causal edges whose timestamps fall within the 2s uncertainty window. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
