# Level B Repetition Report

- Generated at: `2026-09-02T18:24:37.999023+00:00`
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
- Alert -> memory start mean/std: `29.301` / `0.0`
- Alert -> memory preserved mean/std: `360.15` / `0.0`
- Alert -> case sealed mean/std: `865.81` / `0.0`
- Total duration mean/std: `969.42` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.75` / `0.0`
- Weighted recoverability mean/std: `0.7466` / `0.0`
- Degraded relations total: `1`
- Ambiguous relations total: `1`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0002`
- Case ID: `case-57c08fa1`
- Status: `partial`
- Scientific case status: `diagnostic_failed`
- Attack output: `app_core/infrastructure/attack/outputs/20260902T180651Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `failed` / `completed` / `completed`
- Analysis status: `completed`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `completed_with_degradation`
- Nested Level A comparison: `Insufficient Data` / `not_enough_generated_level_a_repetitions`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.75` / `0.7466` / `0.7906`
- Relations recovered/degraded/ambiguous/missing: `6` / `1` / `1` / `0`
- Alert -> memory start: `29.301` seconds
- Alert -> case sealed: `865.81` seconds
- Total repetition duration: `969.42` seconds
- Warnings: `6 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Memory analysis exists but no effective dump analysis was recorded. | Critical evidence gate failed; this case is diagnostic/audit only and is not scientifically complete. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
- Blockers: `missing_critical_evidence=memory_artifacts_present`
