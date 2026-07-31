# Level B Repetition Report

- Generated at: `2026-07-29T02:40:00.282355+00:00`
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
- Compared executions: `EXEC-0006`

## Nested Level A Repeatability

- Completed nested reports: `0`
- Failed nested reports: `1`
- Nested comparison statuses: `not_available`

## Aggregate Timing Metrics

- `N_B`: `1`
- Alert -> memory start mean/std: `57.008` / `0.0`
- Alert -> memory preserved mean/std: `641.821` / `0.0`
- Alert -> case sealed mean/std: `1293.928` / `0.0`
- Total duration mean/std: `3404.839` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.875` / `0.0`
- Weighted recoverability mean/std: `0.8767` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `1`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0006`
- Case ID: `case-0c919ca3`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260729T011821Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `1`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `completed` / `completed`
- Analysis status: `failed`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `failed`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `0.875` / `0.8767` / `0.8761`
- Relations recovered/degraded/ambiguous/missing: `7` / `0` / `1` / `0`
- Alert -> memory start: `57.008` seconds
- Alert -> case sealed: `1293.928` seconds
- Total repetition duration: `3404.839` seconds
- Warnings: `7 of 8 expected causal edges were recovered. The reconstruction is mostly supported by preserved evidence, but it still does not establish absolute causality. | Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here. | nested Level A scientific report did not complete successfully for this Level B case (status=failed) — reason: level_a_dry_run_generation_failed:no_execution_was_generated | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
