# Level B Repetition Report

- Generated at: `2026-07-19T08:26:57.564653+00:00`
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
- Compared executions: `EXEC-0039, EXEC-0040`

## Nested Level A Repeatability

- Completed nested reports: `2`
- Failed nested reports: `0`
- Nested comparison statuses: `Comparable With Degradation, Comparable With Degradation`

## Aggregate Timing Metrics

- `N_B`: `2`
- Alert -> memory start mean/std: `46.481` / `17.503721`
- Alert -> memory preserved mean/std: `583.06` / `92.1247`
- Alert -> case sealed mean/std: `1705.324` / `81.836296`
- Total duration mean/std: `3154.466` / `190.990956`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.625` / `0.0`
- Weighted recoverability mean/std: `0.6096` / `0.0`
- Degraded relations total: `4`
- Ambiguous relations total: `2`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0039`
- Case ID: `case-f4c0ebb8`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260719T002404Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
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
- Recoverability / weighted / confidence: `0.625` / `0.6096` / `0.6902`
- Relations recovered/degraded/ambiguous/missing: `5` / `2` / `1` / `0`
- Alert -> memory start: `58.858` seconds
- Alert -> case sealed: `1647.457` seconds
- Total repetition duration: `3019.415` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 2

- Execution ID: `EXEC-0040`
- Case ID: `case-b589e6ca`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260719T042354Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
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
- Recoverability / weighted / confidence: `0.625` / `0.6096` / `0.6902`
- Relations recovered/degraded/ambiguous/missing: `5` / `2` / `1` / `0`
- Alert -> memory start: `34.104` seconds
- Alert -> case sealed: `1763.191` seconds
- Total repetition duration: `3289.517` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Integrity or custody validation remains partial. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Case-wide integrity or custody validation remains partial. | Integrity and custody validation remains partial for this case. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`
