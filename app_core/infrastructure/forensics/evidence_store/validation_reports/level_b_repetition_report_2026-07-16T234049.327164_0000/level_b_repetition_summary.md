# Level B Repetition Report

- Generated at: `2026-07-17T05:36:30.181830+00:00`
- Scenario ID: `industrial_file`
- Scenario fingerprint: `f4d1853b4e08969fab527d26`
- Attack profile: `T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Requested repetitions: `2`
- Nested Level A repetitions per Level B case: `2`
- Completed repetitions: `0`
- Partial repetitions: `1`
- Failed repetitions: `1`

## Higher-Level Level B Comparability

- Comparison status: `Insufficient Data`
- Comparison type: `not_available`
- Compared executions: `EXEC-0033`

## Nested Level A Repeatability

- Completed nested reports: `0`
- Failed nested reports: `1`
- Nested comparison statuses: `not_available`

## Aggregate Timing Metrics

- `N_B`: `2`
- Alert -> memory start mean/std: `25.834` / `0.0`
- Alert -> memory preserved mean/std: `854.564` / `0.0`
- Alert -> case sealed mean/std: `3253.122` / `0.0`
- Total duration mean/std: `4509.888` / `0.0`

## Aggregate Reconstruction Metrics

- Recoverability mean/std: `0.625` / `0.0`
- Weighted recoverability mean/std: `0.6027` / `0.0`
- Degraded relations total: `0`
- Ambiguous relations total: `3`
- Missing relations total: `0`

## Per-Repetition Results

### Repetition 1

- Execution ID: `EXEC-0033`
- Case ID: `case-6fbc1dca`
- Status: `partial`
- Scientific case status: `scientifically_complete`
- Attack output: `app_core/infrastructure/attack/outputs/20260717T000219Z_T0831_MANIPULATION_OF_CONTROL_MODBUS`
- Trigger arming attempts: `3`
- Trigger alert detected: `True`
- Trigger rule/severity: `86601` / `high`
- Automatic acquisition started: `True`
- Memory / network / disk acquisition: `completed` / `partial` / `completed`
- Analysis status: `failed`
- Reconstruction status: `completed_with_degradation`
- Nested Level A status: `failed`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `skipped`
- Recoverability / weighted / confidence: `0.625` / `0.6027` / `0.6202`
- Relations recovered/degraded/ambiguous/missing: `5` / `0` / `3` / `0`
- Alert -> memory start: `25.834` seconds
- Alert -> case sealed: `3253.122` seconds
- Total repetition duration: `4509.888` seconds
- Warnings: `5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges. | Semantic reconstruction has not been generated. | At least one causal edge is temporally ambiguous under the preserved uncertainty window. | Temporal synchronization is not reliable. The preserved max clock offset is approximately 624.919s, which makes event ordering ambiguous for causal edges whose timestamps fall within the 626.919s uncertainty window. | Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing. | Modbus register and value precision (declared in ground truth as register=4, expected_value=30) is not confirmed by packet-level parsing; only the presence of Modbus traffic is verified here. | nested Level A scientific report did not complete successfully for this Level B case (status=failed) — reason: child_job_timeout: stuck at 'Refresh or load multilayer analysis' — Run Dry-Run Execution 2/2: Regenerate Reconstruction — Calling the same reconstruction regeneration used by the FOC Reconstruction view. | Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.`

### Repetition 2

- Execution ID: `EXEC-UNKNOWN-2`
- Case ID: `not_created`
- Status: `failed`
- Scientific case status: `diagnostic_failed`
- Attack output: `not_available`
- Trigger arming attempts: `0`
- Trigger alert detected: `False`
- Trigger rule/severity: `None` / `unknown`
- Automatic acquisition started: `False`
- Memory / network / disk acquisition: `skipped` / `skipped` / `skipped`
- Analysis status: `failed`
- Reconstruction status: `failed`
- Nested Level A status: `not_available`
- Nested Level A comparison: `not_available` / `not_available`
- Previous heavy case cleaned before next repetition: `not_applicable`
- Recoverability / weighted / confidence: `None` / `None` / `None`
- Relations recovered/degraded/ambiguous/missing: `0` / `0` / `0` / `0`
- Alert -> memory start: `None` seconds
- Alert -> case sealed: `None` seconds
- Total repetition duration: `None` seconds
- Warnings: `Unexpected repetition failure: [Errno 2] No such file or directory: '/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260717-040617-551F/jobs/level-a-scientific-report-2026-07-17T040617.783163_0000.json.tmp' -> '/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260717-040617-551F/jobs/level-a-scientific-report-2026-07-17T040617.783163_0000.json'`
- Blockers: `[Errno 2] No such file or directory: '/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260717-040617-551F/jobs/level-a-scientific-report-2026-07-17T040617.783163_0000.json.tmp' -> '/home/younes/nicscyberlab_v3/app_core/infrastructure/forensics/evidence_store/repetition_campaigns/CMP-20260717-040617-551F/jobs/level-a-scientific-report-2026-07-17T040617.783163_0000.json'`
