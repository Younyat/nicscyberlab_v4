# Paper Evidence Package

## Executive summary

- Report ID: `paper-b-CMP-20260719-215231-55D0-2026-07-19T215251.056948_0000`
- Level requested: `B`
- Generated at: `2026-07-19T23:05:32.408119+00:00`
- Source campaign: `CMP-20260719-215231-55D0`
- Requested repetitions: `1`
- Completed / partial / failed: `0` / `1` / `0`
- Higher-level comparison status: `Insufficient Data`
- Nested Level A completed reports: `1`

## Reviewer-facing interpretation

### What does this level prove?

- Level B proves whether repeated execution of the same controlled incident in the same deployed scenario produces comparable new forensic cases and comparable reconstruction outputs.
- Level B also exposes trigger quality, alert-to-acquisition latency, preservation ordering, and cross-case comparability.

### What does this level not prove?

- Level B does not prove full redeployment reproducibility. That belongs to Level C.

### Cross-case scientific comparison

- Comparison type: `not_available`
- Comparison status: `Insufficient Data`
- Compared executions: `EXEC-0001`

### Operational latency and acquisition

- Alert -> memory start mean/std: `64.855` / `0.0`
- Alert -> case sealed mean/std: `1688.861` / `0.0`

### Nested Level A inside each Level B case

- Each Level B repetition generated a new case and then launched a nested Level A repeatability audit over that preserved case.
- Nested comparison statuses: `Insufficient Data`

### Which paper tables are supported by this output?

- `TAB-QUAL-POSITIONING`: support=`supported` | concern=`Clarifies what the system is intended to measure and what each module contributes.`
- `TAB-REQ-METRIC-MAP`: support=`supported` | concern=`Addresses reviewer concern that invariants and requirements were not operationalized.`
- `TAB-LEVEL-A-REPEATABILITY`: support=`supported` | concern=`Addresses whether results are stable without changing the preserved evidence.`
- `TAB-DIAGNOSTIC-INDICATORS`: support=`supported` | concern=`Addresses reviewer concern that 100% operational readiness was being conflated with complete causal reconstruction.`
- `TAB-RELATION-STATE-MATRIX`: support=`supported` | concern=`Addresses reviewer concern that abstract counts of recovered/degraded/missing relations lack operational and forensic meaning.`
- `TAB-OPER-LATENCY`: support=`supported` | concern=`Addresses reviewer concern that operational latency and trigger effectiveness were not quantified.`
- `TAB-ARTIFACT-SIZE-COVERAGE`: support=`supported` | concern=`Addresses whether evidence preservation and coverage are measurable rather than assumed.`
- `TAB-FAILURE-DEGRADATION`: support=`supported` | concern=`Directly addresses the reviewer concern about hidden failures and perfect binary success narratives.`
- `TAB-INVARIANT-RECOVERY`: support=`partial` | concern=`Addresses reviewer concern that semantic or forensic invariants were claimed without a concrete runtime operationalization trace.`
- `TAB-LEVEL-B-COMPARABILITY`: support=`supported` | concern=`Addresses reviewer concern that repeatability must include acquisition and preservation, not just reanalysis.`
- `TAB-LEVEL-C-REDEPLOYMENT`: support=`unsupported` | concern=`Addresses reviewer concern about full reproducibility beyond one deployment state.`

### Limitations and degradation

- warning: 5 of 8 expected causal edges were recovered. The reconstruction is partially supported and should be presented with explicit caveats on the degraded or ambiguous edges.
- warning: Integrity or custody validation remains partial.
- warning: At least one causal edge is temporally ambiguous under the preserved uncertainty window.
- warning: Some causal edges could not be temporally ordered because the required artifact timestamps were not available or not resolvable.
- warning: Modbus traffic is observed, but register and value precision are not confirmed by packet-level parsing.
- warning: Case-wide integrity or custody validation remains partial.
- warning: Integrity and custody validation remains partial for this case.
- warning: Heavy generated case artifacts were cleaned after nested Level A reporting so the next Level B repetition could create a fresh case without accumulating heavy storage.
