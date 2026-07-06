# Level B Execution Audit

## Executive Summary

- Campaign ID: `CMP-20260705-214036-62E8`
- Requested Level B repetitions: `6`
- Attempted repetitions: `6`
- Not-started repetitions: `0`
- Completed / partial / failed: `0` / `6` / `0`
- Job status: `running`

## Where The Workflow Stopped

- Phase: `Generate Level B report`
- Detail: `Aggregating per-repetition timing, acquisition, reconstruction, warnings, blockers, and case outputs into the final Level B validation report bundle.`

## Generated Outputs

- Level B execution workspaces: `EXEC-0001, EXEC-0002, EXEC-0003, EXEC-0004, EXEC-0005, EXEC-0006`
- Forensic cases created: `case-ca69634c, case-97240455, case-01c88521, case-08eb88d0, case-d2454912, case-d70662d7`
- Cases with analysis outputs present: `case-ca69634c, case-97240455, case-01c88521, case-08eb88d0, case-d2454912, case-d70662d7`
- Nested Level A reports completed: `CMP-20260705-222605-6EBE, CMP-20260705-233527-6046, CMP-20260706-004341-C66C, CMP-20260706-015115-28F8, CMP-20260706-025943-4D8C, CMP-20260706-041301-AE84`
- Heavy-case cleanups completed: `case-ca69634c, case-97240455, case-01c88521, case-08eb88d0, case-d2454912, case-d70662d7`
- Final Level B report bundle emitted: `True`

## Missing Or Pending Outputs

- Remaining Level B repetitions not started: `0`
- Missing nested Level A reports: `0`
- Missing heavy-case cleanups: `0`
- Higher-level comparison ready: `False`

## Reviewer-Facing Interpretation

This audit distinguishes between physical preservation success and full Level B scientific completion. A preserved case may already contain memory, disk, network, alerts, and partial or complete analysis outputs while the orchestration still fails before nested Level A, cleanup, or cross-run comparison complete.

## Expected Professional End State

For a successful Level B batch, every requested repetition should create a fresh case, complete multilayer analysis, complete nested Level A reporting, clean the heavy case while retaining a lightweight bundle, and then continue to the next repetition until the batch report can compare all runs.
