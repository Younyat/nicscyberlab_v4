# Level B Execution Audit

## Executive Summary

- Campaign ID: `CMP-20260720-230112-DFA1`
- Requested Level B repetitions: `2`
- Attempted repetitions: `2`
- Not-started repetitions: `0`
- Completed / partial / failed: `0` / `2` / `0`
- Job status: `running`

## Where The Workflow Stopped

- Phase: `Generate Level B report`
- Detail: `Aggregating per-repetition timing, acquisition, reconstruction, warnings, blockers, and case outputs into the final Level B validation report bundle.`

## Generated Outputs

- Level B execution workspaces: `EXEC-0005, EXEC-0006`
- Forensic cases created: `case-dbe63124, case-0376b413`
- Cases with analysis outputs present: `case-dbe63124, case-0376b413`
- Nested Level A reports completed: `CMP-20260721-080312-DBF9, CMP-20260721-093835-0C24`
- Heavy-case cleanups completed: `case-dbe63124, case-0376b413`
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
