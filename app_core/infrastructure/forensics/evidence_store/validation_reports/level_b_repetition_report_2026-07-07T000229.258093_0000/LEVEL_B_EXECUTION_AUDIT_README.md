# Level B Execution Audit

## Executive Summary

- Campaign ID: `CMP-20260707-000220-CBFB`
- Requested Level B repetitions: `10`
- Attempted repetitions: `10`
- Not-started repetitions: `0`
- Completed / partial / failed: `0` / `10` / `0`
- Job status: `running`

## Where The Workflow Stopped

- Phase: `Generate Level B report`
- Detail: `Aggregating per-repetition timing, acquisition, reconstruction, warnings, blockers, and case outputs into the final Level B validation report bundle.`

## Generated Outputs

- Level B execution workspaces: `EXEC-0001, EXEC-0002, EXEC-0003, EXEC-0004, EXEC-0005, EXEC-0006, EXEC-0007, EXEC-0008, EXEC-0009, EXEC-0010`
- Forensic cases created: `case-f9b84046, case-4bd7a2e5, case-d997e30f, case-e51b2792, case-7efda4ef, case-0f9a0a23, case-0baf5deb, case-1f159b69, case-7b45be16, case-11d0a562`
- Cases with analysis outputs present: `case-f9b84046, case-4bd7a2e5, case-d997e30f, case-e51b2792, case-7efda4ef, case-0f9a0a23, case-0baf5deb, case-1f159b69, case-7b45be16, case-11d0a562`
- Nested Level A reports completed: `CMP-20260707-003413-941B, CMP-20260707-013725-3103, CMP-20260707-023407-57F2, CMP-20260707-034341-2C79, CMP-20260707-044713-E8D3, CMP-20260707-054954-719C, CMP-20260707-064943-45B8, CMP-20260707-080204-64C7, CMP-20260707-090447-F7FE, CMP-20260707-101125-3A3A`
- Heavy-case cleanups completed: `case-f9b84046, case-4bd7a2e5, case-d997e30f, case-e51b2792, case-7efda4ef, case-0f9a0a23, case-0baf5deb, case-1f159b69, case-7b45be16, case-11d0a562`
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
