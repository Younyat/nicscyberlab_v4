# Level B Execution Audit

## Executive Summary

- Campaign ID: `CMP-20260723-210541-1465`
- Requested Level B repetitions: `1`
- Attempted repetitions: `1`
- Not-started repetitions: `0`
- Completed / partial / failed: `0` / `0` / `1`
- Job status: `running`

## Where The Workflow Stopped

- Phase: `Generate Level B report`
- Detail: `Aggregating per-repetition timing, acquisition, reconstruction, warnings, blockers, and case outputs into the final Level B validation report bundle.`

## Generated Outputs

- Level B execution workspaces: `EXEC-UNKNOWN-1`
- Forensic cases created: `none`
- Cases with analysis outputs present: `none`
- Nested Level A reports completed: `none`
- Heavy-case cleanups completed: `none`
- Final Level B report bundle emitted: `True`

## Missing Or Pending Outputs

- Remaining Level B repetitions not started: `0`
- Missing nested Level A reports: `0`
- Missing heavy-case cleanups: `0`
- Higher-level comparison ready: `False`

## Reviewer-Facing Interpretation

This audit distinguishes between physical preservation success and full Level B scientific completion. A preserved case may already contain memory, disk, network, alerts, and partial or complete analysis outputs while the orchestration still fails before nested Level A, cleanup, or cross-run comparison complete.

## Last Failed Repetition

- Repetition number: `1`
- Execution ID: `EXEC-UNKNOWN-1`
- Case ID: `not_available`
- Case path: `not_available`
- Analysis status observed: `failed`
- Nested Level A status: `not_generated`
- Cleanup status: `not_generated`
- Warnings: `Unexpected repetition failure: Command '['ssh', '-i', '/home/younes/.ssh/my_key', '-o', 'StrictHostKeyChecking=no', 'ubuntu@10.0.2.44', "REMOTE_DUMP='' bash -s"]' timed out after 120 seconds`
- Blockers: `Command '['ssh', '-i', '/home/younes/.ssh/my_key', '-o', 'StrictHostKeyChecking=no', 'ubuntu@10.0.2.44', "REMOTE_DUMP='' bash -s"]' timed out after 120 seconds`

## Expected Professional End State

For a successful Level B batch, every requested repetition should create a fresh case, complete multilayer analysis, complete nested Level A reporting, clean the heavy case while retaining a lightweight bundle, and then continue to the next repetition until the batch report can compare all runs.
