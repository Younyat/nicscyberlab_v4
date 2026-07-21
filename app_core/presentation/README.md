# presentation

Flask blueprint registration and top-level HTTP routes (`api.py`, `foc_experimentation_api.py`, and others) that expose the `app_core/infrastructure/*` services to the frontend.

## Key parameters / gotchas

- **`foc_experimentation_api.py` is a thin pass-through layer** — most routes just call into `level_b_repetition_runner`/`level_a_scientific_report_service`/etc. and forward the `error` field from the result dict as the HTTP status. When a service function adds a new distinct error type, remember to give it its own status code here (e.g. 409 for "conflict, needs confirmation") instead of letting it fall into the generic 400 bucket — the frontend's generic error handler shows `data.message`, but the status code can matter for callers that branch on it.

## Change log

### 2026-07-16
- `api_foc_level_b_repetitions_run`: now passes `force_replace_active` through from the request body, and returns HTTP 409 (was going to fall through to 400) when `start_level_b_repetitions_job` reports `error: active_job_running`. **Why**: added an active-job guard in `foc_experimentation/level_b_repetition_runner.py` to stop two Level B repetition jobs running concurrently — see that module's README.

### 2026-07-19
- Registered `campaign_repetitions_bp` (new module, see `infrastructure/campaign_repetitions/README.md`) right next to `level_c_bp`, same try/except-wrapped pattern as every other optional blueprint here. **Why**: backs the new repetitions detail bell in `static/index.html`. Import-checked in isolation (module import + Flask test-client requests against all 4 new routes, including the 404 path) before touching the live server — actual reload deliberately deferred while a real campaign was still active, per the same-day entries in the other two READMEs above.
