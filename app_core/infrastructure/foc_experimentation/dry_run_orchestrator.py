from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path

from .config import EVIDENCE_STORE_ROOT, campaign_config_path, campaign_dir, campaign_manifest_path, rel
from .execution_service import create_execution_from_campaign
from .job_runner import (
    append_phase,
    get_job,
    job_cancel_requested,
    list_jobs,
    new_job,
    raise_if_cancelled,
    start_job,
    update_job,
)
from .profile_builder import load_case_bundle, resolve_case_source
from .config import CASE_REGISTRY_PATH
from ..foc_causal_reconstruction.service import causal_status_payload, run_causal_reconstruction
from ..foc_reconstruction.foc_case_analysis import _list_case_entries
from ..foc_reconstruction.evidence_lifecycle_dashboard import get_lifecycle_job, start_full_lifecycle_job
from ..foc_reconstruction.foc_bootstrap import bootstrap_existing_context
from ..foc_reconstruction.foc_config import GENERATED_FILES
from ..foc_reconstruction.foc_manifest_manager import read_generated_json, regenerate_foc
from ..foc_reconstruction.foc_paths import project_path
from ..foc_reconstruction.foc_sources import utc_now

DEFAULT_CAUSAL_TIMEOUT_SECONDS = 1800
DEFAULT_LIFECYCLE_TIMEOUT_SECONDS = 3600
DEFAULT_POLL_SECONDS = 2.5


def _json_load(path: Path):
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _lookup_case_registry_card(case_id: str) -> dict | None:
    registry = _json_load(CASE_REGISTRY_PATH) or {}
    for entry in list(registry.get("entries") or []):
        if str(entry.get("case_id") or "") == str(case_id):
            return entry
    return None


def _load_campaign(campaign_id: str) -> tuple[dict, dict]:
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    config = _json_load(campaign_config_path(campaign_id)) or {}
    return manifest, config


def _running_job_for_campaign(campaign_id: str) -> dict | None:
    for item in list_jobs():
        meta = item.get("meta") or {}
        if str(meta.get("campaign_id")) != str(campaign_id):
            continue
        if str(item.get("job_type") or "").lower() == "level_a_scientific_report":
            continue
        if str(item.get("status")) in {"queued", "running"}:
            return item
    return None


def _phase(job_id: str, job_path: Path, key: str, label: str, status: str, percent: float, detail: str | None = None) -> None:
    append_phase(job_id, job_path, phase_key=key, phase_label=label, status=status, progress_percent=percent, detail=detail)


def _fail(job_id: str, job_path: Path, phase_key: str, phase_label: str, percent: float, reason: str, *, final_status: str = "failed") -> None:
    _phase(job_id, job_path, phase_key, phase_label, "failed", percent, reason)
    update_job(
        job_id,
        job_path,
        status=final_status,
        finished_at=utc_now(),
        current_phase=phase_key,
        current_phase_label=phase_label,
        current_phase_detail=reason,
        progress_percent=100.0,
        errors=[{"message": reason}],
    )


def _active_case_path() -> Path | None:
    ptr = EVIDENCE_STORE_ROOT / "_active_case.txt"
    try:
        raw = ptr.read_text(encoding="utf-8").splitlines()[0].strip()
    except Exception:
        return None
    if not raw:
        return None
    candidate = Path(raw).expanduser().resolve()
    return candidate if candidate.is_dir() else None


def _case_id_from_path(path: Path) -> str:
    target = str(path.resolve())
    for entry in _list_case_entries():
        candidate = str((project_path() / str(entry.get("path") or "")).resolve())
        if candidate == target:
            return str(entry.get("case_id"))
    return f"case-{hashlib.sha1(path.name.encode('utf-8')).hexdigest()[:8]}"


def _resolve_reference_case(config: dict, overrides: dict) -> dict | None:
    explicit_case_id = str(overrides.get("source_case_id") or config.get("base_case_id") or config.get("run_case_id") or "").strip()
    explicit_case_path = str(overrides.get("source_case_path") or config.get("base_case_path") or config.get("run_case_path") or "").strip()
    if explicit_case_id or explicit_case_path:
        source = resolve_case_source(case_id=explicit_case_id or None, case_path=explicit_case_path or None)
        if not source:
            return None
        resolved_path = Path(source["case_path"]).resolve()
        return {
            "case_id": explicit_case_id or _case_id_from_path(resolved_path),
            "case_path": str(resolved_path),
            "case_rel_path": source["case_rel_path"],
            "source_policy": "configured_reference_case",
        }
    active_case = _active_case_path()
    if not active_case:
        return None
    source = resolve_case_source(case_path=str(active_case))
    if not source:
        return None
    return {
        "case_id": _case_id_from_path(active_case),
        "case_path": str(active_case),
        "case_rel_path": source["case_rel_path"],
        "source_policy": "active_case_fallback",
    }


def _reference_case_failure_reason(config: dict, overrides: dict, level: str) -> str:
    explicit_case_id = str(overrides.get("source_case_id") or config.get("base_case_id") or config.get("run_case_id") or "").strip()
    explicit_case_path = str(overrides.get("source_case_path") or config.get("base_case_path") or config.get("run_case_path") or "").strip()
    if explicit_case_id or explicit_case_path:
        case_registry_card = _lookup_case_registry_card(explicit_case_id) if explicit_case_id else None
        registered_case_path = str((case_registry_card or {}).get("case_path") or "").strip()
        registered_abs = None
        if registered_case_path:
            try:
                registered_abs = str((project_path() / registered_case_path).resolve())
            except Exception:
                registered_abs = registered_case_path
        if level == "A":
            detail_parts = [
                f"Configured Level A base case {explicit_case_id or explicit_case_path} is no longer readable.",
            ]
            if explicit_case_path:
                detail_parts.append(f"Configured path: {explicit_case_path}.")
            elif registered_case_path:
                detail_parts.append(f"Registered path: {registered_case_path}.")
            if registered_abs:
                detail_parts.append(f"Resolved location: {registered_abs}.")
            detail_parts.append("Level A does not generate a new case and cannot rerun the scientific backend chain without that preserved case.")
            detail_parts.append("Existing execution profiles remain comparable, but a new Level A dry-run cannot be generated from lightweight memory alone.")
            return " ".join(detail_parts)
        return (
            f"Configured preserved reference case {explicit_case_id or explicit_case_path} is not readable. "
            "Level B/C can continue only with another preserved reference case, the active preserved case, or scaffold-only dry-run mode."
        )
    if level == "A":
        return (
            "No preserved base case could be resolved for this Level A dry-run execution. "
            "Level A requires a readable preserved base case because it reanalyzes existing evidence rather than generating a new case."
        )
    return "No preserved base case could be resolved for this dry-run execution."


def _wait_for_causal(case_id: str, case_path: Path, *, timeout_seconds: float = DEFAULT_CAUSAL_TIMEOUT_SECONDS, poll_seconds: float = DEFAULT_POLL_SECONDS, job_id: str | None = None, job_path: Path | None = None) -> dict:
    deadline = time.time() + timeout_seconds
    last = {"status": "unknown"}
    while time.time() < deadline:
        if job_id and job_path:
            raise_if_cancelled(job_id, job_path, phase_key="run_causal_reconstruction", phase_label="Run Causal Reconstruction", detail="Dry-run execution cancellation was requested while waiting for causal reconstruction.")
        payload = causal_status_payload(case_id, case_path) or {"status": "unknown"}
        last = payload
        if str(payload.get("status") or "").lower() not in {"running", "ready_to_run", "queued"}:
            return payload
        time.sleep(poll_seconds)
    last["status"] = last.get("status") or "timeout"
    last["reason"] = last.get("reason") or "Timed out while waiting for causal reconstruction."
    return last


def _wait_for_lifecycle(job_id: str, *, timeout_seconds: float = DEFAULT_LIFECYCLE_TIMEOUT_SECONDS, poll_seconds: float = DEFAULT_POLL_SECONDS, on_poll=None, parent_job_id: str | None = None, parent_job_path: Path | None = None) -> dict:
    deadline = time.time() + timeout_seconds
    last = {"status": "unknown"}
    while time.time() < deadline:
        if parent_job_id and parent_job_path and job_cancel_requested(parent_job_id):
            raise_if_cancelled(parent_job_id, parent_job_path, phase_key="run_full_evidence_lifecycle", phase_label="Run Full Evidence Lifecycle", detail="Dry-run execution cancellation was requested while waiting for the full evidence lifecycle.")
        payload = get_lifecycle_job(job_id)
        if isinstance(payload, dict):
            last = payload
            if callable(on_poll):
                try:
                    on_poll(payload)
                except Exception:
                    pass
            if str(payload.get("status") or "").lower() not in {"queued", "running"}:
                return payload
        time.sleep(poll_seconds)
    last["status"] = last.get("status") or "timeout"
    return last


def _sync_nested_lifecycle_trace(job_id: str, job_path: Path, lifecycle_payload: dict) -> None:
    trace = list(lifecycle_payload.get("phase_trace") or [])
    current_label = (
        lifecycle_payload.get("current_phase_label")
        or ((trace[-1] or {}).get("phase_label") if trace else None)
        or str(lifecycle_payload.get("current_phase") or "Run Full Evidence Lifecycle").replace("_", " ").title()
    )
    current_detail = (
        lifecycle_payload.get("current_phase_detail")
        or ((trace[-1] or {}).get("detail") if trace else None)
        or "Running nested full evidence lifecycle phases."
    )
    nested_progress = lifecycle_payload.get("progress_percent")
    if nested_progress is None:
        mapped_progress = 74.0
    else:
        try:
            mapped_progress = round(74.0 + (float(nested_progress) * 0.14), 1)
        except Exception:
            mapped_progress = 74.0
    update_job(
        job_id,
        job_path,
        lifecycle_job_id=lifecycle_payload.get("job_id"),
        lifecycle_phase_trace=trace,
        current_phase_label=f"Run Full Evidence Lifecycle · {current_label}",
        current_phase_detail=f"{current_label}: {current_detail}",
        progress_percent=mapped_progress,
    )


def start_dry_run_execution_job(campaign_id: str, overrides: dict | None = None) -> dict:
    overrides = dict(overrides or {})
    manifest, config = _load_campaign(campaign_id)
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    running = _running_job_for_campaign(campaign_id)
    if running:
        return running

    level = str(config.get("level") or manifest.get("level") or "A").upper()
    job = new_job(
        job_type="campaign_dry_run_execution",
        title=f"Run dry-run execution for {campaign_id}",
        job_path=campaign_dir(campaign_id) / "jobs" / f"job-{uuid.uuid4().hex[:8]}.json",
        meta={"campaign_id": campaign_id, "level": level, "dry_run": True},
    )

    def runner(job_id: str, job_path: Path) -> None:
        _run_dry_run_execution(job_id, job_path, campaign_id, manifest, config, overrides)

    return start_job(job, runner)


def run_dry_run_execution_inline(campaign_id: str, *, overrides: dict | None = None, title: str | None = None) -> dict:
    overrides = dict(overrides or {})
    manifest, config = _load_campaign(campaign_id)
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    level = str(config.get("level") or manifest.get("level") or "A").upper()
    job = new_job(
        job_type="campaign_dry_run_execution_inline",
        title=title or f"Run dry-run execution inline for {campaign_id}",
        job_path=campaign_dir(campaign_id) / "jobs" / f"job-inline-{uuid.uuid4().hex[:8]}.json",
        meta={"campaign_id": campaign_id, "level": level, "dry_run": True, "inline": True},
    )
    job_id = str(job["job_id"])
    job_path = Path(job["job_path"])
    update_job(
        job_id,
        job_path,
        status="running",
        started_at=utc_now(),
        current_phase="starting",
        current_phase_label="Starting",
        current_phase_detail="Preparing inline dry-run execution.",
        progress_percent=1.0,
        phase_statuses=[
            {
                "phase_key": "starting",
                "phase_label": "Starting",
                "status": "running",
                "detail": "Preparing inline dry-run execution.",
                "updated_at": utc_now(),
                "progress_percent": 1.0,
            }
        ],
    )
    try:
        _run_dry_run_execution(job_id, job_path, campaign_id, manifest, config, overrides)
    except Exception as exc:
        update_job(
            job_id,
            job_path,
            status="failed",
            finished_at=utc_now(),
            current_phase="failed",
            current_phase_label="Failed",
            current_phase_detail=str(exc),
            progress_percent=100.0,
            errors=[{"message": str(exc)}],
        )
    return get_job(job_id) or job


def _run_dry_run_execution(job_id: str, job_path: Path, campaign_id: str, manifest: dict, config: dict, overrides: dict) -> None:
    level = str(config.get("level") or manifest.get("level") or "A").upper()
    raise_if_cancelled(job_id, job_path, phase_key="starting", phase_label="Starting", detail="Dry-run execution was cancelled before it started.")
    _phase(job_id, job_path, "resolve_reference_case", "Resolve reference preserved case", "running", 4.0, "Resolving the preserved case that will feed the dry-run scientific replay.")
    reference_case = _resolve_reference_case(config, overrides)
    if not reference_case:
        if level in {"B", "C"}:
            _phase(job_id, job_path, "resolve_reference_case", "Resolve reference preserved case", "completed_with_degradation", 8.0, "No configured or active preserved case was available. Falling back to scaffold-only dry-run execution.")
            progress_hook = lambda key, label, percent, detail=None: _phase(job_id, job_path, key, label, "running", percent, detail)
            result = create_execution_from_campaign(campaign_id, overrides={**overrides, "_progress_hook": progress_hook})
            final_status = "completed" if result.get("status") == "completed" else "completed_with_degradation"
            _phase(job_id, job_path, "finalize", "Finalize dry-run execution", "completed", 100.0, "Scaffold-only dry-run execution registered because no preserved reference case was available.")
            update_job(
                job_id,
                job_path,
                current_phase="completed",
                current_phase_label="Completed",
                current_phase_detail="Scaffold-only dry-run execution registered.",
                progress_percent=100.0,
                status=final_status,
                finished_at=utc_now(),
                generated_artifacts=list((result.get("artifacts") or {}).values()),
                meta={**(manifest or {}), **result, "campaign_id": campaign_id, "dry_run_reference_mode": "scaffold_only_without_reference_case"},
            )
            return
        _fail(
            job_id,
            job_path,
            "resolve_reference_case",
            "Resolve reference preserved case",
            8.0,
            _reference_case_failure_reason(config, overrides, level),
        )
        return

    case_id = str(reference_case["case_id"])
    case_path = Path(reference_case["case_path"]).resolve()
    update_job(job_id, job_path, current_case_id=case_id)
    _phase(job_id, job_path, "resolve_reference_case", "Resolve reference preserved case", "completed", 10.0, f"Using preserved case {case_id} from {reference_case['source_policy']}.")

    raise_if_cancelled(job_id, job_path, phase_key="bootstrap_foc", phase_label="Bootstrap FOC", detail="Dry-run execution was cancelled before FOC bootstrap.")
    _phase(job_id, job_path, "bootstrap_foc", "Bootstrap FOC", "running", 16.0, "Calling the same backend bootstrap used by the FOC Reconstruction view.")
    try:
        bootstrap_result = bootstrap_existing_context(force=False)
        bootstrap_manifest = regenerate_foc(bootstrap_mode=True)
    except Exception as exc:
        _fail(job_id, job_path, "bootstrap_foc", "Bootstrap FOC", 16.0, f"FOC bootstrap failed: {exc}")
        return
    bootstrap_reason = bootstrap_result.get("status") or "bootstrapped"
    _phase(job_id, job_path, "bootstrap_foc", "Bootstrap FOC", "completed", 28.0, f"FOC bootstrap finished with status {bootstrap_reason}.")

    raise_if_cancelled(job_id, job_path, phase_key="regenerate_reconstruction", phase_label="Regenerate Reconstruction", detail="Dry-run execution was cancelled before reconstruction regeneration.")
    _phase(job_id, job_path, "regenerate_reconstruction", "Regenerate Reconstruction", "running", 34.0, "Calling the same reconstruction regeneration used by the FOC Reconstruction view.")
    try:
        current_manifest = read_generated_json(GENERATED_FILES["manifest"]) or bootstrap_manifest or {}
        regenerate_foc(bootstrap_mode=bool(current_manifest.get("bootstrap_mode")))
    except Exception as exc:
        _fail(job_id, job_path, "regenerate_reconstruction", "Regenerate Reconstruction", 34.0, f"FOC regeneration failed: {exc}")
        return
    _phase(job_id, job_path, "regenerate_reconstruction", "Regenerate Reconstruction", "completed", 46.0, "FOC reconstruction artifacts were regenerated successfully.")

    raise_if_cancelled(job_id, job_path, phase_key="run_causal_reconstruction", phase_label="Run Causal Reconstruction", detail="Dry-run execution was cancelled before causal reconstruction.")
    _phase(job_id, job_path, "run_causal_reconstruction", "Run Causal Reconstruction", "running", 54.0, f"Launching causal reconstruction for preserved case {case_id}.")
    try:
        causal_start = run_causal_reconstruction(case_id=case_id, case_path=case_path, degraded_ok=True, strict=False)
    except Exception as exc:
        _fail(job_id, job_path, "run_causal_reconstruction", "Run Causal Reconstruction", 54.0, f"Causal reconstruction failed to start: {exc}")
        return
    causal_status = _wait_for_causal(case_id, case_path, job_id=job_id, job_path=job_path)
    causal_state = str(causal_status.get("status") or causal_start.get("status") or "unknown").lower()
    causal_retry_required = False
    if causal_state in {"blocked_missing_analysis", "not_available"}:
        causal_retry_required = True
        _phase(job_id, job_path, "run_causal_reconstruction", "Run Causal Reconstruction", "completed_with_degradation", 62.0, causal_status.get("reason") or "Causal reconstruction needs refreshed lifecycle artifacts first; continuing with full evidence lifecycle.")
    elif causal_state in {"failed", "blocked_missing_ground_truth", "timeout"}:
        _fail(job_id, job_path, "run_causal_reconstruction", "Run Causal Reconstruction", 66.0, causal_status.get("reason") or "Causal reconstruction did not complete successfully.")
        return
    else:
        causal_phase_status = "completed_with_degradation" if causal_state == "completed_with_degradation" else "completed"
        _phase(job_id, job_path, "run_causal_reconstruction", "Run Causal Reconstruction", causal_phase_status, 68.0, causal_status.get("reason") or "Causal reconstruction completed.")

    raise_if_cancelled(job_id, job_path, phase_key="run_full_evidence_lifecycle", phase_label="Run Full Evidence Lifecycle", detail="Dry-run execution was cancelled before the full evidence lifecycle.")
    _phase(job_id, job_path, "run_full_evidence_lifecycle", "Run Full Evidence Lifecycle", "running", 74.0, f"Launching the same full evidence lifecycle backend used by the Executive Scientific Reconstruction Surface for {case_id}.")
    lifecycle_job = start_full_lifecycle_job(case_id, force_analysis=True, strict=False, degraded_ok=True)
    if lifecycle_job.get("error"):
        _fail(job_id, job_path, "run_full_evidence_lifecycle", "Run Full Evidence Lifecycle", 74.0, f"Could not start full evidence lifecycle: {lifecycle_job.get('error')}")
        return
    update_job(job_id, job_path, current_lifecycle_job_id=str(lifecycle_job.get("job_id") or ""))
    lifecycle_status = _wait_for_lifecycle(
        str(lifecycle_job.get("job_id")),
        on_poll=lambda payload: _sync_nested_lifecycle_trace(job_id, job_path, payload),
        parent_job_id=job_id,
        parent_job_path=job_path,
    )
    update_job(job_id, job_path, current_lifecycle_job_id=None)
    lifecycle_state = str(lifecycle_status.get("status") or "unknown").lower()
    if lifecycle_state in {"failed", "timeout"}:
        errors = lifecycle_status.get("errors") or []
        reason = "; ".join(str(item) for item in errors if item) or "Full evidence lifecycle did not complete successfully."
        _fail(job_id, job_path, "run_full_evidence_lifecycle", "Run Full Evidence Lifecycle", 86.0, reason)
        return
    lifecycle_phase_status = "completed_with_degradation" if lifecycle_state == "completed_with_degradation" else "completed"
    lifecycle_reason = "; ".join(str(item) for item in (lifecycle_status.get("warnings") or []) if item) or "Full evidence lifecycle completed."
    _phase(job_id, job_path, "run_full_evidence_lifecycle", "Run Full Evidence Lifecycle", lifecycle_phase_status, 88.0, lifecycle_reason)

    causal_final_phase_status = "completed"
    if causal_retry_required:
        raise_if_cancelled(job_id, job_path, phase_key="rerun_causal_reconstruction", phase_label="Rerun Causal Reconstruction", detail="Dry-run execution was cancelled before causal reconstruction retry.")
        _phase(job_id, job_path, "rerun_causal_reconstruction", "Rerun Causal Reconstruction", "running", 90.0, "Retrying causal reconstruction after the refreshed evidence lifecycle outputs were generated.")
        try:
            rerun_start = run_causal_reconstruction(case_id=case_id, case_path=case_path, degraded_ok=True, strict=False)
        except Exception as exc:
            _fail(job_id, job_path, "rerun_causal_reconstruction", "Rerun Causal Reconstruction", 90.0, f"Causal reconstruction retry failed to start: {exc}")
            return
        rerun_status = _wait_for_causal(case_id, case_path, job_id=job_id, job_path=job_path)
        rerun_state = str(rerun_status.get("status") or rerun_start.get("status") or "unknown").lower()
        if rerun_state in {"failed", "blocked_missing_ground_truth", "blocked_missing_analysis", "not_available", "timeout"}:
            _fail(job_id, job_path, "rerun_causal_reconstruction", "Rerun Causal Reconstruction", 92.0, rerun_status.get("reason") or "Causal reconstruction retry did not complete successfully.")
            return
        causal_final_phase_status = "completed_with_degradation" if rerun_state == "completed_with_degradation" else "completed"
        _phase(job_id, job_path, "rerun_causal_reconstruction", "Rerun Causal Reconstruction", causal_final_phase_status, 94.0, rerun_status.get("reason") or "Causal reconstruction retry completed.")
    else:
        causal_final_phase_status = "completed_with_degradation" if causal_state == "completed_with_degradation" else "completed"

    raise_if_cancelled(job_id, job_path, phase_key="finalize", phase_label="Finalize dry-run execution", detail="Dry-run execution was cancelled before execution registration.")
    progress_hook = lambda key, label, percent, detail=None: _phase(job_id, job_path, key, label, "running", min(98.0, percent), detail)
    result = create_execution_from_campaign(
        campaign_id,
        overrides={
            **overrides,
            "source_case_id": case_id,
            "source_case_path": str(case_path),
            "_progress_hook": progress_hook,
        },
    )
    final_status = "completed"
    if result.get("status") != "completed" or causal_final_phase_status != "completed" or lifecycle_phase_status != "completed":
        final_status = "completed_with_degradation"
    _phase(job_id, job_path, "finalize", "Finalize dry-run execution", "completed", 100.0, "Dry-run execution registered from refreshed FOC, causal reconstruction, and evidence lifecycle outputs.")
    update_job(
        job_id,
        job_path,
        current_phase="completed",
        current_phase_label="Completed",
        current_phase_detail="Dry-run execution registered from refreshed scientific outputs.",
        progress_percent=100.0,
        status=final_status,
        finished_at=utc_now(),
        generated_artifacts=list((result.get("artifacts") or {}).values()),
        meta={
            "campaign_id": campaign_id,
            "level": level,
            "reference_case_id": case_id,
            "reference_case_path": rel(case_path),
            "dry_run_reference_mode": reference_case["source_policy"],
            **result,
        },
    )
