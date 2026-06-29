from __future__ import annotations

import json
import logging
import threading
import traceback
import uuid
from pathlib import Path

from .config import CAMPAIGNS_ROOT
from ..foc_reconstruction.foc_sources import utc_now

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}
_THREADS: dict[str, threading.Thread] = {}


class JobCancelled(Exception):
    pass


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def new_job(*, job_type: str, title: str, job_path: Path, meta: dict | None = None) -> dict:
    job_id = f"exp-{uuid.uuid4().hex[:12]}"
    payload = {
        "job_id": job_id,
        "job_type": job_type,
        "title": title,
        "status": "queued",
        "requested_at": utc_now(),
        "started_at": None,
        "finished_at": None,
        "current_phase": "queued",
        "progress_percent": 0.0,
        "warnings": [],
        "errors": [],
        "generated_artifacts": [],
        "meta": meta or {},
        "job_path": str(job_path),
    }
    with _LOCK:
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def update_job(job_id: str, job_path: Path, **changes) -> dict:
    with _LOCK:
        payload = dict(_JOBS.get(job_id) or {})
        if payload.get("hard_stop_locked") and not changes.pop("allow_post_stop_update", False):
            _JOBS[job_id] = payload
            _write_json(job_path, payload)
            return payload
        payload.update(changes)
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def append_job_list(job_id: str, job_path: Path, field: str, value) -> dict:
    with _LOCK:
        payload = dict(_JOBS.get(job_id) or {})
        if payload.get("hard_stop_locked"):
            _JOBS[job_id] = payload
            _write_json(job_path, payload)
            return payload
        items = list(payload.get(field) or [])
        items.append(value)
        payload[field] = items
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def get_job(job_id: str) -> dict | None:
    with _LOCK:
        cached = dict(_JOBS.get(job_id) or {})
    if cached:
        return cached
    # Under a multi-process server (e.g. gunicorn -w N), each worker keeps its
    # own in-memory _JOBS dict, so a job started by one worker is invisible to
    # a status poll handled by another -- the poll would otherwise report
    # job_not_found even while the job is genuinely running. Fall back to the
    # job file on disk, which every update already writes via _write_json,
    # mirroring evidence_lifecycle_dashboard.get_lifecycle_job()'s same
    # disk-fallback for the same reason.
    for job_path in CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json"):
        try:
            payload = json.loads(job_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict) and payload.get("job_id") == job_id:
            with _LOCK:
                _JOBS[job_id] = payload
            return payload
    return None


def job_cancel_requested(job_id: str) -> bool:
    payload = get_job(job_id) or {}
    return bool(payload.get("cancel_requested")) or str(payload.get("status") or "").lower() in {"cancel_requested", "cancelled", "stopped"}


def request_cancel(job_id: str) -> dict | None:
    payload = get_job(job_id)
    if not payload:
        return None
    job_path = Path(str(payload.get("job_path") or ""))
    status = str(payload.get("status") or "").lower()
    if status in {"completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"}:
        return payload
    return update_job(
        job_id,
        job_path,
        cancel_requested=True,
        cancel_requested_at=utc_now(),
        status="cancel_requested",
    )


def request_force_stop(job_id: str) -> dict | None:
    payload = get_job(job_id)
    if not payload:
        return None
    job_path = Path(str(payload.get("job_path") or ""))
    status = str(payload.get("status") or "").lower()
    if status in {"completed", "completed_with_degradation", "completed_with_failures", "failed", "cancelled", "stopped"}:
        return payload
    return update_job(
        job_id,
        job_path,
        cancel_requested=True,
        cancel_requested_at=utc_now(),
        force_stop_requested=True,
        force_stop_requested_at=utc_now(),
        status="stopped",
        finished_at=utc_now(),
        current_phase="force_stopped",
        current_phase_label="Force Stopped",
        current_phase_detail="A forced stop was requested by the operator. Nested scientific work was asked to stop, and the experimentation wrapper was closed immediately.",
        progress_percent=100.0,
        hard_stop_locked=True,
    )


def raise_if_cancelled(job_id: str, job_path: Path, *, phase_key: str | None = None, phase_label: str | None = None, detail: str | None = None) -> None:
    if not job_cancel_requested(job_id):
        return
    payload = get_job(job_id) or {}
    force_stop = bool(payload.get("force_stop_requested")) or str(payload.get("status") or "").lower() == "stopped"
    update_job(
        job_id,
        job_path,
        status="stopped" if force_stop else "cancelled",
        finished_at=utc_now(),
        current_phase=phase_key or ("force_stopped" if force_stop else "cancelled"),
        current_phase_label=phase_label or ("Force Stopped" if force_stop else "Cancelled"),
        current_phase_detail=detail or ("A forced stop was requested by the operator." if force_stop else "Job cancellation was requested by the operator."),
        progress_percent=100.0,
        hard_stop_locked=force_stop,
    )
    raise JobCancelled(detail or "job_cancelled")


def list_jobs() -> list[dict]:
    with _LOCK:
        return [dict(item) for item in _JOBS.values()]


def append_phase(job_id: str, job_path: Path, *, phase_key: str, phase_label: str, status: str, progress_percent: float, detail: str | None = None) -> dict:
    with _LOCK:
        payload = dict(_JOBS.get(job_id) or {})
        phases = list(payload.get("phase_statuses") or [])
        phases.append(
            {
                "phase_key": phase_key,
                "phase_label": phase_label,
                "status": status,
                "detail": detail,
                "updated_at": utc_now(),
                "progress_percent": progress_percent,
            }
        )
        payload["phase_statuses"] = phases
        payload["current_phase"] = phase_key
        payload["current_phase_label"] = phase_label
        payload["current_phase_detail"] = detail
        payload["progress_percent"] = progress_percent
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def start_job(job: dict, target) -> dict:
    job_id = str(job["job_id"])
    job_path = Path(job["job_path"])

    def runner():
        update_job(
            job_id,
            job_path,
            status="running",
            started_at=utc_now(),
            current_phase="starting",
            current_phase_label="Starting",
            current_phase_detail="Preparing experimentation job runner.",
            progress_percent=1.0,
            phase_statuses=[
                {
                    "phase_key": "starting",
                    "phase_label": "Starting",
                    "status": "running",
                    "detail": "Preparing experimentation job runner.",
                    "updated_at": utc_now(),
                    "progress_percent": 1.0,
                }
            ],
        )
        try:
            target(job_id, job_path)
        except JobCancelled:
            existing = get_job(job_id) or {}
            if str(existing.get("status") or "").lower() == "stopped":
                return
            update_job(
                job_id,
                job_path,
                status="cancelled",
                finished_at=utc_now(),
                current_phase="cancelled",
                current_phase_label="Cancelled",
                current_phase_detail="Job cancellation was requested by the operator.",
                progress_percent=100.0,
            )
        except Exception as exc:
            logger.exception("Experimentation job %s failed", job_id)
            update_job(
                job_id,
                job_path,
                status="failed",
                finished_at=utc_now(),
                current_phase="failed",
                progress_percent=100.0,
                errors=[{"message": str(exc), "traceback": traceback.format_exc(limit=20)}],
            )
        finally:
            with _LOCK:
                _THREADS.pop(job_id, None)

    thread = threading.Thread(target=runner, daemon=True, name=f"foc-exp-{job_id}")
    with _LOCK:
        _THREADS[job_id] = thread
    thread.start()
    return job
