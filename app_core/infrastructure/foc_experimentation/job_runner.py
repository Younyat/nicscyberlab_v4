from __future__ import annotations

import json
import logging
import threading
import traceback
import uuid
from pathlib import Path

from ..foc_reconstruction.foc_sources import utc_now

logger = logging.getLogger(__name__)

_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}
_THREADS: dict[str, threading.Thread] = {}


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
        payload.update(changes)
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def append_job_list(job_id: str, job_path: Path, field: str, value) -> dict:
    with _LOCK:
        payload = dict(_JOBS.get(job_id) or {})
        items = list(payload.get(field) or [])
        items.append(value)
        payload[field] = items
        _JOBS[job_id] = payload
    _write_json(job_path, payload)
    return payload


def get_job(job_id: str) -> dict | None:
    with _LOCK:
        return dict(_JOBS.get(job_id) or {}) or None


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
