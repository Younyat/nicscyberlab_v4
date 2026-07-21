import os
import re
import json
import time
import fcntl
import hashlib
import logging
import threading
import subprocess
import shutil
import uuid
from datetime import datetime, timezone
from flask import current_app
from urllib.parse import urlencode

from flask import Blueprint, request, jsonify, Response, send_from_directory
import openstack



from pathlib import Path
from ..foc_reconstruction.foc_paths import relative_path
from ..node_health.node_health_api import cleanup_node_free_space, resolve_node_for_remote_ops
from .volatility_symbols import (
    get_job as get_vol3_job,
    start_memory_analysis_job,
    start_symbol_generation_job,
    symbols_inventory_payload,
    SYMBOL_ROOT as VOL3_DYNAMIC_SYMBOL_ROOT,
)

# plotting (fig_forensic_cost_stacked.pdf)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt



logger = logging.getLogger("app_logger")

forensics_bp = Blueprint("forensics", __name__)



# ============================================================
# PATHS
# ============================================================

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))





FORENSICS_SCRIPTS_DIR = os.path.join(REPO_ROOT, "app_core", "infrastructure", "forensics", "scripts")





SCENARIO_DIR = os.path.join(REPO_ROOT, "scenario")
SCENARIO_FILE = os.path.join(SCENARIO_DIR, "scenario_file.json")

TOOLS_TMP_DIR = os.path.join(REPO_ROOT, "tools-installer-tmp")
INSTALLED_DIR = os.path.join(REPO_ROOT, "tools-installer", "installed")

EVIDENCE_ROOT = os.path.join(REPO_ROOT, "app_core", "infrastructure", "forensics", "evidence_store")
CAMPAIGNS_ROOT = Path(EVIDENCE_ROOT) / "repetition_campaigns"
DFIR_AUTO_DECISIONS_ROOT = Path(EVIDENCE_ROOT) / "_dfir_auto_decisions"


os.makedirs(EVIDENCE_ROOT, exist_ok=True)
DFIR_AUTO_DECISIONS_ROOT.mkdir(parents=True, exist_ok=True)


# ============================================================
# ACTIVE CASE POINTER (evidence_store/_active_case.txt)
# ============================================================

ACTIVE_CASE_PTR = os.path.join(EVIDENCE_ROOT, "_active_case.txt")
ACTIVE_PRESERVATION_PTR = os.path.join(EVIDENCE_ROOT, "_active_preservation.json")
STALE_PLACEHOLDER_CASE_MIN_AGE_SECONDS = 30
MEMORY_BUILD_MIN_FREE_MB = 1200

def set_active_case_dir(case_dir: str) -> None:
    """
    Guarda el puntero al CASE activo en:
      app_core/infrastructure/forensics/evidence_store/_active_case.txt

    - Escribe una ruta absoluta (1 línea).
    - No lanza excepciones (fail-safe).
    """
    try:
        case_dir = os.path.abspath((case_dir or "").strip())
        if not case_dir:
            return

        # Asegura que el case existe (si no existe, no escribimos puntero)
        if not os.path.isdir(case_dir):
            return

        os.makedirs(os.path.dirname(ACTIVE_CASE_PTR), exist_ok=True)

        with open(ACTIVE_CASE_PTR, "w", encoding="utf-8") as f:
            f.write(case_dir + "\n")
    except Exception:
        # Fail-safe: nunca romper el flujo de creación del caso
        pass


def _read_active_case_dir() -> str:
    try:
        if not os.path.isfile(ACTIVE_CASE_PTR):
            return ""
        raw = (Path(ACTIVE_CASE_PTR).read_text(encoding="utf-8") or "").strip()
        if not raw:
            return ""
        case_dir = os.path.abspath(raw)
        if os.path.isdir(case_dir):
            return case_dir
        try:
            Path(ACTIVE_CASE_PTR).unlink(missing_ok=True)
        except Exception:
            pass
        return ""
    except Exception:
        return ""


def _load_active_preservation_state() -> dict:
    try:
        if not os.path.isfile(ACTIVE_PRESERVATION_PTR):
            return {}
        payload = json.loads(Path(ACTIVE_PRESERVATION_PTR).read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _write_json_file(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _read_json_file(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _write_active_preservation_state(case_dir: str, *, run_id: str = "R1", state: str = "running", source: str = "dfir") -> dict:
    payload = {
        "case_dir": os.path.abspath(case_dir),
        "case_id": os.path.basename(os.path.abspath(case_dir)),
        "run_id": (run_id or "R1").strip() or "R1",
        "state": str(state or "running").strip().lower() or "running",
        "source": str(source or "dfir").strip() or "dfir",
        "started_at_utc": _utc_now_iso(),
    }
    try:
        Path(ACTIVE_PRESERVATION_PTR).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass
    return payload


def _clear_active_preservation_state(case_dir: str | None = None, *, run_id: str | None = None, final_state: str = "completed", reason: str | None = None) -> None:
    current = _load_active_preservation_state()
    if not current:
        return
    current_case_dir = os.path.abspath(str(current.get("case_dir") or ""))
    requested_case_dir = os.path.abspath(str(case_dir or "")) if case_dir else ""
    current_run_id = str(current.get("run_id") or "").strip()
    requested_run_id = str(run_id or "").strip()
    if requested_case_dir and current_case_dir and requested_case_dir != current_case_dir:
        return
    if requested_run_id and current_run_id and requested_run_id != current_run_id:
        return
    try:
        if current_case_dir and os.path.isdir(current_case_dir):
            _append_case_event(
                current_case_dir,
                "active_preservation_released",
                run_id=requested_run_id or current_run_id or "R1",
                meta={
                    "final_state": str(final_state or "completed"),
                    "reason": str(reason or "").strip() or None,
                },
            )
    except Exception:
        pass
    try:
        Path(ACTIVE_PRESERVATION_PTR).unlink(missing_ok=True)
    except Exception:
        pass


def release_stale_preservation_lock_for_case(case_id: str, *, reason: str | None = None) -> bool:
    """Public entry point for other modules' orphan watchdogs (e.g.
    job_runner._recover_orphaned_job) to release the active-preservation lock
    for a case whose owning job was just marked interrupted, without needing
    to resolve a case_dir themselves. No-op if the lock doesn't belong to
    this case_id (never releases someone else's lock by mistake).
    """
    current = _load_active_preservation_state()
    if not current or str(current.get("case_id") or "") != str(case_id or ""):
        return False
    _clear_active_preservation_state(
        case_dir=current.get("case_dir"),
        run_id=current.get("run_id"),
        final_state="stopped_orphaned_worker",
        reason=reason or "Owning job was marked interrupted by the job-runner orphan watchdog.",
    )
    return True


def _load_acquisition_profile_for_case(case_dir: str) -> dict:
    try:
        path = os.path.join(case_dir, "metadata", "acquisition_profile.json")
        if not os.path.isfile(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _case_event_present(case_dir: str, event_name: str) -> bool:
    for item in _read_jsonl_events(case_dir):
        if str(item.get("event") or "") == event_name:
            return True
    return False


def _case_preservation_in_progress(case_dir: str) -> bool:
    profile = _load_acquisition_profile_for_case(case_dir)
    if profile.get("memory_started_utc") and not profile.get("memory_completed_utc"):
        return True
    if profile.get("network_context_import_started_utc") and not profile.get("network_context_import_completed_utc"):
        return True
    if profile.get("disk_started_utc") and not profile.get("disk_completed_utc"):
        return True

    events = _read_jsonl_events(case_dir)
    present = {str(item.get("event") or "") for item in events if item.get("event")}
    starts = {
        "memory_start": ("memory_preserved", "memory_failed"),
        "disk_start": ("disk_preserved", "disk_failed"),
        "pcap_start": ("pcap_preserved", "pcap_failed"),
        "industrial_start": ("industrial_preserved", "industrial_failed"),
    }
    for start_evt, terminal in starts.items():
        if start_evt in present and not any(done_evt in present for done_evt in terminal):
            return True

    if _case_event_present(case_dir, "active_preservation_claimed") and not _case_event_present(case_dir, "active_preservation_released"):
        if not _case_event_present(case_dir, "dfir_orchestration_done"):
            return True

    return False


def _clear_active_case_pointer_if_matches(case_dir: str) -> None:
    try:
        current = _read_active_case_dir()
        if current and os.path.abspath(current) == os.path.abspath(case_dir):
            Path(ACTIVE_CASE_PTR).write_text("", encoding="utf-8")
    except Exception:
        pass


def _is_abandoned_placeholder_case(case_dir: str, *, min_age_seconds: int = STALE_PLACEHOLDER_CASE_MIN_AGE_SECONDS) -> bool:
    if not case_dir or not os.path.isdir(case_dir):
        return False
    manifest_path = os.path.join(case_dir, "manifest.json")
    custody_path = os.path.join(case_dir, "chain_of_custody.log")
    events_path = _events_path(case_dir)
    if os.path.isfile(manifest_path) or os.path.isfile(custody_path) or os.path.isfile(events_path):
        return False
    try:
        age_seconds = max(0.0, time.time() - os.path.getmtime(case_dir))
    except Exception:
        return False
    return age_seconds >= float(min_age_seconds)


_PRESERVATION_ORPHAN_GRACE_SECONDS = 180


def _latest_case_activity_ts(case_dir: str) -> float:
    """Cheap heartbeat proxy: mtime of the small metadata files every real
    acquisition/analysis step touches, not a full scan of (possibly
    multi-GB) evidence files. Same 'file activity as heartbeat' trick as
    foc_case_analysis._latest_analysis_activity, kept fast on purpose since
    this runs on every guard check.
    """
    latest = 0.0
    for rel in ("metadata/pipeline_events.jsonl", "metadata/acquisition_profile.json", "analysis/analysis_status.json"):
        try:
            ts = os.path.getmtime(os.path.join(case_dir, rel))
            latest = max(latest, ts)
        except OSError:
            continue
    return latest


def _active_preservation_guard(max_recent_seconds: int = 900) -> dict:
    current = _load_active_preservation_state()
    if not current:
        return {"allowed": True, "active": False, "reason": None}

    case_dir = os.path.abspath(str(current.get("case_dir") or ""))
    case_id = str(current.get("case_id") or os.path.basename(case_dir or "") or "not_available")
    run_id = str(current.get("run_id") or "R1").strip() or "R1"
    started_at = str(current.get("started_at_utc") or "").strip()
    started_epoch = iso_to_epoch(started_at) if started_at else 0.0
    age_seconds = max(0.0, time.time() - started_epoch) if started_epoch else None

    if not case_dir or not os.path.isdir(case_dir):
        _clear_active_preservation_state(case_dir=case_dir or None, run_id=run_id, final_state="stale_cleared", reason="preservation_case_directory_missing")
        return {"allowed": True, "active": False, "reason": None, "stale_lock_cleared": True}

    if _is_abandoned_placeholder_case(case_dir):
        _clear_active_case_pointer_if_matches(case_dir)
        try:
            shutil.rmtree(case_dir)
        except Exception:
            pass
        _clear_active_preservation_state(case_dir=case_dir, run_id=run_id, final_state="stale_cleared", reason="placeholder_case_pruned_without_manifest_or_events")
        return {"allowed": True, "active": False, "reason": None, "stale_lock_cleared": True, "placeholder_case_pruned": True}

    if _case_event_present(case_dir, "dfir_orchestration_done"):
        _clear_active_preservation_state(case_dir=case_dir, run_id=run_id, final_state="completed", reason="dfir_orchestration_done_recorded")
        return {"allowed": True, "active": False, "reason": None, "stale_lock_cleared": True}

    latest_activity_ts = _latest_case_activity_ts(case_dir)
    if latest_activity_ts and (time.time() - latest_activity_ts) > _PRESERVATION_ORPHAN_GRACE_SECONDS:
        reason = (
            f"No preservation activity recorded for case {case_id} in over {_PRESERVATION_ORPHAN_GRACE_SECONDS}s "
            "(pipeline_events.jsonl / acquisition_profile.json / analysis_status.json all stale) — the owning "
            "worker likely died or was replaced before finishing. Releasing the lock; nothing already preserved was deleted."
        )
        _clear_active_preservation_state(case_dir=case_dir, run_id=run_id, final_state="stopped_orphaned_worker", reason=reason)
        return {"allowed": True, "active": False, "reason": None, "stale_lock_cleared": True, "orphan_reason": reason}

    in_progress = _case_preservation_in_progress(case_dir)
    if not in_progress and age_seconds is not None and age_seconds > float(max_recent_seconds):
        _clear_active_preservation_state(case_dir=case_dir, run_id=run_id, final_state="stale_cleared", reason="preservation_lock_expired_without_active_steps")
        return {"allowed": True, "active": False, "reason": None, "stale_lock_cleared": True}

    reason = (
        f"Automatic forensic case creation is blocked because evidence preservation is already running for case {case_id}. "
        f"While artifacts are being preserved, DFIR is treated as OFF for new interventions. "
        f"Wait until the current preservation finishes before arming a new case."
    )
    return {
        "allowed": False,
        "active": True,
        "reason": reason,
        "case_dir": case_dir,
        "case_id": case_id,
        "run_id": run_id,
        "started_at_utc": started_at or None,
        "age_seconds": round(age_seconds, 3) if age_seconds is not None else None,
        "policy_state": "blocked_active_preservation",
    }


def _scientific_job_payloads() -> list[dict]:
    payloads: list[dict] = []
    seen_job_ids: set[str] = set()
    for job_path in CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json"):
        payload = _read_json_file(job_path)
        job_id = str(payload.get("job_id") or "").strip()
        if not job_id or job_id in seen_job_ids:
            continue
        seen_job_ids.add(job_id)
        payloads.append(payload)
    return payloads


def _running_scientific_jobs() -> list[dict]:
    running_statuses = {"queued", "running", "cancel_requested"}
    items: list[dict] = []

    # Level A / B jobs (stored under CAMPAIGNS_ROOT/CMP-*/jobs/*.json)
    for payload in _scientific_job_payloads():
        status = str(payload.get("status") or "").strip().lower()
        if status not in running_statuses:
            continue
        meta = payload.get("meta") or {}
        items.append(
            {
                "job_id": str(payload.get("job_id") or ""),
                "title": str(payload.get("title") or "Scientific workflow"),
                "status": status,
                "campaign_id": str(meta.get("campaign_id") or ""),
                "level": str(meta.get("level") or payload.get("level") or "unknown").strip().upper() or "UNKNOWN",
                "current_phase": str(payload.get("current_phase_label") or payload.get("current_phase") or "running"),
            }
        )

    # Level C jobs (stored under runtime/level_c_jobs/LC-*/job_state.json)
    lc_jobs_root = Path(REPO_ROOT) / "runtime" / "level_c_jobs"
    if lc_jobs_root.exists():
        for state_path in lc_jobs_root.glob("LC-*/job_state.json"):
            try:
                payload = _read_json_file(state_path)
                if not payload:
                    continue
                status = str(payload.get("status") or "").strip().lower()
                if status not in running_statuses:
                    continue
                items.append(
                    {
                        "job_id": str(payload.get("job_id") or state_path.parent.name),
                        "title": "Level C campaign",
                        "status": status,
                        "campaign_id": str((payload.get("config") or {}).get("campaign_id") or ""),
                        "level": "C",
                        "current_phase": str(payload.get("phase") or "running"),
                    }
                )
            except Exception:
                pass

    return items


def _list_case_dirs() -> list[Path]:
    root = Path(EVIDENCE_ROOT)
    items: list[Path] = []
    if not root.exists():
        return items
    for item in root.iterdir():
        if item.is_dir() and item.name.startswith("CASE-"):
            items.append(item.resolve())
    items.sort(key=lambda path: path.name, reverse=True)
    return items


def _preferred_existing_case() -> dict | None:
    active_case = _read_active_case_dir().strip()
    active_path = Path(active_case).resolve() if active_case else None
    candidates = [case_path for case_path in _list_case_dirs() if not _case_preservation_in_progress(str(case_path))]
    if active_path and active_path in candidates:
        preferred = active_path
    elif candidates:
        preferred = candidates[0]
    else:
        return None
    manifest = _read_manifest(str(preferred)) if (preferred / "manifest.json").is_file() else {}
    return {
        "case_dir": str(preferred),
        "case_id": preferred.name,
        "created_at": manifest.get("created_at"),
        "artifacts_count": len(list(manifest.get("artifacts") or [])),
        "is_active_pointer": bool(active_path and active_path == preferred),
    }


def _sanitize_dfir_alert_payload(payload: dict | None) -> dict:
    data = payload if isinstance(payload, dict) else {}
    return {
        "ts": str(data.get("ts") or "").strip() or None,
        "severity": str(data.get("severity") or "UNKNOWN").strip().upper() or "UNKNOWN",
        "score": data.get("score"),
        "forensics": str(data.get("forensics") or "").strip().upper() or None,
        "signature": str(data.get("signature") or "DFIR Alert").strip() or "DFIR Alert",
        "src": str(data.get("src") or "--").strip() or "--",
        "dst": str(data.get("dst") or "--").strip() or "--",
        "kind": str(data.get("kind") or "Detection alert").strip() or "Detection alert",
        "raw": str(data.get("raw") or "").strip() or None,
    }


def _new_dfir_auto_decision_id() -> str:
    return f"dfir-auto-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"


def _decision_path(decision_id: str) -> Path:
    return DFIR_AUTO_DECISIONS_ROOT / f"{decision_id}.json"


def _find_pending_dfir_auto_decision() -> dict | None:
    for path in sorted(DFIR_AUTO_DECISIONS_ROOT.glob("dfir-auto-*.json"), reverse=True):
        payload = _read_json_file(path)
        if str(payload.get("status") or "") == "pending_user_choice":
            payload.setdefault("decision_path", str(path))
            return payload
    return None


def _write_dfir_auto_decision(payload: dict) -> dict:
    decision_id = str(payload.get("decision_id") or "").strip()
    if not decision_id:
        decision_id = _new_dfir_auto_decision_id()
        payload["decision_id"] = decision_id
    payload["updated_at_utc"] = _utc_now_iso()
    path = _decision_path(decision_id)
    _write_json_file(path, payload)
    payload["decision_path"] = str(path)
    return payload


def _create_dfir_auto_decision(*, status: str, alert: dict, operator: str, stream_params: dict, context: dict, message: str, recommended_action: str | None = None) -> dict:
    payload = {
        "decision_id": _new_dfir_auto_decision_id(),
        "kind": "dfir_auto_case_creation_decision",
        "status": status,
        "created_at_utc": _utc_now_iso(),
        "updated_at_utc": _utc_now_iso(),
        "operator": operator,
        "alert": alert,
        "observed_alerts": [{"ts_utc": _utc_now_iso(), "alert": alert}],
        "stream_params": stream_params,
        "context": context,
        "message": message,
        "recommended_action": recommended_action,
        "decision_source": "index_dfir_auto",
    }
    return _write_dfir_auto_decision(payload)


def _build_dfir_auto_stream_url(*, stream_params: dict, decision_id: str | None = None, decision_resolution: str | None = None, alert: dict | None = None) -> str:
    query = {
        "run_id": str(stream_params.get("run_id") or "R1"),
        "traffic_seconds": int(stream_params.get("traffic_seconds") or 20),
        "mem_mode": str(stream_params.get("mem_mode") or "build"),
        "container_name": str(stream_params.get("container_name") or "nova_libvirt"),
    }
    if decision_id:
        query["decision_id"] = decision_id
    if decision_resolution:
        query["decision_resolution"] = decision_resolution
    alert = alert or {}
    for key, query_key in {
        "severity": "alert_severity",
        "signature": "alert_signature",
        "src": "alert_src",
        "dst": "alert_dst",
        "kind": "alert_kind",
        "forensics": "forensics",
    }.items():
        value = alert.get(key)
        if value:
            query[query_key] = str(value)
    if alert.get("score") is not None:
        query["alert_score"] = str(alert.get("score"))
    return "/api/dfir/orchestrator/auto/stream?" + urlencode(query)


def _delete_existing_case_for_dfir(case_dir: str) -> dict:
    target = Path(os.path.abspath(case_dir))
    if not target.is_dir():
        return {"deleted": False, "reason": "case_not_found", "case_dir": str(target)}
    guard = _active_preservation_guard()
    if not guard.get("allowed") and os.path.abspath(str(guard.get("case_dir") or "")) == str(target):
        return {"deleted": False, "reason": "active_preservation_in_progress", "case_dir": str(target)}
    try:
        active_case = _read_active_case_dir().strip()
        if active_case and os.path.abspath(active_case) == str(target):
            Path(ACTIVE_CASE_PTR).write_text("", encoding="utf-8")
    except Exception:
        pass
    size_before = 0
    try:
        for root, _dirs, files in os.walk(target):
            for file_name in files:
                try:
                    size_before += os.path.getsize(os.path.join(root, file_name))
                except Exception:
                    pass
    except Exception:
        pass
    shutil.rmtree(target)
    return {"deleted": True, "case_dir": str(target), "freed_bytes_estimated": size_before}


os.makedirs(TOOLS_TMP_DIR, exist_ok=True)
os.makedirs(INSTALLED_DIR, exist_ok=True)

DEFAULT_SCENARIO = {
    "scenario_name": "Default Empty Scenario",
    "description": "Escenario por defecto: no se encontró 'scenario_file.json'",
    "nodes": [{"data": {"id": "n1", "name": "Nodo Inicial"}, "position": {"x": 100, "y": 100}}],
    "edges": []
}

MOCK_SCENARIO_DATA = {}
try:
    with open(SCENARIO_FILE, "r") as f:
        MOCK_SCENARIO_DATA["file"] = json.load(f)
except Exception:
    MOCK_SCENARIO_DATA["file"] = DEFAULT_SCENARIO

# ============================================================
# OpenStack Connection
# ============================================================
def get_openstack_connection():
    return openstack.connection.Connection(
        auth_url=os.environ.get("OS_AUTH_URL"),
        project_name=os.environ.get("OS_PROJECT_NAME"),
        username=os.environ.get("OS_USERNAME"),
        password=os.environ.get("OS_PASSWORD"),
        region_name=os.environ.get("OS_REGION_NAME"),
        user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
        project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
        compute_api_version="2",
        identity_interface="public",
    )

# ============================================================
# TOOLS: tmp + installed merge (lo que tu UI necesita)
# ============================================================
def safe_instance_filename(instance_name: str) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", (instance_name or "").lower())
    return f"{safe_name}_tools.json"

def load_tools_tmp(instance_name: str) -> dict:
    path = os.path.join(TOOLS_TMP_DIR, safe_instance_filename(instance_name))
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("tools", {})
        if isinstance(tools, list):
            tools = {t: "pending" for t in tools}
        return tools if isinstance(tools, dict) else {}
    except Exception as e:
        logger.error(f"Error leyendo tools tmp de {instance_name}: {e}")
        return {}

def load_tools_installed(instance_id: str) -> dict:
    if not instance_id:
        return {}
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("installed_tools", {})
        return tools if isinstance(tools, dict) else {}
    except Exception as e:
        logger.error(f"Error leyendo installed tools de {instance_id}: {e}")
        return {}

def merge_tools_state(instance_id: str, instance_name: str) -> dict:
    tmp = load_tools_tmp(instance_name) or {}
    installed = load_tools_installed(instance_id) or {}

    merged = {}
    for tool, status in tmp.items():
        merged[tool] = status

    for tool, date in installed.items():
        if tool not in merged:
            merged[tool] = date
        else:
            if merged[tool] in ("error", "pending", "uninstalling"):
                continue
            merged[tool] = date

    return merged

# ============================================================
# OpenStack inventory endpoints
# ============================================================
def extract_subnet_cidr(conn, network_id: str):
    cidrs = []
    try:
        net = conn.network.get_network(network_id)
        subnet_ids = getattr(net, "subnet_ids", []) or []
        for sid in subnet_ids:
            try:
                sub = conn.network.get_subnet(sid)
                if getattr(sub, "cidr", None):
                    cidrs.append(sub.cidr)
            except Exception:
                continue
    except Exception:
        return []
    return cidrs

@forensics_bp.route("/api/openstack/instances/full", methods=["GET"])
def api_openstack_instances_full():
    conn = None
    try:
        conn = get_openstack_connection()
        out = []

        for server in conn.compute.servers(details=True):
            ip_private = None
            ip_floating = None
            networks = []

            addresses = server.addresses or {}
            for net_name, addrs in addresses.items():
                for a in addrs:
                    addr = a.get("addr")
                    ip_type = a.get("OS-EXT-IPS:type")
                    mac = a.get("OS-EXT-IPS-MAC:mac_addr") or a.get("mac_addr")
                    networks.append({"network": net_name, "ip": addr, "type": ip_type, "mac": mac})
                    if ip_type == "floating":
                        ip_floating = addr
                    else:
                        ip_private = addr

            flavor_obj = None
            try:
                flavor_ref = server.flavor["id"] if server.flavor else None
                if flavor_ref:
                    f = None
                    try:
                        f = conn.compute.get_flavor(flavor_ref)
                    except Exception:
                        for fl in conn.compute.flavors():
                            if fl.name == flavor_ref:
                                f = fl
                                break
                    if f:
                        flavor_obj = {
                            "id": f.id,
                            "name": f.name,
                            "vcpus": f.vcpus,
                            "ram_mb": f.ram,
                            "disk_gb": f.disk,
                            "ephemeral_gb": getattr(f, "ephemeral", 0),
                            "swap_mb": getattr(f, "swap", 0),
                        }
            except Exception as e:
                logger.warning(f"No se pudo leer flavor para {server.name}: {e}")

            volumes = []
            try:
                attached = getattr(server, "attached_volumes", []) or []
                for v in attached:
                    vid = v.get("id")
                    if not vid:
                        continue
                    try:
                        vol = conn.block_storage.get_volume(vid)
                        volumes.append({
                            "id": vol.id,
                            "name": vol.name,
                            "size_gb": vol.size,
                            "status": vol.status,
                            "bootable": vol.bootable,
                            "volume_type": getattr(vol, "volume_type", None),
                        })
                    except Exception:
                        volumes.append({"id": vid, "name": None, "size_gb": None, "status": "unknown", "bootable": None})
            except Exception as e:
                logger.warning(f"No se pudo leer volúmenes para {server.name}: {e}")

            try:
                sgs = [sg.get("name") for sg in (server.security_groups or []) if sg.get("name")]
            except Exception:
                sgs = []

            tools_state = merge_tools_state(server.id, server.name)

            out.append({
                "id": server.id,
                "name": server.name,
                "status": server.status,
                "image": server.image["id"] if server.image else None,
                "created_at": getattr(server, "created_at", None),
                "updated_at": getattr(server, "updated_at", None),
                "flavor": flavor_obj,
                "ip_private": ip_private,
                "ip_floating": ip_floating,
                "networks": networks,
                "security_groups": sgs,
                "volumes": volumes,
                "tools": tools_state,
                "evidence": {"memory": (server.status == "ACTIVE"), "disk": True, "network": len(networks) > 0}
            })

        return jsonify({"instances": out}), 200

    except Exception as e:
        logger.error(f"Error /api/openstack/instances/full: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@forensics_bp.route("/api/openstack/flavors", methods=["GET"])
def api_openstack_flavors():
    conn = None
    try:
        conn = get_openstack_connection()
        flavors = []
        for f in conn.compute.flavors(details=True):
            flavors.append({
                "id": f.id,
                "name": f.name,
                "vcpus": f.vcpus,
                "ram_mb": f.ram,
                "disk_gb": f.disk,
                "ephemeral_gb": getattr(f, "ephemeral", 0),
                "swap_mb": getattr(f, "swap", 0),
                "is_public": getattr(f, "is_public", None),
            })
        flavors.sort(key=lambda x: (x["vcpus"], x["ram_mb"], x["disk_gb"]))
        return jsonify({"flavors": flavors}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/flavors: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@forensics_bp.route("/api/openstack/networks", methods=["GET"])
def api_openstack_networks():
    conn = None
    try:
        conn = get_openstack_connection()
        networks = []
        for n in conn.network.networks():
            cidrs = extract_subnet_cidr(conn, n.id)
            networks.append({
                "id": n.id,
                "name": n.name,
                "status": getattr(n, "status", None),
                "is_router_external": getattr(n, "is_router_external", None),
                "provider_network_type": getattr(n, "provider_network_type", None),
                "provider_segmentation_id": getattr(n, "provider_segmentation_id", None),
                "cidrs": cidrs,
            })
        networks.sort(key=lambda x: x["name"] or "")
        return jsonify({"networks": networks}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/networks: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@forensics_bp.route("/api/openstack/security-groups", methods=["GET"])
def api_openstack_security_groups():
    conn = None
    try:
        conn = get_openstack_connection()
        sgs = []
        for sg in conn.network.security_groups():
            rules = getattr(sg, "security_group_rules", []) or []
            sgs.append({
                "id": sg.id,
                "name": sg.name,
                "description": getattr(sg, "description", ""),
                "rules_count": len(rules),
            })
        sgs.sort(key=lambda x: x["name"] or "")
        return jsonify({"security_groups": sgs}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/security-groups: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

@forensics_bp.route("/api/openstack/keypairs", methods=["GET"])
def api_openstack_keypairs():
    conn = None
    try:
        conn = get_openstack_connection()
        keys = []
        for k in conn.compute.keypairs():
            keys.append({
                "name": k.name,
                "fingerprint": getattr(k, "fingerprint", None),
                "type": getattr(k, "type", None),
            })
        keys.sort(key=lambda x: x["name"] or "")
        return jsonify({"keypairs": keys}), 200
    except Exception as e:
        logger.error(f"Error /api/openstack/keypairs: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

# ============================================================
# Tools tmp endpoints (para tu instalador actual)
# ============================================================
def save_as_installed(instance_id, instance_name, tool_name):
    os.makedirs(INSTALLED_DIR, exist_ok=True)
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")

    if os.path.exists(path):
        with open(path, "r") as f:
            data = json.load(f)
    else:
        data = {"instance_id": instance_id, "instance_name": instance_name, "installed_tools": {}}

    data["installed_tools"][tool_name] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def remove_from_installed(instance_id, tool_name):
    path = os.path.join(INSTALLED_DIR, f"{instance_id}.json")
    if not os.path.exists(path):
        return False
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if tool_name in data.get("installed_tools", {}):
            del data["installed_tools"][tool_name]
            with open(path, "w") as f:
                json.dump(data, f, indent=4)
            return True
    except Exception as e:
        logger.error(f"Error al actualizar JSON en desinstalación: {e}")
    return False

@forensics_bp.route("/api/add_tool_to_instance", methods=["POST"])
def add_tool_to_instance():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"status": "error", "msg": "JSON vacío"}), 400

        instance = data.get("instance") or data.get("name")
        tools_data = data.get("tools", {})

        os.makedirs(TOOLS_TMP_DIR, exist_ok=True)
        safe = re.sub(r"[^a-zA-Z0-9_-]", "_", instance.lower())
        path = os.path.join(TOOLS_TMP_DIR, f"{safe}_tools.json")

        if isinstance(tools_data, list):
            data["tools"] = {t: "pending" for t in tools_data}

        if not isinstance(data.get("tools"), dict):
            data["tools"] = {}

        with open(path, "w") as f:
            json.dump(data, f, indent=4)

        return jsonify({"status": "success", "saved": path, "current_tools": data["tools"]}), 200

    except Exception as e:
        return jsonify({"status": "error", "msg": str(e)}), 500

@forensics_bp.route("/api/get_tools_for_instance", methods=["GET"])
def get_tools_for_instance():
    instance_name = request.args.get("instance")
    if not instance_name:
        return jsonify({"tools": {}}), 200

    filename = safe_instance_filename(instance_name)
    path = os.path.join(TOOLS_TMP_DIR, filename)

    if not os.path.exists(path):
        return jsonify({"instance": instance_name, "tools": {}}), 200

    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("tools", {})
        if isinstance(tools, list):
            tools = {t: "pending" for t in tools}
        return jsonify({"instance": instance_name, "tools": tools}), 200
    except Exception as e:
        logger.error(f"Error leyendo tools tmp {path}: {e}")
        return jsonify({"instance": instance_name, "tools": {}}), 500

@forensics_bp.route("/api/read_tools_configs", methods=["GET"])
def read_tools_configs():
    if not os.path.exists(TOOLS_TMP_DIR):
        return jsonify({"files": []}), 200

    result = []
    for filename in os.listdir(TOOLS_TMP_DIR):
        if filename.endswith("_tools.json"):
            path = os.path.join(TOOLS_TMP_DIR, filename)
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                result.append({"file": filename, "instance": data.get("instance"), "tools": data.get("tools", {})})
            except Exception:
                continue
    return jsonify({"files": result}), 200

@forensics_bp.route("/api/install_tools", methods=["POST"])
def install_tools():
    data = request.get_json(force=True, silent=True) or {}
    instance_id = data.get("instance_id")
    instance_name = data.get("instance")
    tools_to_install = data.get("tools", [])

    script = os.path.join(REPO_ROOT, "tools-installer", "tools_install_master.sh")
    if not os.path.exists(script):
        return jsonify({"status": "error", "msg": "Script maestro no encontrado"}), 404

    try:
        os.chmod(script, 0o755)
    except Exception:
        pass

    def generate():
        process = subprocess.Popen(
            ["bash", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        for line in process.stdout:
            yield f"data: {line.strip()}\n\n"

        process.wait()

        if process.returncode == 0 and instance_id and instance_name:
            for t_name in tools_to_install:
                save_as_installed(instance_id, instance_name, t_name)
            yield "data: [SUCCESS] Registro actualizado en el sistema.\n\n"

        yield f"data: [FIN] Exit Code: {process.returncode}\n\n"

    return Response(generate(), mimetype="text/event-stream")

# ============================================================
# Forensic Host Tools (instalar en el host)
# ============================================================
FORENSIC_HOST_TOOLS = {
    "volatility3": {"check_cmd": ["bash", "-lc", "vol --info >/dev/null 2>&1"], "install_script": "forensic-host/install_volatility3.sh"},
    "autopsy":     {"check_cmd": ["bash", "-lc", "autopsy --help >/dev/null 2>&1"], "install_script": "forensic-host/install_autopsy.sh"},
    "tsk":         {"check_cmd": ["bash", "-lc", "tsk_recover -V >/dev/null 2>&1"], "install_script": "forensic-host/install_tsk.sh"},
    "tcpdump":     {"check_cmd": ["bash", "-lc", "tcpdump --version >/dev/null 2>&1"], "install_script": "forensic-host/install_tcpdump.sh"},
    "tshark":      {"check_cmd": ["bash", "-lc", "tshark --version >/dev/null 2>&1"], "install_script": "forensic-host/install_tshark.sh"},
    "termshark":   {"check_cmd": ["bash", "-lc", "termshark --version >/dev/null 2>&1"], "install_script": "forensic-host/install_termshark.sh"},
}

def host_tool_status(tool_name: str) -> dict:
    spec = FORENSIC_HOST_TOOLS.get(tool_name)
    if not spec:
        return {"name": tool_name, "status": "unknown"}
    try:
        r = subprocess.run(spec["check_cmd"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if r.returncode == 0:
            return {"name": tool_name, "status": "installed"}
        return {"name": tool_name, "status": "not_installed"}
    except Exception as e:
        return {"name": tool_name, "status": "error", "error": str(e)}

@forensics_bp.route("/api/host/forensic/tools", methods=["GET"])
def api_host_forensic_tools():
    out = [host_tool_status(t) for t in FORENSIC_HOST_TOOLS.keys()]
    return jsonify({"tools": out}), 200

@forensics_bp.route("/api/host/forensic/install", methods=["POST"])
def api_host_forensic_install():
    data = request.get_json(force=True, silent=True) or {}
    tool = data.get("tool")

    if tool not in FORENSIC_HOST_TOOLS:
        return jsonify({"status": "error", "msg": "Tool no permitida"}), 400

    script_rel = FORENSIC_HOST_TOOLS[tool]["install_script"]
    script_path = os.path.join(REPO_ROOT, script_rel)

    if not os.path.exists(script_path):
        return jsonify({"status": "error", "msg": f"Script no encontrado: {script_rel}"}), 404

    try:
        os.chmod(script_path, 0o755)
    except Exception:
        pass

    try:
        proc = subprocess.run(["bash", script_path], cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        status = host_tool_status(tool)
        return jsonify({
            "status": "success" if proc.returncode == 0 else "error",
            "tool": tool,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "after": status
        }), 200 if proc.returncode == 0 else 500
    except Exception as e:
        logger.error(f"Error instalando {tool} en host: {e}", exc_info=True)
        return jsonify({"status": "error", "msg": str(e)}), 500

# ============================================================
# DFIR / FORENSICS (lo que tu UI llama)
# ============================================================
def _is_safe_case_dir(case_dir: str) -> bool:
    if not case_dir:
        return False
    case_dir = os.path.normpath(case_dir)
    return case_dir.startswith(os.path.normpath(EVIDENCE_ROOT) + os.sep)

def _manifest_path(case_dir: str) -> str:
    return os.path.join(case_dir, "manifest.json")

def _read_manifest(case_dir: str) -> dict:
    mp = _manifest_path(case_dir)
    if not os.path.exists(mp):
        return {"case_dir": case_dir, "created_at": None, "artifacts": []}
    with open(mp, "r") as f:
        return json.load(f)

def _write_manifest(case_dir: str, manifest: dict):
    mp = _manifest_path(case_dir)
    with open(mp, "w") as f:
        json.dump(manifest, f, indent=2)

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()







def _add_artifact_fast(case_dir: str, rel_path: str, a_type: str, sha256: str = None, size: int = None):
    abs_path = os.path.join(case_dir, rel_path)
    if not os.path.exists(abs_path):
        return

    if size is None:
        try:
            size = os.path.getsize(abs_path)
        except Exception:
            size = None

    manifest = _read_manifest(case_dir)
    manifest.setdefault("artifacts", []).append({
        "type": a_type,
        "rel_path": rel_path,
        "sha256": sha256,
        "size": size,
        "ts": _utc_now_iso()
    })
    _write_manifest(case_dir, manifest)






# ============================================================
# CHAIN OF CUSTODY (append-only + hash chaining) + TIME SYNC
# ============================================================

# 2026-07-20: _append_custody_entry() used to read the last entry's hash and
# then append its own entry with zero locking around that read-then-write
# sequence. Two concurrent writers for the same case (two gunicorn workers, or
# two acquisition threads) could both read the same "last hash" before either
# had written, so the second writer's entry would silently chain from a stale
# (or, if the read raced with file creation, genesis "0"*64) prev_hash instead
# of the real current tail -- producing a permanently broken custody chain
# with no error at write time, only discovered later by
# foc_case_analysis._phase_integrity_custody() reporting custody_chain_valid:
# false. Confirmed live on a real case: entry 3 ("acquire_start") had
# prev_hash "0"*64 instead of chaining from entry 2 ("ir_inputs_preserved").
# Fixed with a per-case-dir threading.Lock (fast path, guards threads within
# one worker process) plus an fcntl.flock on the custody log itself (guards
# across separate gunicorn worker processes, which don't share Python
# objects) held around the entire read-last-hash + compute + append sequence.
_CUSTODY_THREAD_LOCKS_GUARD = threading.Lock()
_CUSTODY_THREAD_LOCKS: dict[str, threading.Lock] = {}


def _custody_thread_lock(case_dir: str) -> threading.Lock:
    key = os.path.abspath(case_dir)
    with _CUSTODY_THREAD_LOCKS_GUARD:
        lock = _CUSTODY_THREAD_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _CUSTODY_THREAD_LOCKS[key] = lock
        return lock


def _custody_path(case_dir: str) -> str:
    return os.path.join(case_dir, "chain_of_custody.log")

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _read_last_custody_hash(case_dir: str) -> str:
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        return "0" * 64
    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size <= 0:
                return "0" * 64
            back = min(8192, size)
            f.seek(-back, os.SEEK_END)
            tail = f.read().decode("utf-8", errors="ignore")
        lines = [ln for ln in tail.splitlines() if ln.strip()]
        if not lines:
            return "0" * 64
        last = json.loads(lines[-1])
        h = (last.get("entry_hash") or "").strip()
        return h if h else "0" * 64
    except Exception:
        return "0" * 64

def _ensure_custody_file(case_dir: str) -> None:
    if not _is_safe_case_dir(case_dir):
        return
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        try:
            Path(p).touch()
        except Exception:
            pass

def _append_custody_entry(
    case_dir: str,
    action: str,
    actor: str,
    run_id: str = "R1",
    artifact_rel: str = None,
    outcome: str = "ok",
    details: dict = None
) -> None:
    if not _is_safe_case_dir(case_dir):
        return
    _ensure_custody_file(case_dir)

    with _custody_thread_lock(case_dir):
        with open(_custody_path(case_dir), "a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                prev_hash = _read_last_custody_hash(case_dir)
                ts = _utc_now_iso()

                entry = {
                    "ts_utc": ts,
                    "ts_epoch": time.time(),
                    "run_id": (run_id or "R1"),
                    "actor": (actor or "unknown"),
                    "action": action,
                    "artifact_rel": artifact_rel,
                    "outcome": outcome,
                    "details": (details or {}),
                    "prev_hash": prev_hash,
                }

                payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
                entry["entry_hash"] = _sha256_hex(payload)

                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

def _register_custody_artifact(case_dir: str) -> None:
    rel = "chain_of_custody.log"
    abs_path = os.path.join(case_dir, rel)
    if not os.path.exists(abs_path):
        return
    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None
    _add_artifact_fast(case_dir, rel, "custody_log", sha256=sha, size=size)


def _parse_chrony_tracking_max_offset_ms(text: str):
    if not text:
        return None

    def to_ms(val: float, unit: str):
        u = (unit or "").strip().lower()
        if u in ("s", "sec", "secs", "second", "seconds"):
            return val * 1000.0
        if u in ("ms", "msec", "msecs", "millisecond", "milliseconds"):
            return val
        if u in ("us", "usec", "usecs", "microsecond", "microseconds"):
            return val / 1000.0
        if u in ("ns", "nsec", "nsecs", "nanosecond", "nanoseconds"):
            return val / 1_000_000.0
        return None

    max_ms = None

    # 1) Captura líneas típicas de chronyc tracking:
    #    "Last offset     : -0.000123456 seconds"
    #    "RMS offset      : 0.000456789 seconds"
    #    "System time     : 0.000001234 seconds slow of NTP time"
    patterns = [
        r"(?:Last|RMS)\s+offset\s*:\s*([+-]?\d+(?:\.\d+)?)\s*([a-zA-Z]+)",
        r"System\s+time\s*:\s*([+-]?\d+(?:\.\d+)?)\s*([a-zA-Z]+)",
        # fallback genérico
        r"offset\s*[:=]\s*([+-]?\d+(?:\.\d+)?)\s*([a-zA-Z]+)",
    ]

    for pat in patterns:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            try:
                v = abs(float(m.group(1)))
            except Exception:
                continue
            ms = to_ms(v, m.group(2))
            if ms is None:
                continue
            max_ms = ms if max_ms is None else max(max_ms, ms)

    return round(max_ms, 3) if max_ms is not None else None

def _export_time_sync(case_dir: str, run_id: str = "R1") -> dict:
    if not _is_safe_case_dir(case_dir):
        return {}

    ensure_case_layout(case_dir)

    rel = os.path.join("metadata", "time_sync.json")
    abs_path = os.path.join(case_dir, rel)

    chrony_tracking = ""
    chrony_sources = ""
    ntpq = ""
    timedatectl = ""

    try:
        r = subprocess.run(["bash", "-lc", "chronyc tracking 2>/dev/null || true"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        chrony_tracking = r.stdout or ""
    except Exception:
        pass

    try:
        r = subprocess.run(["bash", "-lc", "chronyc sources -v 2>/dev/null || true"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        chrony_sources = r.stdout or ""
    except Exception:
        pass

    try:
        r = subprocess.run(["bash", "-lc", "ntpq -pn 2>/dev/null || true"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ntpq = r.stdout or ""
    except Exception:
        pass

    try:
        r = subprocess.run(["bash", "-lc", "timedatectl 2>/dev/null || true"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        timedatectl = r.stdout or ""
    except Exception:
        pass

    max_offset_ms = _parse_chrony_tracking_max_offset_ms(chrony_tracking)

    payload = {
        "schema": "nics_time_sync_v1",
        "generated_at_utc": _utc_now_iso(),
        "run_id": (run_id or "R1"),
        "max_offset_ms": max_offset_ms,
        "raw": {
            "chronyc_tracking": chrony_tracking,
            "chronyc_sources_v": chrony_sources,
            "ntpq_pn": ntpq,
            "timedatectl": timedatectl,
        },
    }

    try:
        _atomic_write_json(abs_path, payload)
    except Exception:
        return {}

    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None

    try:
        _add_artifact_fast(case_dir, rel, "time_sync", sha256=sha, size=size)
    except Exception:
        pass

    try:
        _append_case_event(case_dir, "time_sync_exported", run_id=run_id, meta={
            "rel": rel, "sha256": sha, "size": size, "max_offset_ms": max_offset_ms
        })
    except Exception:
        pass

    return {"rel": rel, "sha256": sha, "size": size, "max_offset_ms": max_offset_ms}


def _write_case_digest(case_dir: str, run_id: str = "R1") -> dict:
    if not _is_safe_case_dir(case_dir):
        return {}

    ensure_case_layout(case_dir)

    rel = os.path.join("metadata", "case_digest.json")
    abs_path = os.path.join(case_dir, rel)

    def safe_sha(relp: str):
        ap = os.path.join(case_dir, relp)
        if not os.path.exists(ap):
            return None
        try:
            return _sha256_file(ap)
        except Exception:
            return None

    payload = {
        "schema": "nics_case_digest_v1",
        "generated_at_utc": _utc_now_iso(),
        "run_id": (run_id or "R1"),
        "digests": {
            "manifest_json_sha256": safe_sha("manifest.json"),
            "pipeline_events_jsonl_sha256": safe_sha(os.path.join("metadata", "pipeline_events.jsonl")),
            "chain_of_custody_log_sha256": safe_sha("chain_of_custody.log"),
            "time_sync_json_sha256": safe_sha(os.path.join("metadata", "time_sync.json")),
        }
    }

    try:
        _atomic_write_json(abs_path, payload)
    except Exception:
        return {}

    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None

    try:
        _add_artifact_fast(case_dir, rel, "case_digest", sha256=sha, size=size)
    except Exception:
        pass

    try:
        _append_case_event(case_dir, "case_digest_written", run_id=run_id, meta={"rel": rel, "sha256": sha, "size": size})
    except Exception:
        pass

    return {"rel": rel, "sha256": sha, "size": size}




def iso_to_epoch(iso_utc: str) -> float:
    s = (iso_utc or "").strip()
    if not s:
        return 0.0

    # Soporta:
    # - 2026-02-19T15:22:57Z
    # - 2026-02-19T15:22:57.367+0000
    # - 2026-02-19T15:22:57.367+00:00
    if s.endswith("Z"):
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    else:
        # normaliza +0000 -> +00:00
        if len(s) >= 5 and (s[-5] in ["+", "-"]) and s[-3] != ":":
            s = s[:-2] + ":" + s[-2:]
        dt = datetime.fromisoformat(s)

    return dt.astimezone(timezone.utc).timestamp()


def _utc_now_iso() -> str:
    # ISO UTC real (timezone-aware)
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_case_event(case_dir: str, event: str, run_id: str = "R1", meta: dict = None, ts_utc: str = None):
    """
    Append-only event log.
    Si ts_utc se proporciona, se usa ese timestamp (y su ts_epoch coherente).
    Si no, se usa 'now' en UTC.
    """
    os.makedirs(_case_meta_dir(case_dir), exist_ok=True)

    ts = (ts_utc or "").strip() or _utc_now_iso()
    rec = {
        "ts_utc": ts,
        "ts_epoch": iso_to_epoch(ts),
        "event": event,
        "run_id": (run_id or "R1"),
        "meta": meta or {}
    }
    with open(_events_path(case_dir), "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

def _get_or_set_alert_ts(case_dir: str, run_id: str = "R1", provided_alert_ts_utc: str = None) -> str:
    run_id = (run_id or "R1").strip() or "R1"
    alert_ts = (provided_alert_ts_utc or "").strip() or _utc_now_iso()

    ep = _events_path(case_dir)

    if os.path.exists(ep):
        try:
            with open(ep, "r", encoding="utf-8") as f:
                for line in f:
                    line = (line or "").strip()
                    if not line:
                        continue
                    r = json.loads(line)
                    if r.get("event") == "alert" and r.get("run_id") == run_id:
                        return (r.get("ts_utc") or alert_ts).strip() or alert_ts
        except Exception:
            pass

    _append_case_event(
        case_dir,
        "alert",
        run_id=run_id,
        meta={"source": "pipeline"},
        ts_utc=alert_ts,
    )

    _export_time_sync(case_dir, run_id=run_id)
    _append_custody_entry(case_dir, "alert", "forensics_api", run_id=run_id, details={"source": "pipeline"})
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    try:
        _save_ir_snapshot_to_case(case_dir, run_id=run_id)
    except Exception:
        pass

    return alert_ts







def _case_meta_dir(case_dir: str) -> str:
    return os.path.join(case_dir, "metadata")

def _events_path(case_dir: str) -> str:
    return os.path.join(_case_meta_dir(case_dir), "pipeline_events.jsonl")



def ensure_case_layout(case_dir: str) -> None:
    """
    Asegura que la estructura del caso existe y que dirs críticos no son ficheros.
    También asegura metadata/ir para snapshots de IR.
    """
    if not case_dir or not os.path.isdir(case_dir):
        return

    required_dirs = [
    "metadata",
    "metadata/ir",
    "metadata/ir/inputs",
    "metadata/fsr",
    "metadata/fsr/inputs",
    "network",
    "disk",
    "memory",
    "industrial",
    "analysis",
    "derived",
    ]

    for d in required_dirs:
        p = os.path.join(case_dir, d)

        if os.path.exists(p) and not os.path.isdir(p):
            try:
                os.remove(p)
            except Exception:
                raise

        os.makedirs(p, exist_ok=True)

    evp = _events_path(case_dir)
    if not os.path.exists(evp):
        try:
            Path(evp).touch()
        except Exception:
            pass



def register_derived(
    case_dir: str,
    rel_path: str,
    derived_type: str,
    run_id: str = "R1",
    source_rel: str = None,
    extra_meta: dict = None,
    compute_sha: bool = False,
) -> None:
    """
    Registra un artefacto DERIVADO (dentro de derived/ o analysis/ si lo decides así)
    en el manifest, y deja un evento append-only en pipeline_events.jsonl.

    - NO inventa nada: solo indexa lo que ya exista en disco.
    - Por defecto NO recalcula SHA (compute_sha=False) para no costear dumps grandes.
    """
    if not _is_safe_case_dir(case_dir):
        return
    if not rel_path:
        return

    ensure_case_layout(case_dir)

    abs_path = os.path.join(case_dir, rel_path)
    if not os.path.exists(abs_path):
        return

    sha = None
    size = None

    try:
        if os.path.isfile(abs_path):
            size = os.path.getsize(abs_path)
            if compute_sha:
                sha = _sha256_file(abs_path)
        else:
            # directorio: sin sha/size
            size = None
            sha = None
    except Exception:
        pass

    # Manifest
    manifest = _read_manifest(case_dir)
    manifest.setdefault("artifacts", []).append({
        "type": derived_type,
        "rel_path": rel_path,
        "sha256": sha,
        "size": size,
        "ts": _utc_now_iso()
    })
    _write_manifest(case_dir, manifest)

    # Evento pipeline (append-only)
    meta = {"rel": rel_path, "type": derived_type}
    if source_rel:
        meta["source_rel"] = source_rel
    if extra_meta and isinstance(extra_meta, dict):
        meta.update(extra_meta)

    try:
        _append_case_event(case_dir, "derived_registered", run_id=run_id, meta=meta)
    except Exception:
        pass








def _atomic_write_json(path: str, obj: dict):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)





#--------------------------------------------IR--------------------------------

import os
import json
import shutil


INDUSTRIAL_SCENARIO_DIR = os.path.join(REPO_ROOT, "industrial-scenario", "scenarios")
INDUSTRIAL_SCENARIO_FILE = os.path.join(INDUSTRIAL_SCENARIO_DIR, "industrial_industrial_file.json")


def _copy_json_file_to_case(case_dir: str, repo_root: str, src_rel: str, dst_rel: str) -> dict:
    """
    Copia SIMPLE (byte a byte) de un fichero JSON desde el repo hacia el case.
    - src_rel: ruta relativa al REPO_ROOT (ej: "scenario/scenario_file.json")
    - dst_rel: ruta relativa dentro del case (ej: "metadata/ir/inputs/scenario/scenario_file.json")
    No parsea JSON, no re-serializa, no cambia contenido.

    Devuelve metadatos de copia (y, si es posible, sha256 y size del destino).
    """
    out = {
        "src_rel": src_rel,
        "src_abs": None,
        "dst_rel": dst_rel,
        "dst_abs": None,
        "status": "missing",
        "reason": None,
        "sha256": None,
        "size": None,
    }

    try:
        src_abs = os.path.join(repo_root, src_rel)
        out["src_abs"] = src_abs

        if not os.path.exists(src_abs):
            out["reason"] = "not_found"
            return out
        if not os.path.isfile(src_abs):
            out["reason"] = "exists_but_not_file"
            return out

        dst_abs = os.path.join(case_dir, dst_rel)
        out["dst_abs"] = dst_abs
        os.makedirs(os.path.dirname(dst_abs), exist_ok=True)

        shutil.copy2(src_abs, dst_abs)
        out["status"] = "copied"

        try:
            out["sha256"] = _sha256_file(dst_abs)
            out["size"] = os.path.getsize(dst_abs)
        except Exception:
            out["sha256"] = None
            out["size"] = None

        return out

    except Exception as e:
        out["status"] = "error"
        out["reason"] = str(e)
        return out


def _copy_json_dir_to_case(case_dir: str, repo_root: str, src_dir_rel: str, dst_dir_rel: str) -> dict:
    """
    Copia SIMPLE de todos los *.json de un directorio del repo hacia el case.
    - src_dir_rel: ruta relativa al REPO_ROOT (ej: "tools-installer/installed")
    - dst_dir_rel: ruta relativa dentro del case (ej: "metadata/ir/inputs/tools-installer/installed")

    Devuelve lista de ficheros copiados (cada uno con sha256/size si se pudo calcular).
    """
    out = {
        "src_dir_rel": src_dir_rel,
        "src_dir_abs": None,
        "dst_dir_rel": dst_dir_rel,
        "dst_dir_abs": None,
        "status": "missing_dir",
        "reason": None,
        "files": [],
    }

    try:
        src_dir_abs = os.path.join(repo_root, src_dir_rel)
        out["src_dir_abs"] = src_dir_abs

        if not os.path.isdir(src_dir_abs):
            out["reason"] = "not_found_or_not_dir"
            return out

        dst_dir_abs = os.path.join(case_dir, dst_dir_rel)
        out["dst_dir_abs"] = dst_dir_abs
        os.makedirs(dst_dir_abs, exist_ok=True)

        for fn in sorted(os.listdir(src_dir_abs)):
            if not fn.lower().endswith(".json"):
                continue

            src_rel = os.path.join(src_dir_rel, fn)
            dst_rel = os.path.join(dst_dir_rel, fn)

            out["files"].append(_copy_json_file_to_case(case_dir, repo_root, src_rel, dst_rel))

        out["status"] = "ok"
        return out

    except Exception as e:
        out["status"] = "error"
        out["reason"] = str(e)
        return out


def _save_ir_snapshot_to_case(case_dir: str, run_id: str = "R1") -> dict:
    """
    IR snapshot PRESERVADO (copia simple, pero REGISTRADO como evidencia):

    Copia al CASE:
      - scenario/scenario_file.json  -> metadata/ir/inputs/scenario/scenario_file.json
      - tools-installer/installed/*.json -> metadata/ir/inputs/tools-installer/installed/*.json
      - tools-installer-tmp/*.json -> metadata/ir/inputs/tools-installer-tmp/*.json

    Escribe:
      - metadata/ir/ir_snapshot.json (resumen de copia)

    Además, al finalizar:
      - registra TODOS los ficheros copiados + el snapshot en manifest (type="ir_input" / "ir_snapshot")
      - añade evento en metadata/pipeline_events.jsonl (ir_inputs_preserved)
      - añade entrada en chain_of_custody.log (ir_inputs_preserved) y actualiza digest

    Nota: esto debe ejecutarse al crear el caso (idealmente justo después de ensure_case_layout y antes
    de adquisiciones reactivas), porque fija inputs de la ejecución en el CASE.
    """
    if not _is_safe_case_dir(case_dir):
        return {}

    ensure_case_layout(case_dir)

    run_id = (run_id or "R1").strip() or "R1"

    snapshot_rel = os.path.join("metadata", "ir", "ir_snapshot.json")
    snapshot_abs = os.path.join(case_dir, snapshot_rel)
    os.makedirs(os.path.dirname(snapshot_abs), exist_ok=True)

    results = {
        "schema": "nics_ir_snapshot_v1",
        "generated_at_utc": _utc_now_iso(),
        "run_id": run_id,
        "copied": {
            "scenario_file": None,
            "tools_installed_dir": None,
            "tools_tmp_dir": None,
        },
    }

    # 1) scenario/scenario_file.json
    results["copied"]["scenario_file"] = _copy_json_file_to_case(
        case_dir=case_dir,
        repo_root=REPO_ROOT,
        src_rel=os.path.join("scenario", "scenario_file.json"),
        dst_rel=os.path.join("metadata", "ir", "inputs", "scenario", "scenario_file.json"),
    )

    # 2) tools-installer/installed/*.json
    results["copied"]["tools_installed_dir"] = _copy_json_dir_to_case(
        case_dir=case_dir,
        repo_root=REPO_ROOT,
        src_dir_rel=os.path.join("tools-installer", "installed"),
        dst_dir_rel=os.path.join("metadata", "ir", "inputs", "tools-installer", "installed"),
    )

    # 3) tools-installer-tmp/*.json
    results["copied"]["tools_tmp_dir"] = _copy_json_dir_to_case(
        case_dir=case_dir,
        repo_root=REPO_ROOT,
        src_dir_rel="tools-installer-tmp",
        dst_dir_rel=os.path.join("metadata", "ir", "inputs", "tools-installer-tmp"),
    )

    # 4) Escribe snapshot JSON (derivado) y calcula hash/size
    try:
        _atomic_write_json(snapshot_abs, results)
    except Exception:
        return {}

    snapshot_sha = None
    snapshot_size = None
    try:
        snapshot_sha = _sha256_file(snapshot_abs)
        snapshot_size = os.path.getsize(snapshot_abs)
    except Exception:
        snapshot_sha = None
        snapshot_size = None

    # Helpers locales para registrar sin romper ejecución si algo falla
    def _register_artifact(rel_path: str, a_type: str, sha256: str = None, size: int = None) -> None:
        try:
            _add_artifact_fast(case_dir, rel_path, a_type, sha256=sha256, size=size)
        except Exception:
            pass

    def _iter_copied_files() -> list:
        """
        Devuelve lista de dicts: [{"rel": ..., "sha256": ..., "size": ..., "status": ...}, ...]
        Solo incluye ficheros que efectivamente quedaron copiados.
        """
        out = []

        def add_from_entry(entry: dict):
            if not isinstance(entry, dict):
                return
            if entry.get("status") != "copied":
                return
            rel = entry.get("dst_rel")
            if not rel:
                return
            out.append({
                "rel": rel,
                "sha256": entry.get("sha256"),
                "size": entry.get("size"),
            })

        add_from_entry(results.get("copied", {}).get("scenario_file"))

        inst = results.get("copied", {}).get("tools_installed_dir", {})
        for e in (inst.get("files") or []):
            add_from_entry(e)

        tmp = results.get("copied", {}).get("tools_tmp_dir", {})
        for e in (tmp.get("files") or []):
            add_from_entry(e)

        return out

    copied_files = _iter_copied_files()

    # 5) Registrar en manifest: inputs copiados + snapshot
    #    Tipos: ir_input para inputs; ir_snapshot para el resumen.
    for f in copied_files:
        _register_artifact(f["rel"], "ir_input", sha256=f.get("sha256"), size=f.get("size"))
    _register_artifact(snapshot_rel, "ir_snapshot", sha256=snapshot_sha, size=snapshot_size)

    # 6) Pipeline event: un evento agregador con recuentos y hashes relevantes
    try:
        _append_case_event(
            case_dir,
            "ir_inputs_preserved",
            run_id=run_id,
            meta={
                "snapshot_rel": snapshot_rel,
                "snapshot_sha256": snapshot_sha,
                "snapshot_size": snapshot_size,
                "copied_count": len(copied_files),
                "copied": copied_files,
            },
        )
    except Exception:
        pass

    # 7) Chain of custody + digest: una entrada agregadora (sin spamear una por fichero)
    try:
        _append_custody_entry(
            case_dir,
            "ir_inputs_preserved",
            "forensics_api",
            run_id=run_id,
            artifact_rel=snapshot_rel,
            details={
                "snapshot_sha256": snapshot_sha,
                "snapshot_size": snapshot_size,
                "copied_count": len(copied_files),
                "copied": copied_files,
            },
        )
        _register_custody_artifact(case_dir)
        _write_case_digest(case_dir, run_id=run_id)
    except Exception:
        pass

    return {
        "rel": snapshot_rel,
        "sha256": snapshot_sha,
        "size": snapshot_size,
        "copied": results["copied"],
        "copied_files_count": len(copied_files),
    }


#--------------------------------------------------------IR end------------------

#--------------------------------------------------------FSR------------------


def _save_fsr_eval_to_case(case_dir: str, run_id: str = "R1") -> dict:
    """
    Guarda la evaluación FSR dentro del CASE en:
      metadata/fsr/fsr_eval_<run_id>.json

    Además:
      - registra el fichero en manifest (fsr_eval)
      - añade evento en pipeline_events.jsonl (fsr_eval_written)
      - añade entrada en chain_of_custody.log y actualiza digest
    """
    if not _is_safe_case_dir(case_dir):
        return {}

    ensure_case_layout(case_dir)

    run_id = (run_id or "R1").strip() or "R1"

    # Lee lo que ya existe en el caso (no toca JSON originales)
    ir_snapshot_abs = os.path.join(case_dir, "metadata", "ir", "ir_snapshot.json")
    pipeline_abs = os.path.join(case_dir, "metadata", "pipeline_events.jsonl")
    manifest_abs = os.path.join(case_dir, "manifest.json")

    def _safe_read_json(abs_path: str):
        try:
            if not abs_path or not os.path.isfile(abs_path):
                return None
            with open(abs_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _read_jsonl(abs_path: str):
        out = []
        try:
            if not abs_path or not os.path.isfile(abs_path):
                return out
            with open(abs_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = (line or "").strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except Exception:
                        continue
        except Exception:
            return out
        return out

    snap = _safe_read_json(ir_snapshot_abs) or {}
    pipe = _read_jsonl(pipeline_abs)
    mani = _safe_read_json(manifest_abs) or {}

    artifacts = mani.get("artifacts", []) or []
    artifact_types = sorted({a.get("type") for a in artifacts if a.get("type")})

    checks = []

    def ok(name: str, passed: bool, details: dict = None):
        checks.append({"check": name, "passed": bool(passed), "details": details or {}})

    # Inputs copiados en IR (mínimo)
    scenario_in_case = os.path.join(case_dir, "metadata", "ir", "inputs", "scenario", "scenario_file.json")
    ok(
        "FSR-IT-1 scenario_file_in_case",
        os.path.isfile(scenario_in_case),
        {"path": "metadata/ir/inputs/scenario/scenario_file.json"}
    )

    installed_dir = os.path.join(case_dir, "metadata", "ir", "inputs", "tools-installer", "installed")
    tmp_dir = os.path.join(case_dir, "metadata", "ir", "inputs", "tools-installer-tmp")

    installed_json_count = len([x for x in os.listdir(installed_dir) if x.lower().endswith(".json")]) if os.path.isdir(installed_dir) else 0
    tmp_json_count = len([x for x in os.listdir(tmp_dir) if x.lower().endswith(".json")]) if os.path.isdir(tmp_dir) else 0

    ok(
        "FSR-IT-2 tools_installed_json_present",
        installed_json_count > 0,
        {"dir": "metadata/ir/inputs/tools-installer/installed", "count": installed_json_count}
    )
    ok(
        "FSR-IT-3 tools_tmp_json_present",
        tmp_json_count > 0,
        {"dir": "metadata/ir/inputs/tools-installer-tmp", "count": tmp_json_count}
    )

    # Pipeline mínimo
    alert_events = [e for e in pipe if e.get("event") == "alert" and (e.get("run_id") or "R1") == run_id]
    ok(
        "FSR-PIPE-1 alert_event_present",
        len(alert_events) > 0,
        {"run_id": run_id, "count": len(alert_events)}
    )

    def has_event(name: str):
        return any((e.get("event") == name and (e.get("run_id") or "R1") == run_id) for e in pipe)

    def paired(start_evt: str, ok_evt: str, fail_evt: str):
        if not has_event(start_evt):
            return True
        return has_event(ok_evt) or has_event(fail_evt)

    ok("FSR-PIPE-2 disk_start_has_outcome", paired("disk_start", "disk_preserved", "disk_failed"))
    ok("FSR-PIPE-3 memory_start_has_outcome", paired("memory_start", "memory_preserved", "memory_failed"))

    # Outputs mínimos
    ok("FSR-OUT-0 manifest_present", os.path.isfile(manifest_abs))
    ok("FSR-OUT-1 artifact_types_nonempty", len(artifact_types) > 0, {"types": artifact_types})

    passed = all(c["passed"] for c in checks)

    res = {
        "schema": "nics_fsr_eval_v1",
        "generated_at_utc": _utc_now_iso(),
        "run_id": run_id,
        "case_dir": case_dir,
        "passed": passed,
        "checks": checks,
        "summary": {
            "artifact_types": artifact_types,
            "pipeline_events": len(pipe),
            "manifest_artifacts": len(artifacts),
        }
    }

    out_rel = os.path.join("metadata", "fsr", f"fsr_eval_{run_id}.json")
    out_abs = os.path.join(case_dir, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)

    # 1) Escribe el JSON
    _atomic_write_json(out_abs, res)

    # 2) Calcula hash + size
    try:
        sha = _sha256_file(out_abs)
        size = os.path.getsize(out_abs)
    except Exception:
        sha = None
        size = None

    # 3) Registra en manifest
    try:
        _add_artifact_fast(case_dir, out_rel, "fsr_eval", sha256=sha, size=size)
    except Exception:
        pass

    # 4) Registra evento en pipeline
    try:
        _append_case_event(
            case_dir,
            "fsr_eval_written",
            run_id=run_id,
            meta={"rel": out_rel, "sha256": sha, "size": size, "passed": passed}
        )
    except Exception:
        pass

    # 5) Registra custody + digest
    try:
        _append_custody_entry(
            case_dir,
            "fsr_eval_written",
            "forensics_api",
            run_id=run_id,
            artifact_rel=out_rel,
            details={"sha256": sha, "size": size, "passed": passed}
        )
        _register_custody_artifact(case_dir)
        _write_case_digest(case_dir, run_id=run_id)
    except Exception:
        pass

    return {"rel": out_rel, "passed": passed, "sha256": sha, "size": size}


#--------------------------------------------------------FSR end------------------





def _add_artifact(case_dir: str, rel_path: str, a_type: str):
    abs_path = os.path.join(case_dir, rel_path)
    if not os.path.exists(abs_path):
        return

    manifest = _read_manifest(case_dir)
    artifacts = manifest.setdefault("artifacts", [])

    try:
        sha = _sha256_file(abs_path)
        size = os.path.getsize(abs_path)
    except Exception:
        sha = None
        size = None

    artifacts.append({
        "type": a_type,
        "rel_path": rel_path,
        "sha256": sha,
        "size": size,
        "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    })
    _write_manifest(case_dir, manifest)

@forensics_bp.route("/api/forensics/case/create", methods=["POST"])
def api_forensics_case_create():
    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    case_dir = os.path.join(EVIDENCE_ROOT, f"CASE-{ts}")
    os.makedirs(case_dir, exist_ok=True)
    logger.info(f"[CASE_CREATE] REPO_ROOT={REPO_ROOT}")
    logger.info(f"[CASE_CREATE] EVIDENCE_ROOT={EVIDENCE_ROOT}")
    logger.info(f"[CASE_CREATE] case_dir={case_dir}")
    logger.info(f"[CASE_CREATE] ACTIVE_CASE_PTR={os.path.join(EVIDENCE_ROOT, '_active_case.txt')}")

    # Subdirs estándar
    for d in ["metadata", "network", "disk", "memory", "industrial", "analysis", "derived"]:
        os.makedirs(os.path.join(case_dir, d), exist_ok=True)

    ensure_case_layout(case_dir)

    set_active_case_dir(case_dir)
    logger.info("[CASE_CREATE] active case pointer written")

    # custody file + register in manifest
    _ensure_custody_file(case_dir)

    # manifest
    manifest = {
        "case_dir": case_dir,
        "created_at": _utc_now_iso(),
        "artifacts": []
    }
    _write_manifest(case_dir, manifest)

    _append_custody_entry(case_dir, "case_created", "forensics_api", run_id="R1", details={"case_dir": case_dir})

    _register_custody_artifact(case_dir)
    _export_time_sync(case_dir, run_id="R1")
    _write_case_digest(case_dir, run_id="R1")

    # NUEVO: snapshot IR de escenarios y tools, fail safe
    _save_ir_snapshot_to_case(case_dir, run_id="R1")
    _save_fsr_eval_to_case(case_dir, run_id="R1")
    # events file (vacío)
    evp = _events_path(case_dir)
    if not os.path.exists(evp):
        Path(evp).touch()

    return jsonify({"case_dir": case_dir}), 200



@forensics_bp.route("/api/forensics/case/manifest", methods=["GET"])
def api_forensics_case_manifest():
    case_dir = request.args.get("case_dir", "")
    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400

    ensure_case_layout(case_dir)

    try:
        return jsonify(_read_manifest(case_dir)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@forensics_bp.route("/api/forensics/case/download", methods=["GET"])
def api_forensics_case_download():
    case_dir = request.args.get("case_dir", "")
    rel = request.args.get("rel", "")

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not rel or ".." in rel or rel.startswith("/") or rel.startswith("\\"):
        return jsonify({"error": "rel inválido"}), 400
    
    ensure_case_layout(case_dir)

    abs_path = os.path.join(case_dir, rel)
    if not os.path.exists(abs_path):
        return jsonify({"error": "Archivo no existe"}), 404

    directory = os.path.dirname(abs_path)
    filename = os.path.basename(abs_path)
    return send_from_directory(directory, filename, as_attachment=True)

def _run_script(script_path: str, args: list, cwd: str = None, timeout: int = 60 * 60, *, stdin_devnull: bool = False, env: dict | None = None):
    if not os.path.exists(script_path):
        return (1, "", f"Script no encontrado: {script_path}")

    try:
        os.chmod(script_path, 0o755)
    except Exception:
        pass

    proc = subprocess.run(
        ["bash", script_path] + args,
        cwd=cwd or REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL if stdin_devnull else None,
        env=env,
    )
    return (proc.returncode, proc.stdout, proc.stderr)


def _sudo_nopasswd_for_disk_helper(script_path: str) -> tuple[bool, str]:
    try:
        probe = subprocess.run(
            ["sudo", "-n", "-l"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=10,
        )
    except Exception:
        return False, ""

    output = f"{probe.stdout}\n{probe.stderr}".strip()
    helper_markers = [
        script_path,
        f"/bin/bash {script_path}",
        f"bash {script_path}",
    ]
    allowed = False
    for line in output.splitlines():
        upper = line.upper()
        if "NOPASSWD" not in upper:
            continue
        if any(marker in line for marker in helper_markers):
            allowed = True
            break
    return allowed, output


def disk_acquisition_preflight(container_name: str = "nova_libvirt", *, require_stable_noninteractive: bool = False) -> dict:
    blockers: list[str] = []
    warnings: list[str] = []
    privilege_mode = "root" if os.geteuid() == 0 else "user"
    script_path = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_disk_kolla_libvirt.sh")
    docker_path = shutil.which("docker")
    qemu_img_path = shutil.which("qemu-img")

    sudo_noninteractive_ok = privilege_mode == "root"
    sudo_nopasswd_granted = privilege_mode == "root"
    sudo_list_output = ""
    helper_sudo_probe_ok = privilege_mode == "root"

    if not os.path.isfile(script_path):
        blockers.append("disk_acquisition_script_missing")
    if not docker_path:
        blockers.append("docker_not_available")
    if not qemu_img_path:
        blockers.append("qemu_img_not_available")

    if privilege_mode != "root":
        # Probe order: try the script-specific NOPASSWD rule FIRST because a
        # dedicated Cmnd_Alias rule (e.g. /etc/sudoers.d/nicscyberlab-acquire-disk)
        # only covers that exact command -- "sudo -n true" will keep failing even
        # when the real acquisition command works without a password.  Only fall
        # back to the generic "sudo -n true" check if the script probe itself fails.
        try:
            helper_probe = subprocess.run(
                ["sudo", "-n", "/bin/bash", script_path, "__nics_probe__"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=10,
            )
            combined = f"{helper_probe.stdout}\n{helper_probe.stderr}".lower()
            script_nopasswd_ok = (
                helper_probe.returncode in {0, 1}
                and "password is required" not in combined
                and "a password is required" not in combined
                and "not allowed" not in combined
                and "sorry" not in combined
            )
        except Exception:
            script_nopasswd_ok = False

        if script_nopasswd_ok:
            # Dedicated NOPASSWD rule for the acquisition script is in place.
            sudo_noninteractive_ok = True
            sudo_nopasswd_granted = True
            helper_sudo_probe_ok = True
        else:
            # No dedicated rule -- fall back to checking a generic cached credential.
            try:
                probe = subprocess.run(
                    ["sudo", "-n", "true"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    stdin=subprocess.DEVNULL,
                    timeout=10,
                )
                sudo_noninteractive_ok = probe.returncode == 0
            except Exception:
                sudo_noninteractive_ok = False

            if sudo_noninteractive_ok:
                sudo_nopasswd_granted, sudo_list_output = _sudo_nopasswd_for_disk_helper(script_path)

        if not sudo_noninteractive_ok:
            blockers.append("sudo_noninteractive_unavailable")
        elif require_stable_noninteractive and not sudo_nopasswd_granted:
            blockers.append("sudo_nopasswd_not_granted_for_disk_helper")
            warnings.append(
                "Current sudo access may depend on a temporary cached credential or an unrelated NOPASSWD rule. "
                "That is not stable enough for multi-repetition Level B batches because nested analysis can outlive the sudo timestamp. "
                "The disk acquisition helper itself needs a dedicated NOPASSWD rule."
            )

    docker_access_ok = False
    should_probe_docker = bool(docker_path) and (privilege_mode == "root" or (sudo_noninteractive_ok and not require_stable_noninteractive))
    if should_probe_docker:
        docker_cmd = ["docker", "ps"] if privilege_mode == "root" else ["sudo", "-n", "docker", "ps"]
        try:
            probe = subprocess.run(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            docker_access_ok = probe.returncode == 0
            if not docker_access_ok:
                blockers.append("docker_access_unavailable")
        except Exception:
            blockers.append("docker_access_unavailable")
    elif docker_path and require_stable_noninteractive and sudo_nopasswd_granted:
        docker_access_ok = True
    elif docker_path and privilege_mode != "root" and not sudo_noninteractive_ok:
        warnings.append(
            "Docker access was not probed because stable non-interactive sudo/root privileges are not currently available."
        )

    return {
        "ok": not blockers,
        "blockers": blockers,
        "warnings": warnings,
        "privilege_mode": privilege_mode,
        "sudo_noninteractive_ok": sudo_noninteractive_ok,
        "sudo_nopasswd_granted": sudo_nopasswd_granted,
        "docker_available": bool(docker_path),
        "docker_access_ok": docker_access_ok,
        "qemu_img_available": bool(qemu_img_path),
        "script_path": script_path,
        "container_name": container_name,
        "sudo_list_excerpt": sudo_list_output[:1000] if sudo_list_output else "",
        "helper_sudo_probe_ok": helper_sudo_probe_ok,
    }


#---------------------------------------------------------------------- FSR ejecutador -------------------

def _read_jsonl_events(case_dir: str) -> list:
    ep = _events_path(case_dir)
    out = []
    try:
        if not os.path.isfile(ep):
            return out
        with open(ep, "r", encoding="utf-8") as f:
            for line in f:
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return out
    return out


def _acquisition_complete_for_run(case_dir: str, run_id: str) -> bool:
    """
    Devuelve True solo si NO hay fases *_start sin su outcome.
    Mapea starts a outcomes típicos, y si aparece un start, exige preserved o failed.
    """
    run_id = (run_id or "R1").strip() or "R1"
    events = [e for e in _read_jsonl_events(case_dir) if (e.get("run_id") or "R1") == run_id]

    # Si no hay eventos, no hay nada que evaluar
    if not events:
        return False

    starts = {
        "disk_start": ("disk_preserved", "disk_failed"),
        "memory_start": ("memory_preserved", "memory_failed"),
        "pcap_start": ("pcap_preserved", "pcap_failed"),
        "industrial_start": ("industrial_preserved", "industrial_failed"),
    }

    present = {e.get("event") for e in events if e.get("event")}

    any_start = any(s in present for s in starts.keys())
    if not any_start:
        # Si tu pipeline no usa *_start, evita disparar en vacío
        return False

    for s, outs in starts.items():
        if s in present:
            ok_evt, fail_evt = outs
            if (ok_evt not in present) and (fail_evt not in present):
                return False

    return True


def _launch_ieee_eval_tables_async(case_dir: str, run_id: str = "R1") -> dict:
    """
    Lanza make_ieee_eval_tables.py cuando la adquisición del run está completa.
    Es idempotente por run: usa un marker .done para no duplicar.
    Guarda logs dentro del CASE y lo registra como derived.
    """
    if not _is_safe_case_dir(case_dir):
        return {"started": False, "reason": "unsafe_case_dir"}

    ensure_case_layout(case_dir)

    run_id = (run_id or "R1").strip() or "R1"

    if not _acquisition_complete_for_run(case_dir, run_id):
        return {"started": False, "reason": "acquisition_not_complete"}

    marker_rel = os.path.join("metadata", "fsr", f"ieee_eval_tables_{run_id}.done")
    marker_abs = os.path.join(case_dir, marker_rel)

    # Ya ejecutado
    if os.path.exists(marker_abs):
        return {"started": False, "reason": "already_done", "marker": marker_rel}

    script_path = os.path.join(FORENSICS_SCRIPTS_DIR, "make_ieee_eval_tables.py")
    if not os.path.isfile(script_path):
        return {"started": False, "reason": "script_not_found", "script": script_path}

    log_rel = os.path.join("analysis", "ieee_eval_tables", run_id, "make_ieee_eval_tables.log")
    log_abs = os.path.join(case_dir, log_rel)
    os.makedirs(os.path.dirname(log_abs), exist_ok=True)

    evidence_root = EVIDENCE_ROOT

    args = [
        "python3", script_path,
        "--evidence-root", evidence_root,
        "--limit", "1",
        "--run-id", run_id,
        "--write-case-fsr",
        "--write-case-analysis-copy",
        "--register-written-artifacts",
    ]

    def worker():
        started_ok = False
        try:
            _append_case_event(case_dir, "ieee_eval_tables_start", run_id=run_id, meta={
                "script": script_path,
                "args": args,
                "evidence_root": evidence_root,
            })
        except Exception:
            pass

        try:
            _append_custody_entry(case_dir, "ieee_eval_tables_start", "forensics_api", run_id=run_id, details={
                "script": script_path,
                "evidence_root": evidence_root,
            })
            _register_custody_artifact(case_dir)
            _write_case_digest(case_dir, run_id=run_id)
        except Exception:
            pass

        t0 = time.time()
        rc = 1
        out = ""
        err = ""

        try:
            proc = subprocess.run(
                args,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60 * 60,
            )
            rc = proc.returncode
            out = proc.stdout or ""
            err = proc.stderr or ""
        except Exception as e:
            rc = 1
            out = ""
            err = f"exception: {e}"

        elapsed = round(time.time() - t0, 3)

        try:
            with open(log_abs, "w", encoding="utf-8") as f:
                f.write(f"[CMD] {' '.join(args)}\n")
                f.write(f"[RC] {rc}\n")
                f.write(f"[ELAPSED_S] {elapsed}\n\n")
                f.write("[STDOUT]\n")
                f.write(out)
                f.write("\n\n[STDERR]\n")
                f.write(err)
        except Exception:
            pass

        # Marca done solo si rc==0
        if rc == 0:
            try:
                Path(marker_abs).touch()
                started_ok = True
            except Exception:
                started_ok = False

        # Registra log como derived
        try:
            register_derived(
                case_dir=case_dir,
                rel_path=log_rel,
                derived_type="ieee_eval_tables_log",
                run_id=run_id,
                extra_meta={"rc": rc, "elapsed_s": elapsed, "done_marker": marker_rel if rc == 0 else None},
                compute_sha=False,
            )
        except Exception:
            pass

        # Eventos + custody
        try:
            _append_case_event(case_dir, "ieee_eval_tables_done" if rc == 0 else "ieee_eval_tables_failed", run_id=run_id, meta={
                "rc": rc,
                "elapsed_s": elapsed,
                "log_rel": log_rel,
                "marker_rel": marker_rel if rc == 0 else None,
            })
        except Exception:
            pass

        try:
            _append_custody_entry(
                case_dir,
                "ieee_eval_tables_done" if rc == 0 else "ieee_eval_tables_failed",
                "forensics_api",
                run_id=run_id,
                artifact_rel=log_rel,
                outcome="ok" if rc == 0 else "error",
                details={"rc": rc, "elapsed_s": elapsed, "marker_rel": marker_rel if rc == 0 else None},
            )
            _register_custody_artifact(case_dir)
            _write_case_digest(case_dir, run_id=run_id)
        except Exception:
            pass

        # Opcional: refrescar FSR eval tras escribir outputs
        if started_ok:
            try:
                _save_fsr_eval_to_case(case_dir, run_id=run_id)
            except Exception:
                pass

    th = threading.Thread(target=worker, daemon=True)
    th.start()

    return {"started": True, "run_id": run_id, "log_rel": log_rel}


#---------------------------------------------------------------------- FSR ejecutador -------------------





def acquire_disk(case_dir: str, vm_id: str, container_name: str = "nova_libvirt", *, run_id: str = "R1", alert_ts_utc: str = "", noninteractive: bool = False) -> dict:
    """
    Pure (Flask-free) disk acquisition, callable from background orchestrators
    (e.g. the Level B real-execution job) as well as from the HTTP route below.
    Returns the same fields the route returns as JSON, plus "ok": bool.
    """
    if not _is_safe_case_dir(case_dir):
        return {"ok": False, "result": "error", "error": "case_dir inválido"}
    if not vm_id:
        return {"ok": False, "result": "error", "error": "vm_id requerido"}

    run_id = (run_id or "R1").strip() or "R1"
    _get_or_set_alert_ts(case_dir, run_id=run_id, provided_alert_ts_utc=(alert_ts_utc or "").strip())

    _append_custody_entry(
        case_dir,
        "acquire_start",
        "forensics_api",
        run_id=run_id,
        details={"kind": "disk", "vm_id": vm_id}
    )
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_disk_kolla_libvirt.sh")
    preflight = disk_acquisition_preflight(container_name, require_stable_noninteractive=bool(noninteractive))
    if not preflight.get("ok"):
        error_message = (
            "Disk acquisition prerequisites are not satisfied: "
            + ", ".join(str(item) for item in preflight.get("blockers") or [] if item)
        )
        _append_case_event(case_dir, "disk_failed", run_id=run_id, meta={"vm_id": vm_id, "container": container_name, "preflight": preflight, "reason": error_message})
        _append_custody_entry(
            case_dir,
            "acquire_failed",
            "forensics_api",
            run_id=run_id,
            outcome="error",
            details={"kind": "disk", "vm_id": vm_id, "preflight": preflight, "reason": error_message}
        )
        _register_custody_artifact(case_dir)
        _write_case_digest(case_dir, run_id=run_id)
        return {"ok": False, "result": "error", "error": error_message, "preflight": preflight}

    _append_case_event(case_dir, "disk_start", run_id=run_id, meta={"vm_id": vm_id, "container": container_name})

    t0 = time.time()
    env = os.environ.copy()
    if noninteractive:
        env["NICS_DFIR_SUDO_NONINTERACTIVE"] = "1"
    try:
        rc, out, err = _run_script(
            script,
            [case_dir, vm_id, container_name],
            cwd=REPO_ROOT,
            timeout=60 * 60,
            stdin_devnull=bool(noninteractive),
            env=env,
        )
    except OSError as exc:
        if getattr(exc, "errno", None) == 28:
            no_space_message = (
                "Disk acquisition failed because the evidence filesystem ran out of space during transient disk conversion. "
                "The helper may need temporary space for overlay qcow2 + backing raw + final raw at the same time."
            )
            _append_case_event(
                case_dir,
                "disk_failed",
                run_id=run_id,
                meta={"vm_id": vm_id, "container": container_name, "reason": no_space_message, "errno": 28},
            )
            _append_custody_entry(
                case_dir,
                "acquire_failed",
                "forensics_api",
                run_id=run_id,
                outcome="error",
                details={"kind": "disk", "vm_id": vm_id, "errno": 28, "reason": no_space_message},
            )
            _register_custody_artifact(case_dir)
            _write_case_digest(case_dir, run_id=run_id)
            return {
                "ok": False,
                "result": "error",
                "exit_code": 28,
                "error": "insufficient_storage_during_disk_acquisition",
                "msg": no_space_message,
                "errno": 28,
                "stdout": "",
                "stderr": str(exc),
                "preflight": preflight,
                "disk_raw": None,
                "sha256": None,
            }
        raise
    t1 = time.time()

    disk_rel = None
    disk_size = None
    sha_value = None

    if rc == 0:
        disk_rel, disk_size, sha_value = _register_disk_from_metadata(case_dir, vm_id)

    _append_case_event(
        case_dir,
        "disk_preserved" if (rc == 0 and disk_rel) else "disk_failed",
        run_id=run_id,
        meta={
            "vm_id": vm_id,
            "rel": disk_rel,
            "size": disk_size,
            "sha256": sha_value,
            "exit_code": rc,
            "elapsed_s": round(t1 - t0, 3),
        }
    )

    if disk_rel:
        _append_custody_entry(
            case_dir,
            "acquire_preserved",
            "forensics_api",
            run_id=run_id,
            artifact_rel=disk_rel,
            outcome="ok" if rc == 0 else "error",
            details={"kind": "disk", "vm_id": vm_id, "sha256": sha_value, "size": disk_size}
        )
    else:
        _append_custody_entry(
            case_dir,
            "acquire_failed",
            "forensics_api",
            run_id=run_id,
            outcome="error",
            details={"kind": "disk", "vm_id": vm_id, "exit_code": rc}
        )

    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    error_message = None
    combined_output = f"{out}\n{err}".lower()
    if rc != 0:
        if "no space left on device" in combined_output or "insufficient free space for transient disk conversion" in combined_output:
            error_message = "insufficient_storage_during_disk_acquisition"
        else:
            error_message = f"disk_acquisition_failed_exit_{rc}"

    return {
        "ok": rc == 0,
        "result": "ok" if rc == 0 else "error",
        "exit_code": rc,
        "error": error_message,
        "stdout": out,
        "stderr": err,
        "preflight": preflight,
        "disk_raw": disk_rel,
        "sha256": sha_value,
    }


@forensics_bp.route("/api/forensics/acquire/disk_kolla", methods=["POST"])
def api_forensics_acquire_disk():
    data = request.get_json(force=True, silent=True) or {}
    case_dir = data.get("case_dir")
    vm_id = data.get("vm_id")
    container_name = data.get("container_name", "nova_libvirt")
    run_id = (data.get("run_id") or "R1").strip()
    alert_ts_utc = (data.get("alert_ts_utc") or "").strip()
    noninteractive = bool(data.get("noninteractive"))

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id:
        return jsonify({"error": "vm_id requerido"}), 400

    out = acquire_disk(case_dir, vm_id, container_name, run_id=run_id, alert_ts_utc=alert_ts_utc, noninteractive=noninteractive)
    status = 200 if out.get("ok") else (507 if out.get("error") == "insufficient_storage_during_disk_acquisition" or out.get("exit_code") == 28 else 500)
    return jsonify({k: v for k, v in out.items() if k != "ok"}), status











@forensics_bp.route("/api/forensics/acquire/disk_kolla/stream", methods=["GET"])
def api_forensics_acquire_disk_stream():
    case_dir = request.args.get("case_dir", "")
    vm_id = request.args.get("vm_id", "")
    container_name = request.args.get("container_name", "nova_libvirt")
    run_id = (request.args.get("run_id") or "R1").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id:
        return jsonify({"error": "vm_id requerido"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_disk_kolla_libvirt.sh")
    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404

    def generate():
        start_ts = time.time()
        script_name = os.path.basename(script)

        _append_case_event(case_dir, "disk_start", run_id=run_id, meta={"vm_id": vm_id, "container": container_name})

        yield f"data: [START] {script_name} {case_dir} {vm_id} {container_name}\n\n"

        p = subprocess.Popen(
            ["bash", script, case_dir, vm_id, container_name],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        last_line = ""
        for line in p.stdout:
            line = (line or "").rstrip("\n")
            if line.strip():
                last_line = line.strip()
            yield f"data: {line}\n\n"

        p.wait()
        rc = p.returncode if p.returncode is not None else 1

        disk_rel = None
        disk_size = None
        sha_value = None

        if rc == 0:
            disk_rel, disk_size, sha_value = _register_disk_from_metadata(case_dir, vm_id)

        _append_case_event(
            case_dir,
            "disk_preserved" if (rc == 0 and disk_rel) else "disk_failed",
            run_id=run_id,
            meta={
                "vm_id": vm_id,
                "rel": disk_rel,
                "size": disk_size,
                "sha256": sha_value,
                "exit_code": rc,
                "elapsed_s": round(time.time() - start_ts, 3),
            }
        )

        payload = {
            "result": "ok" if rc == 0 else "error",
            "exit_code": rc,
            "last": last_line,
            "disk_raw": disk_rel,
            "sha256": sha_value,
            "script": script_name
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(generate(), mimetype="text/event-stream")



@forensics_bp.route("/api/forensics/analyze/memory_vol3", methods=["POST"])
def api_forensics_analyze_memory():
    data = request.get_json(force=True, silent=True) or {}

    if data.get("memory_artifact_id") or data.get("auto_generate_symbols") is not None or not data.get("symbols_dir"):
        case_id = _case_id_from_client_payload(data)
        if not case_id:
            return jsonify({"error": "case_id requerido"}), 400
        memory_artifact_id = (data.get("memory_artifact_id") or os.path.basename((data.get("dump_file") or "").strip() or "")).strip() or None
        auto_generate_symbols = bool(data.get("auto_generate_symbols"))
        overwrite_symbols = bool(data.get("overwrite_symbols"))
        try:
            job = start_memory_analysis_job(
                case_id=case_id,
                memory_artifact_id=memory_artifact_id,
                auto_generate_symbols=auto_generate_symbols,
                overwrite_symbols=overwrite_symbols,
            )
        except FileNotFoundError as exc:
            return jsonify({"error": str(exc)}), 404
        except Exception as exc:
            logger.error("Error starting dynamic memory analysis job: %s", exc, exc_info=True)
            return jsonify({"error": str(exc)}), 500
        return jsonify(job), 202

    case_dir = data.get("case_dir")
    vm_id = data.get("vm_id")
    dump_file = data.get("dump_file") or data.get("dump")  # rel o abs
    symbols_dir = data.get("symbols_dir")
    vol_cmd = data.get("vol_cmd", "vol")

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not dump_file or not symbols_dir:
        return jsonify({"error": "vm_id, dump_file, symbols_dir requeridos"}), 400

    # Resolver dump_file: si es relativo, lo hacemos relativo al case_dir
    dump_path = dump_file
    if not os.path.isabs(dump_path):
        dump_path = os.path.join(case_dir, dump_file)

    if not os.path.exists(dump_path):
        return jsonify({"error": f"Dump no existe: {dump_file}"}), 404

    # Script
    script = os.path.join(FORENSICS_SCRIPTS_DIR, "analyze_memory_vol3.sh")

    # Args EXACTOS que vas a pasar al .sh
    args = [case_dir, dump_path, symbols_dir, vol_cmd, vm_id]

    # Imprime en consola (logs del backend) antes de ejecutar
    print("[VOL3] analyze_memory_vol3.sh will run with:")
    print(f"[VOL3]   case_dir     = {case_dir}")
    print(f"[VOL3]   dump_file    = {dump_file}")
    print(f"[VOL3]   dump_path    = {dump_path}")
    print(f"[VOL3]   symbols_dir  = {symbols_dir}")
    print(f"[VOL3]   vol_cmd      = {vol_cmd}")
    print(f"[VOL3]   vm_id        = {vm_id}")
    print(f"[VOL3]   args         = {args}")
    print(f"[VOL3]   cwd          = {REPO_ROOT}")
    print(f"[VOL3]   script       = {script}")

    rc, out, err = _run_script(
        script,
        args,
        cwd=REPO_ROOT,
        timeout=60 * 60
    )

    # Convención mínima: analysis/vol3/<vm_id>/
    rel_out = os.path.join("analysis", "vol3", vm_id)
    abs_out = os.path.join(case_dir, rel_out)
    if os.path.isdir(abs_out):
        manifest = _read_manifest(case_dir)
        manifest.setdefault("artifacts", []).append({
            "type": "vol3_output_dir",
            "rel_path": rel_out,
            "sha256": None,
            "size": None,
            "ts": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        })
        _write_manifest(case_dir, manifest)

    return jsonify({
        "result": "ok" if rc == 0 else "error",
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "out_dir": rel_out if os.path.isdir(abs_out) else None,

        # Esto te lo devuelve el endpoint para verificar lo que se pasó al .sh
        "debug": {
            "script": script,
            "cwd": REPO_ROOT,
            "case_dir": case_dir,
            "dump_file": dump_file,
            "dump_path": dump_path,
            "symbols_dir": symbols_dir,
            "vol_cmd": vol_cmd,
            "vm_id": vm_id,
            "args": args,
        }
    }), 200 if rc == 0 else 500


@forensics_bp.route("/api/forensics/case/list", methods=["GET"])
def api_forensics_case_list():
    try:
        cases = []
        if os.path.isdir(EVIDENCE_ROOT):
            for name in os.listdir(EVIDENCE_ROOT):
                if not name.startswith("CASE-"):
                    continue
                case_dir = os.path.join(EVIDENCE_ROOT, name)
                if not os.path.isdir(case_dir):
                    continue

                mp = _manifest_path(case_dir)
                created_at = None
                artifacts_count = 0

                if os.path.exists(mp):
                    try:
                        m = _read_manifest(case_dir)
                        created_at = m.get("created_at")
                        artifacts_count = len(m.get("artifacts", []) or [])
                    except Exception:
                        pass

                cases.append({
                    "name": name,
                    "case_dir": case_dir,
                    "created_at": created_at,
                    "artifacts_count": artifacts_count
                })

        # Orden: más reciente primero (por nombre CASE-YYYYMMDD-HHMMSS)
        cases.sort(key=lambda x: x["name"], reverse=True)

        return jsonify({"cases": cases}), 200
    except Exception as e:
        logger.error(f"Error /api/forensics/case/list: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500


def _case_id_from_client_payload(data: dict | None = None) -> str:
    payload = data or {}
    case_id = (payload.get("case_id") or request.args.get("case_id") or "").strip()
    if case_id:
        return case_id
    case_dir = (payload.get("case_dir") or request.args.get("case_dir") or "").strip()
    if case_dir:
        return os.path.basename(os.path.abspath(case_dir))
    return ""


@forensics_bp.route("/api/forensics/symbols", methods=["GET"])
def api_forensics_symbols_inventory():
    case_id = _case_id_from_client_payload()
    return jsonify(symbols_inventory_payload(case_id=case_id or None)), 200


@forensics_bp.route("/api/forensics/symbols/status", methods=["GET"])
def api_forensics_symbols_status():
    case_id = _case_id_from_client_payload()
    memory_artifact_id = (request.args.get("memory_artifact_id") or "").strip() or None
    if not case_id:
        return jsonify({"error": "case_id requerido"}), 400
    return jsonify(symbols_inventory_payload(case_id=case_id)), 200


@forensics_bp.route("/api/forensics/symbols/generate", methods=["POST"])
def api_forensics_symbols_generate():
    data = request.get_json(force=True, silent=True) or {}
    case_id = _case_id_from_client_payload(data)
    if not case_id:
        return jsonify({"error": "case_id requerido"}), 400
    memory_artifact_id = (data.get("memory_artifact_id") or "").strip() or None
    overwrite = bool(data.get("overwrite"))
    mode = (data.get("mode") or "manual").strip() or "manual"
    try:
        job = start_symbol_generation_job(
            case_id=case_id,
            memory_artifact_id=memory_artifact_id,
            overwrite=overwrite,
            mode=mode,
        )
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        logger.error("Error starting symbol generation job: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500
    return jsonify(job), 202


@forensics_bp.route("/api/forensics/symbols/jobs/<job_id>", methods=["GET"])
def api_forensics_symbols_job(job_id: str):
    job = get_vol3_job(job_id)
    if not job:
        return jsonify({"error": "job_not_found", "job_id": job_id}), 404
    return jsonify(job), 200


@forensics_bp.route("/api/forensics/memory/analyze", methods=["POST"])
def api_forensics_memory_analyze_job():
    data = request.get_json(force=True, silent=True) or {}
    case_id = _case_id_from_client_payload(data)
    if not case_id:
        return jsonify({"error": "case_id requerido"}), 400
    memory_artifact_id = (data.get("memory_artifact_id") or "").strip() or None
    auto_generate_symbols = bool(data.get("auto_generate_symbols"))
    overwrite_symbols = bool(data.get("overwrite_symbols"))
    try:
        job = start_memory_analysis_job(
            case_id=case_id,
            memory_artifact_id=memory_artifact_id,
            auto_generate_symbols=auto_generate_symbols,
            overwrite_symbols=overwrite_symbols,
        )
    except FileNotFoundError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        logger.error("Error starting memory analysis job: %s", exc, exc_info=True)
        return jsonify({"error": str(exc)}), 500
    return jsonify(job), 202


@forensics_bp.route("/api/forensics/memory/analysis/<job_id>", methods=["GET"])
def api_forensics_memory_analysis_job(job_id: str):
    job = get_vol3_job(job_id)
    if not job:
        return jsonify({"error": "job_not_found", "job_id": job_id}), 404
    return jsonify(job), 200




def _run_script_sse(script_path: str, args: list, cwd: str = None, timeout: int = 60 * 60):
    if not os.path.exists(script_path):
        def gen_err():
            yield "data: [ERROR] Script no encontrado: {}\n\n".format(script_path)
            payload = {"result": "error", "exit_code": 127, "last": "", "script": os.path.basename(script_path)}
            yield "event: done\ndata: {}\n\n".format(json.dumps(payload))
        return Response(gen_err(), mimetype="text/event-stream")

    try:
        os.chmod(script_path, 0o755)
    except Exception:
        pass

    def generate():
        start_ts = time.time()
        script_name = os.path.basename(script_path)

        yield f"data: [START] {script_name} {' '.join(args)}\n\n"

        p = subprocess.Popen(
            ["bash", script_path] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        last_line = ""
        timed_out = False

        try:
            for line in p.stdout:
                line = (line or "").rstrip("\n")
                if line.strip():
                    last_line = line.strip()

                yield f"data: {line}\n\n"

                if timeout and (time.time() - start_ts) > timeout:
                    timed_out = True
                    try:
                        p.kill()
                    except Exception:
                        pass
                    yield "data: [ERROR] Timeout alcanzado, proceso abortado\n\n"
                    break
        finally:
            try:
                p.wait(timeout=5)
            except Exception:
                pass

        exit_code = p.returncode if p.returncode is not None else 1
        result = "ok" if (exit_code == 0 and not timed_out) else "error"

        yield f"data: [EXIT] {exit_code}\n\n"
        if last_line:
            yield f"data: [LAST] {last_line}\n\n"

        payload = {
            "result": result,
            "exit_code": exit_code,
            "last": last_line,
            "script": script_name,
        }
        # Evento que el front SÍ puede capturar con addEventListener("done", ...)
        yield "event: done\ndata: {}\n\n".format(json.dumps(payload))

    return Response(generate(), mimetype="text/event-stream")


@forensics_bp.route("/api/forensics/vol3/symbols/generate/stream", methods=["GET"])
def api_vol3_symbols_generate_stream():
    case_dir = request.args.get("case_dir", "")
    vm_id = request.args.get("vm_id", "")
    vm_ip = request.args.get("vm_ip", "")
    ssh_user = (request.args.get("ssh_user", "debian") or "debian").strip()
    ssh_key = (request.args.get("ssh_key", "") or "").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not vm_ip:
        return jsonify({"error": "vm_id y vm_ip requeridos"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "generate_vol3_symbols_ssh.sh")
    return _run_script_sse(script, [case_dir, vm_id, vm_ip, ssh_user, ssh_key], cwd=REPO_ROOT, timeout=60 * 60)





def acquire_memory(case_dir: str, vm_id: str, vm_ip: str, ssh_key: str, *, ssh_user: str = "debian", mode: str = "build", run_id: str = "R1", alert_ts_utc: str = "") -> dict:
    """
    Pure (Flask-free) memory acquisition (LiME over SSH), callable from
    background orchestrators (e.g. the Level B real-execution job) as well as
    from the HTTP route below. Returns the same fields the route returns as
    JSON, plus "ok": bool.
    """
    if not _is_safe_case_dir(case_dir):
        return {"ok": False, "result": "error", "error": "case_dir inválido"}
    if not vm_id or not vm_ip:
        return {"ok": False, "result": "error", "error": "vm_id y vm_ip requeridos"}
    if not ssh_key:
        return {"ok": False, "result": "error", "error": "ssh_key requerido (path en el servidor)"}

    run_id = (run_id or "R1").strip() or "R1"
    alert_ts_utc = (alert_ts_utc or "").strip()
    _get_or_set_alert_ts(case_dir, run_id=run_id, provided_alert_ts_utc=alert_ts_utc)

    _append_custody_entry(
        case_dir, "acquire_start", "forensics_api",
        run_id=run_id, details={"kind": "memory", "vm_id": vm_id, "vm_ip": vm_ip, "mode": mode}
    )
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_memory_lime_ssh.sh")

    _append_case_event(case_dir, "memory_start", run_id=run_id, meta={
        "vm_id": vm_id, "vm_ip": vm_ip, "ssh_user": ssh_user, "mode": mode
    })

    def _run_for_user(user: str):
        return _run_script(
            script,
            [case_dir, vm_id, vm_ip, user, ssh_key, mode],
            cwd=REPO_ROOT,
            timeout=60 * 60
        )

    resolved_node = resolve_node_for_remote_ops(instance_id=vm_id, vm_ip=vm_ip)
    resolved_ssh_user = str((resolved_node or {}).get("ssh_user") or "").strip()
    if resolved_ssh_user:
        ssh_user = resolved_ssh_user

    cleanup_preflight = None
    cleanup_recovery = None
    if str(mode or "").strip().lower() == "build":
        cleanup_preflight = cleanup_node_free_space(
            instance_id=vm_id,
            vm_ip=vm_ip,
            minimum_free_mb=MEMORY_BUILD_MIN_FREE_MB,
            max_attempts=2,
        )
        _append_case_event(
            case_dir,
            "memory_preflight_cleanup_completed" if cleanup_preflight.get("status") == "completed" else "memory_preflight_cleanup_failed",
            run_id=run_id,
            meta={
                "vm_id": vm_id,
                "vm_ip": vm_ip,
                "minimum_free_mb": MEMORY_BUILD_MIN_FREE_MB,
                "cleanup": cleanup_preflight,
            },
        )
        if cleanup_preflight.get("status") != "completed" and cleanup_preflight.get("reason") == "insufficient_free_space_after_cleanup":
            _append_custody_entry(
                case_dir,
                "acquire_failed",
                "forensics_api",
                run_id=run_id,
                outcome="error",
                details={
                    "kind": "memory",
                    "vm_id": vm_id,
                    "vm_ip": vm_ip,
                    "mode": mode,
                    "reason": "insufficient_free_space_after_cleanup",
                    "cleanup_preflight": cleanup_preflight,
                },
            )
            _register_custody_artifact(case_dir)
            _write_case_digest(case_dir, run_id=run_id)
            return {
                "ok": False,
                "result": "error",
                "error": (
                    f"insufficient free space on / after cleanup: "
                    f"{cleanup_preflight.get('free_mb_after')}MB < {MEMORY_BUILD_MIN_FREE_MB}MB"
                ),
                "exit_code": 51,
                "stdout": "\n".join(
                    line
                    for attempt in list(cleanup_preflight.get("attempts") or [])
                    for line in list(attempt.get("stdout_excerpt") or [])
                ),
                "stderr": "\n".join(
                    line
                    for attempt in list(cleanup_preflight.get("attempts") or [])
                    for line in list(attempt.get("stderr_excerpt") or [])
                ),
                "mem_dump": None,
                "sha256": None,
                "ssh_user_used": ssh_user,
                "attempted_users": [ssh_user] if ssh_user else [],
                "cleanup_preflight": cleanup_preflight,
            }

    candidate_users: list[str] = []
    for candidate in [resolved_ssh_user, ssh_user, "ubuntu", "debian"]:
        normalized = str(candidate or "").strip()
        if normalized and normalized not in candidate_users:
            candidate_users.append(normalized)

    attempted_users: list[str] = []

    def _run_with_user_fallback() -> tuple[int, str, str, str]:
        selected_user = candidate_users[0] if candidate_users else "debian"
        rc_local = 1
        out_local = ""
        err_local = ""
        for idx, candidate_user in enumerate(candidate_users or [selected_user]):
            if candidate_user not in attempted_users:
                attempted_users.append(candidate_user)
            rc_local, out_local, err_local = _run_for_user(candidate_user)
            selected_user = candidate_user
            auth_fail_local = (rc_local == 255) and ("Permission denied (publickey)" in (err_local or "") or "Permission denied" in (err_local or ""))
            if auth_fail_local and idx < len(candidate_users) - 1:
                continue
            break
        return rc_local, out_local, err_local, selected_user

    t0 = time.time()
    rc, out, err, ssh_user = _run_with_user_fallback()
    if rc == 51 and str(mode or "").strip().lower() == "build":
        cleanup_recovery = cleanup_node_free_space(
            instance_id=vm_id,
            vm_ip=vm_ip,
            minimum_free_mb=MEMORY_BUILD_MIN_FREE_MB,
            max_attempts=2,
        )
        _append_case_event(
            case_dir,
            "memory_recovery_cleanup_completed" if cleanup_recovery.get("status") == "completed" else "memory_recovery_cleanup_failed",
            run_id=run_id,
            meta={
                "vm_id": vm_id,
                "vm_ip": vm_ip,
                "minimum_free_mb": MEMORY_BUILD_MIN_FREE_MB,
                "cleanup": cleanup_recovery,
            },
        )
        if cleanup_recovery.get("status") == "completed":
            rc, out, err, ssh_user = _run_with_user_fallback()
    t1 = time.time()

    mem_rel = mem_size = sha_value = None
    if rc == 0:
        mem_rel, mem_size, sha_value = _register_memory_from_metadata(case_dir, vm_ip=vm_ip)

        if not mem_rel:
            produced_abs = ""
            try:
                lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
                if lines:
                    candidate = lines[-1]
                    if os.path.isabs(candidate) and os.path.exists(candidate):
                        produced_abs = candidate
            except Exception:
                produced_abs = ""

            if produced_abs:
                try:
                    mem_rel = os.path.relpath(produced_abs, case_dir)
                    if mem_rel.startswith("..") or os.path.isabs(mem_rel):
                        mem_rel = None
                except Exception:
                    mem_rel = None

                if mem_rel:
                    try:
                        mem_size = os.path.getsize(os.path.join(case_dir, mem_rel))
                    except Exception:
                        mem_size = None
                    _add_artifact(case_dir, mem_rel, "memory_lime")

    _append_case_event(
        case_dir,
        "memory_preserved" if (rc == 0 and mem_rel) else "memory_failed",
        run_id=run_id,
        meta={
            "vm_id": vm_id,
            "vm_ip": vm_ip,
            "rel": mem_rel,
            "size": mem_size,
            "sha256": sha_value,
            "exit_code": rc,
            "elapsed_s": round(t1 - t0, 3),
            "ssh_user_used": ssh_user,
            "attempted_users": attempted_users,
            "mode": mode,
        }
    )

    if mem_rel:
        _append_custody_entry(
            case_dir, "acquire_preserved", "forensics_api",
            run_id=run_id, artifact_rel=mem_rel,
            outcome="ok" if rc == 0 else "error",
            details={
                "kind": "memory",
                "vm_id": vm_id,
                "vm_ip": vm_ip,
                "sha256": sha_value,
                "size": mem_size,
                "mode": mode
            }
        )
    else:
        _append_custody_entry(
            case_dir, "acquire_failed", "forensics_api",
            run_id=run_id, outcome="error",
            details={
                "kind": "memory",
                "vm_id": vm_id,
                "vm_ip": vm_ip,
                "exit_code": rc,
                "mode": mode
            }
        )

    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    return {
        "ok": rc == 0,
        "result": "ok" if rc == 0 else "error",
        "exit_code": rc,
        "stdout": out,
        "stderr": err,
        "mem_dump": mem_rel,
        "sha256": sha_value,
        "ssh_user_used": ssh_user,
        "attempted_users": attempted_users,
        "cleanup_preflight": cleanup_preflight,
        "cleanup_recovery": cleanup_recovery,
    }


@forensics_bp.route("/api/forensics/acquire/memory_lime", methods=["POST"])
def api_forensics_acquire_memory():
    data = request.get_json(force=True, silent=True) or {}
    case_dir = data.get("case_dir")
    vm_id = data.get("vm_id")
    vm_ip = data.get("vm_ip")
    ssh_user = data.get("ssh_user", "debian")
    ssh_key = data.get("ssh_key", "")
    mode = data.get("mode", "build")
    run_id = (data.get("run_id") or "R1").strip()
    alert_ts_utc = (data.get("alert_ts_utc") or "").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not vm_ip:
        return jsonify({"error": "vm_id y vm_ip requeridos"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido (path en el servidor)"}), 400

    out = acquire_memory(case_dir, vm_id, vm_ip, ssh_key, ssh_user=ssh_user, mode=mode, run_id=run_id, alert_ts_utc=alert_ts_utc)
    status = 200 if out.get("ok") else 500
    return jsonify({k: v for k, v in out.items() if k != "ok"}), status


@forensics_bp.route("/api/forensics/acquire/memory_lime/stream", methods=["GET"])
def api_forensics_acquire_memory_stream():
    case_dir = request.args.get("case_dir", "")
    vm_id = request.args.get("vm_id", "")
    vm_ip = request.args.get("vm_ip", "")
    ssh_user = request.args.get("ssh_user", "debian")
    ssh_key = request.args.get("ssh_key", "")
    mode = request.args.get("mode", "build")
    run_id = (request.args.get("run_id") or "R1").strip()
    alert_ts_utc = (request.args.get("alert_ts_utc") or "").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not vm_id or not vm_ip:
        return jsonify({"error": "vm_id y vm_ip requeridos"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido"}), 400

    _get_or_set_alert_ts(case_dir, run_id=run_id, provided_alert_ts_utc=alert_ts_utc)

    _append_custody_entry(
        case_dir, "acquire_start", "forensics_api",
        run_id=run_id, details={"kind": "memory", "vm_id": vm_id, "vm_ip": vm_ip, "mode": mode}
    )
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "acquire_memory_lime_ssh.sh")
    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404

    candidates = [ssh_user] + [u for u in ["ubuntu", "debian"] if u != ssh_user]

    def sse():
        def emit(line: str):
            return f"data: {(line or '').rstrip(chr(10))}\n\n"

        start_ts = time.time()

        _append_case_event(case_dir, "memory_start", run_id=run_id, meta={
            "vm_id": vm_id, "vm_ip": vm_ip, "ssh_user": ssh_user, "mode": mode
        })

        yield emit(
            f"[SISTEMA] Starting memory acquisition (LiME) "
            f"vm_id={vm_id} ip={vm_ip} user={ssh_user} mode={mode} run_id={run_id}"
        )

        used_user = None
        final_rc = 1
        final_out = ""
        last_stdout_line = ""

        for user in candidates:
            used_user = user
            yield emit(f"[SISTEMA] Trying ssh_user={user}")

            cmd = [
                "bash", "-lc",
                f"stdbuf -oL -eL bash '{script}' '{case_dir}' '{vm_id}' '{vm_ip}' '{user}' '{ssh_key}' '{mode}'"
            ]
            proc = subprocess.Popen(
                cmd,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            lines = []
            for line in proc.stdout:
                lines.append(line)
                if (line or "").strip():
                    last_stdout_line = line.strip()
                yield emit(line.rstrip("\n"))

            proc.wait()
            final_rc = proc.returncode
            final_out = "".join(lines)

            if final_rc == 0:
                break
            if "Permission denied" in final_out:
                yield emit("[SISTEMA] Auth failed, retrying with next user...")
                continue
            break

        mem_rel = mem_size = sha_value = None
        if final_rc == 0:
            mem_rel, mem_size, sha_value = _register_memory_from_metadata(case_dir, vm_ip=vm_ip)

            if not mem_rel and last_stdout_line and os.path.isabs(last_stdout_line) and os.path.exists(last_stdout_line):
                try:
                    mem_rel = os.path.relpath(last_stdout_line, case_dir)
                    if mem_rel.startswith("..") or os.path.isabs(mem_rel):
                        mem_rel = None
                except Exception:
                    mem_rel = None

                if mem_rel:
                    try:
                        mem_size = os.path.getsize(os.path.join(case_dir, mem_rel))
                    except Exception:
                        mem_size = None
                    _add_artifact(case_dir, mem_rel, "memory_lime")

        _append_case_event(
            case_dir,
            "memory_preserved" if (final_rc == 0 and mem_rel) else "memory_failed",
            run_id=run_id,
            meta={
                "vm_id": vm_id,
                "vm_ip": vm_ip,
                "rel": mem_rel,
                "size": mem_size,
                "sha256": sha_value,
                "exit_code": final_rc,
                "elapsed_s": round(time.time() - start_ts, 3),
                "ssh_user_used": used_user,
                "mode": mode,
            }
        )

        if mem_rel:
            _append_custody_entry(
                case_dir, "acquire_preserved", "forensics_api",
                run_id=run_id, artifact_rel=mem_rel,
                outcome="ok",
                details={
                    "kind": "memory",
                    "vm_id": vm_id,
                    "vm_ip": vm_ip,
                    "sha256": sha_value,
                    "size": mem_size,
                    "mode": mode
                }
            )
        else:
            _append_custody_entry(
                case_dir, "acquire_failed", "forensics_api",
                run_id=run_id, outcome="error",
                details={
                    "kind": "memory",
                    "vm_id": vm_id,
                    "vm_ip": vm_ip,
                    "exit_code": final_rc,
                    "mode": mode
                }
            )

        _register_custody_artifact(case_dir)
        _write_case_digest(case_dir, run_id=run_id)

        payload = {
            "result": "ok" if final_rc == 0 else "error",
            "exit_code": final_rc,
            "mem_dump": mem_rel,
            "sha256": sha_value,
            "ssh_user_used": used_user,
            "last": last_stdout_line,
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(sse(), mimetype="text/event-stream")





def _read_text_first_line(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return (f.readline() or "").strip()
    except Exception:
        return ""














def _find_latest_disk_metadata(case_dir: str, vm_id: str):
    meta_dir = os.path.join(case_dir, "metadata")
    if not os.path.isdir(meta_dir):
        return (None, None)

    cands = []
    for fn in os.listdir(meta_dir):
        if fn.startswith(vm_id) and fn.endswith(".disk.metadata.json"):
            p = os.path.join(meta_dir, fn)
            try:
                cands.append((os.path.getmtime(p), p))
            except Exception:
                continue

    if not cands:
        return (None, None)

    cands.sort(key=lambda x: x[0], reverse=True)
    meta_path = cands[0][1]

    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta_obj = json.load(f)
        if not isinstance(meta_obj, dict):
            return (None, None)
        return (meta_path, meta_obj)
    except Exception:
        return (None, None)

def _register_disk_from_metadata(case_dir: str, vm_id: str):
    """
    Registra en manifest:
      - disk/<final_raw> como disk_raw usando sha del metadata/.sha256 (sin recalcular SHA del RAW)
      - metadata/<...>.disk.metadata.json como disk_metadata
      - metadata/<...>.disk.sha256 como disk_sha256_file (si existe)
    Devuelve: (disk_rel, disk_size, sha_value)
    """
    meta_path, meta_obj = _find_latest_disk_metadata(case_dir, vm_id)
    if not meta_path or not meta_obj:
        return (None, None, None)

    final_raw_name = (meta_obj.get("final_raw") or "").strip()
    if not final_raw_name:
        return (None, None, None)

    disk_rel = os.path.join("disk", final_raw_name)
    disk_abs = os.path.join(case_dir, disk_rel)
    if not os.path.exists(disk_abs):
        return (None, None, None)

    # base (para localizar el sha file)
    base = os.path.basename(meta_path).replace(".disk.metadata.json", "")
    sha_rel = os.path.join("metadata", f"{base}.disk.sha256")
    sha_abs = os.path.join(case_dir, sha_rel)

    sha_value = (meta_obj.get("sha256") or "").strip() or None
    if not sha_value and os.path.exists(sha_abs):
        sha_value = _read_text_first_line(sha_abs) or None

    try:
        disk_size = os.path.getsize(disk_abs)
    except Exception:
        disk_size = None

    # RAW (sin re-hash)
    _add_artifact_fast(case_dir, disk_rel, "disk_raw", sha256=sha_value, size=disk_size)

    # metadata.json (pequeño -> ok rehash)
    try:
        meta_rel = os.path.relpath(meta_path, case_dir)
        if not meta_rel.startswith("..") and not os.path.isabs(meta_rel):
            _add_artifact(case_dir, meta_rel, "disk_metadata")
    except Exception:
        pass

    # sha file (pequeño -> ok rehash)
    try:
        if os.path.exists(sha_abs):
            _add_artifact(case_dir, sha_rel, "disk_sha256_file")
    except Exception:
        pass

    return (disk_rel, disk_size, sha_value)







def _register_memory_from_metadata(case_dir: str, vm_ip: str = None):
    """
    Registra en manifest el dump LiME y sus ficheros metadata/sha.
    NO recalcula SHA del dump (usa metadata.json / .sha256 generados por el script).
    Devuelve: (mem_rel, mem_size, sha_value)
    """
    meta_dir = os.path.join(case_dir, "metadata")
    mem_dir  = os.path.join(case_dir, "memory")

    if not os.path.isdir(meta_dir):
        return (None, None, None)

    # Buscar el metadata más reciente de LiME
    cands = []
    for fn in os.listdir(meta_dir):
        # script: memdump_<VM_IP>_<UTC>.lime.metadata.json
        if not fn.endswith(".lime.metadata.json"):
            continue
        if vm_ip and (vm_ip not in fn):
            continue
        p = os.path.join(meta_dir, fn)
        try:
            cands.append((os.path.getmtime(p), p))
        except Exception:
            continue

    if not cands:
        return (None, None, None)

    cands.sort(key=lambda x: x[0], reverse=True)
    meta_path = cands[0][1]

    meta_obj = None
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta_obj = json.load(f)
    except Exception:
        meta_obj = None

    dump_file = ((meta_obj or {}).get("dump_file") or "").strip()
    sha_value = ((meta_obj or {}).get("sha256") or "").strip() or None

    if not dump_file:
        return (None, None, sha_value)

    dump_abs = os.path.join(mem_dir, dump_file)
    if not os.path.exists(dump_abs):
        return (None, None, sha_value)

    mem_rel = os.path.join("memory", dump_file)

    # sha fallback: leer el .sha256 si no viene en metadata.json
    base_sha = os.path.basename(meta_path).replace(".metadata.json", "")
    sha_rel  = os.path.join("metadata", f"{base_sha}.sha256")
    sha_abs  = os.path.join(case_dir, sha_rel)

    if not sha_value and os.path.exists(sha_abs):
        try:
            with open(sha_abs, "r", encoding="utf-8") as f:
                sha_value = (f.read() or "").strip() or None
        except Exception:
            sha_value = None

    # size
    try:
        mem_size = os.path.getsize(dump_abs)
    except Exception:
        mem_size = None

    # Registrar dump (rápido)
    _add_artifact_fast(case_dir, mem_rel, "memory_lime", sha256=sha_value, size=mem_size)

    # Registrar metadata (pequeños)
    try:
        rel_mp = os.path.relpath(meta_path, case_dir)
        if not rel_mp.startswith("..") and not os.path.isabs(rel_mp):
            _add_artifact(case_dir, rel_mp, "memory_metadata")
    except Exception:
        pass

    try:
        if os.path.exists(sha_abs):
            _add_artifact(case_dir, sha_rel, "memory_sha256_file")
    except Exception:
        pass

    return (mem_rel, mem_size, sha_value)






@forensics_bp.route("/api/forensics/analyze/all/stream", methods=["GET"])
def api_forensics_analyze_all_stream():
    case_dir = request.args.get("case_dir", "").strip()
    symbols_dir = request.args.get("symbols_dir", "").strip()  # opcional pero necesario para vol3
    vol_cmd = (request.args.get("vol_cmd", "vol") or "vol").strip()
    run_id = (request.args.get("run_id") or "R1").strip()

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "analyze_case_all.sh")

    _append_case_event(case_dir, "analysis_all_start", run_id=run_id, meta={
        "symbols_dir": symbols_dir or None,
        "vol_cmd": vol_cmd
    })

    # SSE: ejecuta el script y al final emite done
    resp = _run_script_sse(
        script,
        [case_dir, symbols_dir, vol_cmd],
        cwd=REPO_ROOT,
        timeout=60 * 60
    )

    return resp






# ============================================================
# DISK ANALYSIS (TSK) - SSE
# ============================================================

def _safe_join_case(case_dir: str, rel_path: str) -> str:
    """
    Une case_dir + rel_path de forma segura evitando traversal.
    Devuelve abs_path si es seguro; si no, devuelve "".
    """
    if not rel_path:
        return ""
    rel_path = rel_path.strip()

    # prohibiciones básicas
    if rel_path.startswith("/") or rel_path.startswith("\\"):
        return ""
    if ".." in rel_path.replace("\\", "/").split("/"):
        return ""

    abs_path = os.path.normpath(os.path.join(case_dir, rel_path))
    case_norm = os.path.normpath(case_dir)

    # asegurar que queda dentro del case_dir
    if not abs_path.startswith(case_norm + os.sep):
        return ""
    return abs_path


def _register_dir_artifact(case_dir: str, rel_dir: str, a_type: str):
    """
    Registra un directorio como artefacto (sin sha/size).
    """
    manifest = _read_manifest(case_dir)
    manifest.setdefault("artifacts", []).append({
        "type": a_type,
        "rel_path": rel_dir,
        "sha256": None,
        "size": None,
        "ts": _utc_now_iso()
    })
    _write_manifest(case_dir, manifest)


@forensics_bp.route("/api/forensics/analyze/disk_tsk/stream", methods=["GET"])
def api_forensics_analyze_disk_tsk_stream():
    case_dir = (request.args.get("case_dir") or "").strip()
    disk_rel = (request.args.get("disk") or "").strip()
    run_id = (request.args.get("run_id") or "R1").strip() or "R1"

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not disk_rel:
        return jsonify({"error": "disk requerido (rel_path desde manifest)"}), 400

    # Resolver path del disco dentro del caso
    disk_abs = _safe_join_case(case_dir, disk_rel)
    if not disk_abs:
        return jsonify({"error": "disk rel_path inválido"}), 400
    if not os.path.exists(disk_abs):
        return jsonify({"error": f"Disk no existe: {disk_rel}"}), 404

    # Output dir: analysis/tsk/<run_id>/<basename-disco-sin-ext>
    disk_base = os.path.basename(disk_rel)
    disk_stem = re.sub(r"\.(raw|img|dd|qcow2|vmdk)$", "", disk_base, flags=re.IGNORECASE)
    out_rel = os.path.join("analysis", "tsk", run_id, disk_stem)
    out_abs = os.path.join(case_dir, out_rel)
    os.makedirs(out_abs, exist_ok=True)

    script = os.path.join(FORENSICS_SCRIPTS_DIR, "analyze_disk_tsk.sh")
    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404
    try:
        os.chmod(script, 0o755)
    except Exception:
        pass

    def sse():
        def emit(line: str):
            line = (line or "").rstrip("\n")
            return f"data: {line}\n\n"

        start_ts = time.time()
        script_name = os.path.basename(script)

        _append_case_event(case_dir, "disk_analysis_start", run_id=run_id, meta={
            "disk_rel": disk_rel,
            "out_rel": out_rel,
            "script": script_name
        })

        yield emit(f"[SISTEMA] Starting TSK analysis run_id={run_id}")
        yield emit(f"[SISTEMA] disk={disk_rel}")
        yield emit(f"[SISTEMA] out_dir={out_rel}")
        yield emit(f"[START] {script_name} {disk_abs} -> {out_abs}")

        # Ejecuta script con salida en vivo
        p = subprocess.Popen(
            ["bash", script, case_dir, disk_abs, out_abs],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        last_line = ""
        for line in p.stdout:
            line = (line or "").rstrip("\n")
            if line.strip():
                last_line = line.strip()
            yield emit(line)

        p.wait()
        rc = p.returncode if p.returncode is not None else 1

        # Registrar artefacto si hay output
        if rc == 0 and os.path.isdir(out_abs):
            try:
                _register_dir_artifact(case_dir, out_rel, "tsk_output_dir")
            except Exception:
                pass

        _append_case_event(case_dir, "disk_analysis_done" if rc == 0 else "disk_analysis_failed", run_id=run_id, meta={
            "disk_rel": disk_rel,
            "out_rel": out_rel,
            "exit_code": rc,
            "elapsed_s": round(time.time() - start_ts, 3),
            "last": last_line
        })

        payload = {
            "result": "ok" if rc == 0 else "error",
            "exit_code": rc,
            "out_dir": out_rel if (rc == 0 and os.path.isdir(out_abs)) else None,
            "last": last_line,
            "disk": disk_rel,
            "run_id": run_id,
            "script": script_name
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(sse(), mimetype="text/event-stream")







@forensics_bp.route("/api/forensics/traffic/preserve/stream", methods=["GET"])
def api_forensics_traffic_preserve_stream():
    case_dir = (request.args.get("case_dir") or "").strip()
    run_id = (request.args.get("run_id") or "R1").strip() or "R1"

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400

    # Script: repo root
    script = os.path.join(REPO_ROOT, "nics_scenario_traffic_preserve_summary.sh")
    if not os.path.exists(script):
        # fallback
        script2 = os.path.join(FORENSICS_SCRIPTS_DIR, "nics_scenario_traffic_preserve_summary.sh")
        script = script2

    if not os.path.exists(script):
        return jsonify({"error": f"Script no encontrado: {script}"}), 404

    try:
        os.chmod(script, 0o755)
    except Exception:
        pass

    def sse():
        def emit(line: str):
            line = (line or "").rstrip("\n")
            return f"data: {line}\n\n"

        start_ts = time.time()
        script_name = os.path.basename(script)

        ensure_case_layout(case_dir)

        # Eventos M2: inicio captura/preservación (lo usamos como pcap_start)
        _append_case_event(case_dir, "pcap_start", run_id=run_id, meta={
            "script": script_name,
            "mode": "preserve_summary",
        })
        _append_case_event(case_dir, "traffic_preserve_start", run_id=run_id, meta={
            "script": script_name,
        })

        yield emit(f"[SISTEMA] Starting traffic preserve: case_dir={case_dir} run_id={run_id}")
        yield emit(f"[START] {script_name}")

        p = subprocess.Popen(
            ["bash", script],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        last_line = ""
        for line in p.stdout:
            line = (line or "").rstrip("\n")
            if line.strip():
                last_line = line.strip()
            yield emit(line)

        p.wait()
        rc = p.returncode if p.returncode is not None else 1

        # POST: indexar PCAP preservados dentro del CASE al manifest
        index_summary = {"count": 0, "total_bytes": 0, "added": 0, "already_present": 0}
        if rc == 0:
            try:
                index_summary = _index_preserved_pcaps_into_manifest(
                    case_dir,
                    preserve_rel_root="network/traffic_preserved/full_scenario_captures",
                    artifact_type="network_pcap",
                )
            except Exception as e:
                # si falla el indexado, lo reflejamos como warning pero no rompemos el preserve
                yield emit(f"[WARN] PCAP indexing failed: {e}")

        # Eventos M2: fin (lo usamos como pcap_preserved)
        _append_case_event(
            case_dir,
            "pcap_preserved" if (rc == 0) else "pcap_failed",
            run_id=run_id,
            meta={
                "script": script_name,
                "exit_code": rc,
                "elapsed_s": round(time.time() - start_ts, 3),
                "last": last_line,
                "pcaps_count": index_summary.get("count"),
                "pcaps_added": index_summary.get("added"),
                "pcaps_already_present": index_summary.get("already_present"),
                "pcaps_total_bytes": index_summary.get("total_bytes"),
            }
        )
        _append_case_event(
            case_dir,
            "traffic_preserve_done" if (rc == 0) else "traffic_preserve_failed",
            run_id=run_id,
            meta={
                "script": script_name,
                "exit_code": rc,
                "elapsed_s": round(time.time() - start_ts, 3),
                "last": last_line,
                "pcaps_count": index_summary.get("count"),
                "pcaps_total_bytes": index_summary.get("total_bytes"),
            }
        )

        payload = {
            "result": "ok" if rc == 0 else "error",
            "exit_code": rc,
            "last": last_line,
            "script": script_name,
            "run_id": run_id,
            "indexed": index_summary,
        }
        yield f"event: done\ndata: {json.dumps(payload)}\n\n"

    return Response(sse(), mimetype="text/event-stream")







def _list_case_memory_lime(case_dir: str):
    """
    Lista TODOS los memory dumps .lime dentro del caso:
      - Busca en <case_dir>/memory/*.lime
      - Cruza SHA con manifest si existe
      - Ordena por mtime (más reciente primero)
    """
    mem_dir = os.path.join(case_dir, "memory")
    out = []

    sha_by_rel = {}
    try:
        m = _read_manifest(case_dir)
        for a in (m.get("artifacts") or []):
            rel = a.get("rel_path")
            if not rel:
                continue
            # pillamos sha si es un dump real
            if a.get("type") == "memory_lime" or (str(rel).startswith("memory/") and str(rel).endswith(".lime")):
                sha_by_rel[str(rel)] = a.get("sha256")
    except Exception:
        pass

    if not os.path.isdir(mem_dir):
        return out

    for fn in os.listdir(mem_dir):
        if not fn.lower().endswith(".lime"):
            continue

        abs_p = os.path.join(mem_dir, fn)
        if not os.path.isfile(abs_p):
            continue

        rel = os.path.join("memory", fn)
        try:
            st = os.stat(abs_p)
            out.append({
                "rel_path": rel,
                "size": st.st_size,
                "mtime": st.st_mtime,
                "sha256": sha_by_rel.get(rel)
            })
        except Exception:
            out.append({"rel_path": rel, "size": None, "mtime": 0, "sha256": sha_by_rel.get(rel)})

    out.sort(key=lambda x: x.get("mtime", 0), reverse=True)
    return out



@forensics_bp.route("/api/forensics/case/memory/list", methods=["GET"])
def api_forensics_case_memory_list():
    case_dir = (request.args.get("case_dir") or "").strip()
    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400

    try:
        dumps = _list_case_memory_lime(case_dir)
        return jsonify({"case_dir": case_dir, "dumps": dumps}), 200
    except Exception as e:
        logger.error(f"Error /api/forensics/case/memory/list: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500




def _index_preserved_pcaps_into_manifest(
    case_dir: str,
    preserve_rel_root: str = "network/traffic_preserved/full_scenario_captures",
    artifact_type: str = "network_pcap",
) -> dict:
    """
    Indexa TODOS los *.pcap bajo:
      CASE/.../<preserve_rel_root>/**
    y los registra en manifest.json como artifacts con:
      type=artifact_type, rel_path, sha256, size, ts
    Devuelve resumen: {count, total_bytes, added, already_present}
    """
    ensure_case_layout(case_dir)

    preserve_abs_root = os.path.join(case_dir, preserve_rel_root)
    if not os.path.isdir(preserve_abs_root):
        return {"count": 0, "total_bytes": 0, "added": 0, "already_present": 0}

    manifest = _read_manifest(case_dir)
    artifacts = manifest.setdefault("artifacts", [])

    existing = set()
    for a in artifacts:
        rp = str(a.get("rel_path") or "")
        if rp:
            existing.add(rp)

    added = 0
    already = 0
    total_bytes = 0
    count = 0

    for root, _, files in os.walk(preserve_abs_root):
        for fn in files:
            if not fn.endswith(".pcap"):
                continue

            abs_p = os.path.join(root, fn)
            rel_p = os.path.relpath(abs_p, case_dir).replace("\\", "/")

            try:
                sz = os.path.getsize(abs_p)
            except Exception:
                sz = None

            # dedup por rel_path
            if rel_p in existing:
                already += 1
                # aun así contamos sizes para resumen
                if isinstance(sz, int):
                    total_bytes += sz
                    count += 1
                continue

            try:
                sha = _sha256_file(abs_p)
            except Exception:
                sha = None

            artifacts.append({
                "type": artifact_type,
                "rel_path": rel_p,
                "sha256": sha,
                "size": sz,
                "ts": _utc_now_iso(),
            })
            existing.add(rel_p)

            added += 1
            if isinstance(sz, int):
                total_bytes += sz
            count += 1

    _write_manifest(case_dir, manifest)

    return {
        "count": count,
        "total_bytes": total_bytes,
        "added": added,
        "already_present": already,
    }






    # ============================================================
# CHAIN OF CUSTODY (append-only + hash chaining)
# ============================================================

def _custody_path(case_dir: str) -> str:
    return os.path.join(case_dir, "chain_of_custody.log")  # JSONL append-only

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _read_last_custody_hash(case_dir: str) -> str:
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        return "0" * 64

    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size <= 0:
                return "0" * 64

            back = min(8192, size)
            f.seek(-back, os.SEEK_END)
            tail = f.read().decode("utf-8", errors="ignore")

        lines = [ln for ln in tail.splitlines() if ln.strip()]
        if not lines:
            return "0" * 64

        last = json.loads(lines[-1])
        h = (last.get("entry_hash") or "").strip()
        return h if h else "0" * 64
    except Exception:
        return "0" * 64

def _ensure_custody_file(case_dir: str) -> None:
    if not _is_safe_case_dir(case_dir):
        return
    p = _custody_path(case_dir)
    if not os.path.exists(p):
        try:
            Path(p).touch()
        except Exception:
            pass

def _append_custody_entry(
    case_dir: str,
    action: str,
    actor: str,
    run_id: str = "R1",
    artifact_rel: str = None,
    outcome: str = "ok",
    details: dict = None,
) -> None:
    if not _is_safe_case_dir(case_dir):
        return

    ensure_case_layout(case_dir)
    _ensure_custody_file(case_dir)

    with _custody_thread_lock(case_dir):
        with open(_custody_path(case_dir), "a+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                prev_hash = _read_last_custody_hash(case_dir)
                ts = _utc_now_iso()

                entry = {
                    "ts_utc": ts,
                    "ts_epoch": iso_to_epoch(ts),
                    "run_id": (run_id or "R1"),
                    "actor": actor,
                    "action": action,
                    "artifact_rel": artifact_rel,
                    "outcome": outcome,
                    "details": (details or {}),
                    "prev_hash": prev_hash,
                }

                payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode("utf-8")
                entry_hash = _sha256_hex(payload)
                entry["entry_hash"] = entry_hash

                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                f.flush()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

def _register_custody_artifact(case_dir: str) -> None:
    """
    Registra chain_of_custody.log en manifest (sha/size).
    """
    rel = "chain_of_custody.log"
    abs_path = os.path.join(case_dir, rel)
    if not os.path.exists(abs_path):
        return

    try:
        size = os.path.getsize(abs_path)
        sha = _sha256_file(abs_path)
    except Exception:
        size = None
        sha = None

    _add_artifact_fast(case_dir, rel, "custody_log", sha256=sha, size=size)







#---------------------------------------DFIR Orchestrator AUTO








from app_core.infrastructure.ics_traffic.traffic_api import capture_packets_fixed_duration
from app_core.infrastructure.forensics.network_context_importer import (
    import_continuous_network_context,
    initialize_volatile_first_acquisition,
    update_acquisition_profile,
)
def _resolve_dfir_targets_from_openstack(names_lower: list) -> list:
    conn = None
    try:
        conn = get_openstack_connection()
        targets = []
        want = set([n.lower() for n in (names_lower or []) if n])

        for server in conn.compute.servers(details=True):
            sname = (server.name or "").lower()
            hit = None
            for w in want:
                if w in sname:
                    hit = w
                    break
            if not hit:
                continue

            ip_private = None
            ip_floating = None

            addresses = server.addresses or {}
            for _, addrs in addresses.items():
                for a in addrs:
                    addr = a.get("addr")
                    ip_type = a.get("OS-EXT-IPS:type")
                    if ip_type == "floating":
                        ip_floating = addr
                    else:
                        ip_private = addr

            targets.append({
                "role": hit,
                "vm_id": server.id,
                "vm_name": server.name,
                "vm_ip": ip_floating or ip_private or ""
            })

        return targets
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _dfir_ssh_user_for_role(role: str) -> str:
    r = (role or "").lower()
    if r == "victim":
        return "ubuntu"
    return "debian"



@forensics_bp.route("/api/dfir/orchestrator/trigger", methods=["POST"])
def api_dfir_orchestrator_trigger():
    data = request.get_json(force=True, silent=True) or {}

    case_dir = (data.get("case_dir") or "").strip()
    run_id = (data.get("run_id") or "R1").strip() or "R1"
    alert_ts_utc = (data.get("alert_ts_utc") or "").strip()

    traffic_seconds = int(data.get("traffic_seconds") or 20)

    # SSH key server-side para LiME
    ssh_key = (data.get("ssh_key") or os.environ.get("NICS_DFIR_SSH_KEY") or "").strip()
    mode = (data.get("mem_mode") or "build").strip() or "build"
    container_name = (data.get("container_name") or "nova_libvirt").strip() or "nova_libvirt"

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "case_dir inválido"}), 400
    if not ssh_key:
        return jsonify({"error": "ssh_key requerido para DFIR AUTO. Pasa ssh_key o define NICS_DFIR_SSH_KEY"}), 400

    ensure_case_layout(case_dir)

    # Ancla alert ts y registra evento alert si no existe
    alert_ts = _get_or_set_alert_ts(case_dir, run_id=run_id, provided_alert_ts_utc=alert_ts_utc)

    # Resolver targets
    targets = _resolve_dfir_targets_from_openstack(["fuxa", "plc", "victim"])
    if not targets:
        return jsonify({"error": "No se pudieron resolver targets fuxa plc victim en OpenStack"}), 500

    # Validar IPs
    targets_ok = [t for t in targets if (t.get("vm_id") and t.get("vm_ip"))]
    if not targets_ok:
        return jsonify({"error": "Targets encontrados pero sin vm_ip resoluble"}), 500

    # Start orchestration
    _append_case_event(case_dir, "dfir_orchestration_start", run_id=run_id, meta={
        "targets": [{"role": t["role"], "vm_id": t["vm_id"], "vm_ip": t["vm_ip"]} for t in targets_ok],
        "traffic_seconds": traffic_seconds,
        "memory_mode": mode,
        "disk_container": container_name,
        "alert_ts_utc": alert_ts,
    })
    _append_custody_entry(case_dir, "dfir_orchestration_start", "forensics_api", run_id=run_id, details={
        "targets": [{"role": t["role"], "vm_id": t["vm_id"]} for t in targets_ok]
    })
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    initialize_volatile_first_acquisition(
        case_dir,
        run_id=run_id,
        case_created_utc=_utc_now_iso(),
        acquisition_started_utc=_utc_now_iso(),
        trigger_time_utc=alert_ts,
        pre_context_seconds=max(int(traffic_seconds or 0), 120),
        post_context_seconds=max(int(traffic_seconds or 0), 120),
    )

    results = {"traffic": [], "network_context": None, "memory": [], "disk": []}

    # 1) Memory LiME per VM
    update_acquisition_profile(case_dir, run_id=run_id, merge_fields={"memory_started_utc": _utc_now_iso()})
    for t in targets_ok:
        vm_id = t["vm_id"]
        vm_ip = t["vm_ip"]
        role = t["role"]
        resolved_node = resolve_node_for_remote_ops(instance_id=vm_id, vm_ip=vm_ip)
        ssh_user = str((resolved_node or {}).get("ssh_user") or "").strip() or _dfir_ssh_user_for_role(role)

        _append_case_event(case_dir, "dfir_step_start", run_id=run_id, meta={"step": "memory", "vm_id": vm_id, "vm_ip": vm_ip, "role": role})
        # Reutiliza tu función POST existente a nivel interno llamando directamente al script
        # para no depender del servidor HTTP en loopback
        payload = {
            "case_dir": case_dir,
            "vm_id": vm_id,
            "vm_ip": vm_ip,
            "ssh_user": ssh_user,
            "ssh_key": ssh_key,
            "mode": mode,
            "run_id": run_id,
            "alert_ts_utc": alert_ts
        }
        with forensics_bp.test_request_context(json=payload_mem):
            resp = api_forensics_acquire_memory()
        if isinstance(resp, tuple):
            body, code = resp
        else:
            body, code = resp, 200

        if code != 200:
            _append_case_event(case_dir, "dfir_step_failed", run_id=run_id, meta={"step": "memory", "vm_id": vm_id, "role": role, "http_code": code})
            return jsonify({"error": "memory_failed", "vm_id": vm_id, "role": role}), 500

        try:
            results["memory"].append(body.get_json())
        except Exception:
            results["memory"].append({"result": "ok", "vm_id": vm_id})

        update_acquisition_profile(case_dir, run_id=run_id, merge_fields={"memory_completed_utc": _utc_now_iso()})
        _append_case_event(case_dir, "dfir_step_done", run_id=run_id, meta={"step": "memory", "vm_id": vm_id, "role": role})

    # 2) Network context import from the continuous rolling capture buffer.
    _append_case_event(case_dir, "dfir_step_start", run_id=run_id, meta={"step": "network_context_import", "source": "full_scenario_captures"})
    try:
        network_result = import_continuous_network_context(
            case_dir,
            run_id=run_id,
            trigger_time_utc=alert_ts,
            pre_context_seconds=max(int(traffic_seconds or 0), 120),
            post_context_seconds=max(int(traffic_seconds or 0), 120),
        )
        results["network_context"] = network_result
        results["traffic"] = [network_result]
        _append_case_event(case_dir, "dfir_step_done", run_id=run_id, meta={"step": "network_context_import", "preserved_segments": network_result.get("preserved_segments"), "pending_segments": network_result.get("pending_segments")})
    except Exception as e:
        _append_case_event(case_dir, "dfir_step_failed", run_id=run_id, meta={"step": "network_context_import", "reason": str(e)})
        return jsonify({"error": "network_context_import_failed", "reason": str(e)}), 500

    # 3) Disk RAW per VM
    update_acquisition_profile(case_dir, run_id=run_id, merge_fields={"disk_started_utc": _utc_now_iso()})
    for t in targets_ok:
        vm_id = t["vm_id"]
        role = t["role"]

        _append_case_event(case_dir, "dfir_step_start", run_id=run_id, meta={"step": "disk", "vm_id": vm_id, "role": role})
        payload = {
            "case_dir": case_dir,
            "vm_id": vm_id,
            "container_name": container_name,
            "run_id": run_id,
            "alert_ts_utc": alert_ts
        }
        with forensics_bp.test_request_context(json=payload_disk):
            resp = api_forensics_acquire_disk()
        if isinstance(resp, tuple):
            body, code = resp
        else:
            body, code = resp, 200

        if code != 200:
            _append_case_event(case_dir, "dfir_step_failed", run_id=run_id, meta={"step": "disk", "vm_id": vm_id, "role": role, "http_code": code})
            return jsonify({"error": "disk_failed", "vm_id": vm_id, "role": role}), 500

        try:
            results["disk"].append(body.get_json())
        except Exception:
            results["disk"].append({"result": "ok", "vm_id": vm_id})

        _append_case_event(case_dir, "dfir_step_done", run_id=run_id, meta={"step": "disk", "vm_id": vm_id, "role": role})

    _append_case_event(case_dir, "dfir_orchestration_done", run_id=run_id, meta={"targets_count": len(targets_ok)})
    _append_custody_entry(case_dir, "dfir_orchestration_done", "forensics_api", run_id=run_id, details={"targets_count": len(targets_ok)})
    _register_custody_artifact(case_dir)
    _write_case_digest(case_dir, run_id=run_id)

    return jsonify({
        "result": "ok",
        "case_dir": case_dir,
        "run_id": run_id,
        "alert_ts_utc": alert_ts,
        "targets": targets_ok,
        "results": results
    }), 200




 

def _dfir_create_case_internal(run_id: str = "R1", *, source: str = "dfir") -> str:
    guard = _active_preservation_guard()
    if not guard.get("allowed"):
        raise RuntimeError(str(guard.get("reason") or "active_preservation_in_progress"))

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    case_dir = os.path.join(EVIDENCE_ROOT, f"CASE-{ts}")
    os.makedirs(case_dir, exist_ok=True)

    logger.info(f"[DFIR_CASE_CREATE] REPO_ROOT={REPO_ROOT}")
    logger.info(f"[DFIR_CASE_CREATE] EVIDENCE_ROOT={EVIDENCE_ROOT}")
    logger.info(f"[DFIR_CASE_CREATE] case_dir={case_dir}")
    logger.info(f"[DFIR_CASE_CREATE] ACTIVE_CASE_PTR={os.path.join(EVIDENCE_ROOT, '_active_case.txt')}")

    for d in ["metadata", "network", "disk", "memory", "industrial", "analysis", "derived"]:
        os.makedirs(os.path.join(case_dir, d), exist_ok=True)

    ensure_case_layout(case_dir)

    set_active_case_dir(case_dir)
    _write_active_preservation_state(case_dir, run_id=run_id, state="running", source=source)
    logger.info("[DFIR_CASE_CREATE] active case pointer written")

    _ensure_custody_file(case_dir)

    manifest = {
        "case_dir": case_dir,
        "created_at": _utc_now_iso(),
        "artifacts": []
    }
    _write_manifest(case_dir, manifest)

    _append_custody_entry(case_dir, "case_created", "forensics_api", run_id=run_id, details={"case_dir": case_dir})
    _append_case_event(case_dir, "active_preservation_claimed", run_id=run_id, meta={"source": source})

    _register_custody_artifact(case_dir)
    _export_time_sync(case_dir, run_id=run_id)
    _write_case_digest(case_dir, run_id=run_id)

    evp = _events_path(case_dir)
    if not os.path.exists(evp):
        Path(evp).touch()

    return case_dir




    # ============================================================
# DFIR AUTO ORCHESTRATOR (SSE)
# - Single-run lock
# - SSH key autodetection: query -> env -> common defaults
# ============================================================

DFIR_ORCH_LOCK = threading.Lock()


def _resolve_ssh_key_path(raw: str) -> str:
    s = (raw or "").strip()
    if not s:
        return ""
    # Expande $HOME / ${HOME} y ~
    s = os.path.expandvars(s)
    s = os.path.expanduser(s)
    p = os.path.abspath(s)
    # Solo válido si existe como fichero
    return p if os.path.isfile(p) else ""


def _detect_ssh_key_path() -> str:
    # Orden: env -> rutas por defecto
    candidates = [
        os.environ.get("NICS_DFIR_SSH_KEY", ""),
        os.environ.get("SSH_KEY", ""),          # tu caso: SSH_KEY="$HOME/.ssh/my_key"
        "~/.ssh/my_key",
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
    ]
    for c in candidates:
        p = _resolve_ssh_key_path(c)
        if p:
            return p
    return ""


@forensics_bp.route("/api/dfir/orchestrator/auto/pending", methods=["GET"])
def api_dfir_orchestrator_auto_pending():
    running_jobs = _running_scientific_jobs()
    if running_jobs:
        return jsonify(
            {
                "pending": False,
                "suppressed": True,
                "reason": "scientific_workflow_running",
                "message": (
                    "A DFIR AUTO case-conflict prompt is suppressed while a Level A/B/C scientific workflow is running."
                ),
                "running_jobs": running_jobs,
            }
        ), 200
    pending = _find_pending_dfir_auto_decision()
    if not pending:
        return jsonify({"pending": False}), 200
    return jsonify({"pending": True, "decision": pending}), 200


@forensics_bp.route("/api/dfir/orchestrator/active", methods=["GET"])
def api_dfir_orchestrator_active():
    _active_preservation_guard()
    current = _load_active_preservation_state()
    if not current:
        return jsonify({"active": False}), 200

    case_dir = os.path.abspath(str(current.get("case_dir") or ""))
    case_id = str(current.get("case_id") or (os.path.basename(case_dir) if case_dir else "")).strip() or None
    started_at = str(current.get("started_at_utc") or "").strip() or None
    elapsed_seconds = None
    if started_at:
        try:
            started_dt = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            if started_dt.tzinfo is None:
                started_dt = started_dt.replace(tzinfo=timezone.utc)
            elapsed_seconds = max(0.0, (datetime.now(timezone.utc) - started_dt.astimezone(timezone.utc)).total_seconds())
        except Exception:
            elapsed_seconds = None

    events = _read_jsonl_events(case_dir) if case_dir and os.path.isdir(case_dir) else []
    last_event = events[-1] if events else {}
    return jsonify(
        {
            "active": True,
            "case_id": case_id,
            "case_dir": relative_path(Path(case_dir)) if case_dir and os.path.isdir(case_dir) else (case_dir or None),
            "run_id": str(current.get("run_id") or "R1"),
            "state": str(current.get("state") or "running"),
            "source": str(current.get("source") or "dfir"),
            "started_at_utc": started_at,
            "elapsed_seconds": elapsed_seconds,
            "last_event": str(last_event.get("event") or "") or None,
            "last_event_at_utc": str(last_event.get("ts_utc") or last_event.get("timestamp") or "") or None,
            "phase_label": str(last_event.get("event") or current.get("state") or "running").replace("_", " "),
        }
    ), 200


@forensics_bp.route("/api/dfir/orchestrator/auto/plan", methods=["POST"])
def api_dfir_orchestrator_auto_plan():
    data = request.get_json(force=True, silent=True) or {}
    operator = str(data.get("operator_hint") or "index_dfir_auto").strip() or "index_dfir_auto"
    alert = _sanitize_dfir_alert_payload(data.get("alert") or {})
    stream_params = {
        "run_id": str(data.get("run_id") or "R1").strip() or "R1",
        "traffic_seconds": int(data.get("traffic_seconds") or 20),
        "mem_mode": str(data.get("mem_mode") or "build").strip() or "build",
        "container_name": str(data.get("container_name") or "nova_libvirt").strip() or "nova_libvirt",
    }

    active_guard = _active_preservation_guard()
    if not active_guard.get("allowed"):
        decision = _create_dfir_auto_decision(
            status="blocked_active_preservation",
            alert=alert,
            operator=operator,
            stream_params=stream_params,
            context={"active_preservation": active_guard},
            message=str(active_guard.get("reason") or "Active preservation is already running."),
            recommended_action="wait_for_current_preservation",
        )
        return jsonify(
            {
                "status": "blocked",
                "reason": "active_preservation_in_progress",
                "message": decision["message"],
                "decision": decision,
            }
        ), 200

    running_jobs = _running_scientific_jobs()
    if running_jobs:
        message = (
            "DFIR AUTO did not open a new case because a scientific repetition workflow is currently running. "
            "During Level A/B/C execution, new background auto-preservation must not coexist with campaign-controlled cases."
        )
        decision = _create_dfir_auto_decision(
            status="blocked_by_scientific_run",
            alert=alert,
            operator=operator,
            stream_params=stream_params,
            context={"running_scientific_jobs": running_jobs},
            message=message,
            recommended_action="wait_for_scientific_workflow_completion",
        )
        return jsonify(
            {
                "status": "blocked",
                "reason": "scientific_workflow_running",
                "message": message,
                "decision": decision,
                "running_jobs": running_jobs,
            }
        ), 200

    existing_pending = _find_pending_dfir_auto_decision()
    if existing_pending:
        observed = list(existing_pending.get("observed_alerts") or [])
        observed.append({"ts_utc": _utc_now_iso(), "alert": alert})
        existing_pending["observed_alerts"] = observed[-20:]
        existing_pending = _write_dfir_auto_decision(existing_pending)
        return jsonify(
            {
                "status": "decision_required",
                "message": str(existing_pending.get("message") or "A DFIR AUTO decision is already pending."),
                "decision": existing_pending,
            }
        ), 200

    previous_case = _preferred_existing_case()
    if previous_case:
        message = (
            f"A preserved forensic case already exists ({previous_case['case_id']}). "
            "Because no Level A/B/C workflow is currently running, operator approval is required before DFIR AUTO creates another case."
        )
        decision = _create_dfir_auto_decision(
            status="pending_user_choice",
            alert=alert,
            operator=operator,
            stream_params=stream_params,
            context={"previous_case": previous_case},
            message=message,
            recommended_action="prompt_operator_for_case_conflict_resolution",
        )
        return jsonify(
            {
                "status": "decision_required",
                "message": message,
                "decision": decision,
                "options": [
                    "coexist_with_previous_case",
                    "replace_previous_case",
                    "keep_previous_case_only",
                ],
            }
        ), 200

    decision = _create_dfir_auto_decision(
        status="approved_without_previous_case",
        alert=alert,
        operator=operator,
        stream_params=stream_params,
        context={"previous_case": None},
        message="No preserved case conflict exists. DFIR AUTO may create a new case immediately.",
        recommended_action="launch_now",
    )
    return jsonify(
        {
            "status": "approved",
            "message": decision["message"],
            "decision": decision,
            "stream_url": _build_dfir_auto_stream_url(
                stream_params=stream_params,
                decision_id=str(decision.get("decision_id") or ""),
                decision_resolution="launch_now",
                alert=alert,
            ),
        }
    ), 200


@forensics_bp.route("/api/dfir/orchestrator/auto/decision", methods=["POST"])
def api_dfir_orchestrator_auto_decision():
    data = request.get_json(force=True, silent=True) or {}
    decision_id = str(data.get("decision_id") or "").strip()
    action = str(data.get("action") or "").strip()
    operator = str(data.get("operator_hint") or "index_dfir_auto").strip() or "index_dfir_auto"
    if not decision_id:
        return jsonify({"error": "decision_id_required"}), 400
    decision = _read_json_file(_decision_path(decision_id))
    if not decision:
        return jsonify({"error": "decision_not_found"}), 404
    if str(decision.get("status") or "") != "pending_user_choice":
        return jsonify({"error": "decision_not_pending", "decision": decision}), 409

    previous_case = ((decision.get("context") or {}).get("previous_case") or {})
    alert = decision.get("alert") or {}
    stream_params = decision.get("stream_params") or {}

    if action == "keep_previous_case_only":
        decision["status"] = "user_kept_previous_case_only"
        decision["operator"] = operator
        decision["resolution"] = action
        decision["message"] = (
            f"The operator kept the existing case {previous_case.get('case_id') or 'not_available'} and explicitly suppressed new case creation."
        )
        decision = _write_dfir_auto_decision(decision)
        return jsonify({"status": "suppressed", "decision": decision, "message": decision["message"]}), 200

    if action == "replace_previous_case":
        deleted = _delete_existing_case_for_dfir(str(previous_case.get("case_dir") or ""))
        if not deleted.get("deleted"):
            decision["status"] = "blocked_previous_case_replacement"
            decision["operator"] = operator
            decision["resolution"] = action
            decision["message"] = (
                f"DFIR AUTO could not replace the previous case because deletion failed: {deleted.get('reason') or 'unknown'}."
            )
            decision["replace_previous_case_result"] = deleted
            decision = _write_dfir_auto_decision(decision)
            return jsonify({"status": "blocked", "decision": decision, "message": decision["message"]}), 409
        decision["replace_previous_case_result"] = deleted
        resolution = "replace_previous_case"
    elif action == "coexist_with_previous_case":
        resolution = "coexist_with_previous_case"
    else:
        return jsonify({"error": "invalid_action"}), 400

    decision["status"] = "approved_by_operator"
    decision["operator"] = operator
    decision["resolution"] = resolution
    decision["message"] = (
        "The operator approved a new DFIR AUTO case outside scientific repetition mode."
    )
    decision = _write_dfir_auto_decision(decision)
    return jsonify(
        {
            "status": "approved",
            "decision": decision,
            "stream_url": _build_dfir_auto_stream_url(
                stream_params=stream_params,
                decision_id=decision_id,
                decision_resolution=resolution,
                alert=alert,
            ),
            "message": decision["message"],
        }
    ), 200







@forensics_bp.route("/api/dfir/orchestrator/auto/stream", methods=["GET"])
def api_dfir_orchestrator_auto_stream():
    run_id = (request.args.get("run_id") or "R1").strip() or "R1"

    try:
        traffic_seconds = int(request.args.get("traffic_seconds") or 20)
    except Exception:
        traffic_seconds = 20

    mem_mode = (request.args.get("mem_mode") or "build").strip() or "build"
    container_name = (request.args.get("container_name") or "nova_libvirt").strip() or "nova_libvirt"
    alert_ts_utc = (request.args.get("alert_ts_utc") or "").strip()
    decision_id = (request.args.get("decision_id") or "").strip()
    decision_resolution = (request.args.get("decision_resolution") or "").strip()
    alert_meta = _sanitize_dfir_alert_payload(
        {
            "severity": request.args.get("alert_severity"),
            "score": request.args.get("alert_score"),
            "signature": request.args.get("alert_signature"),
            "src": request.args.get("alert_src"),
            "dst": request.args.get("alert_dst"),
            "kind": request.args.get("alert_kind"),
            "forensics": request.args.get("forensics"),
        }
    )

    ssh_key = _resolve_ssh_key_path(request.args.get("ssh_key", ""))
    if not ssh_key:
        ssh_key = _detect_ssh_key_path()

    if not ssh_key:
        return jsonify({
            "error": "ssh_key requerido. Define SSH_KEY o NICS_DFIR_SSH_KEY o pasa ?ssh_key=...",
            "searched": [
                "query: ssh_key",
                "env: NICS_DFIR_SSH_KEY",
                "env: SSH_KEY",
                "~/.ssh/my_key",
                "~/.ssh/id_rsa",
                "~/.ssh/id_ed25519"
            ]
        }), 400

    acquired = DFIR_ORCH_LOCK.acquire(blocking=False)
    if not acquired:
        return jsonify({"error": "DFIR orchestration already running"}), 409

    # CLAVE: capturar el app real antes de entrar al generator (SSE)
    app = current_app._get_current_object()

    def sse():
        def emit(line: str):
            return f"data: {(line or '').rstrip(chr(10))}\n\n"

        start_ts = time.time()
        case_dir = None
        preservation_released = False

        try:
            # CLAVE: mantener contexto de app durante el streaming
            with app.app_context():
                yield emit("[SISTEMA] DFIR AUTO started. Lock acquired.")
                yield emit(f"[SISTEMA] ssh_key resolved: {ssh_key}")

                # 1) Resolver targets antes de crear el caso para no dejar
                # casos abortados vacios si OpenStack falla.
                try:
                    targets = _resolve_dfir_targets_from_openstack(["fuxa", "plc", "victim"])
                except Exception as exc:
                    yield emit(f"[ERROR] target resolution failed: {exc}")
                    payload = {"result": "error", "exit_code": 10, "case_dir": None, "reason": "target_resolution_failed", "details": str(exc)}
                    yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                    return
                targets_ok = [t for t in (targets or []) if (t.get("vm_id") and t.get("vm_ip"))]
                if not targets_ok:
                    yield emit("[ERROR] No targets resolvable: fuxa plc victim")
                    payload = {"result": "error", "exit_code": 1, "case_dir": None, "reason": "no_targets"}
                    yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                    return

                # 2) Crear CASE aqui
                try:
                    case_dir = _dfir_create_case_internal(run_id=run_id, source="dfir_auto_orchestrator")
                except RuntimeError as exc:
                    reason = str(exc)
                    yield emit(f"[BLOCKED] {reason}")
                    payload = {"result": "error", "exit_code": 8, "case_dir": None, "reason": "active_preservation_in_progress", "details": reason}
                    yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                    return
                yield emit(f"[SISTEMA] Case created: {case_dir}")
                if decision_id:
                    _append_case_event(
                        case_dir,
                        "dfir_auto_decision_applied",
                        run_id=run_id,
                        meta={
                            "decision_id": decision_id,
                            "decision_resolution": decision_resolution or None,
                            "alert": alert_meta,
                        },
                    )
                    _append_custody_entry(
                        case_dir,
                        "dfir_auto_decision_applied",
                        "forensics_api",
                        run_id=run_id,
                        details={
                            "decision_id": decision_id,
                            "decision_resolution": decision_resolution or None,
                            "alert_severity": alert_meta.get("severity"),
                            "alert_signature": alert_meta.get("signature"),
                        },
                    )
                    _register_custody_artifact(case_dir)
                    _write_case_digest(case_dir, run_id=run_id)

                # 3) Anclar alert timestamp dentro del CASE
                alert_ts = _get_or_set_alert_ts(case_dir, run_id=run_id, provided_alert_ts_utc=alert_ts_utc)
                yield emit(f"[SISTEMA] Alert anchor ts_utc={alert_ts}")

                yield emit("[SISTEMA] Targets:")
                for t in targets_ok:
                    yield emit(f"  - {t['role']} vm_id={t['vm_id']} ip={t['vm_ip']}")

                _append_case_event(case_dir, "dfir_orchestration_start", run_id=run_id, meta={
                    "targets": [{"role": t["role"], "vm_id": t["vm_id"], "vm_ip": t["vm_ip"]} for t in targets_ok],
                    "traffic_seconds": traffic_seconds,
                    "memory_mode": mem_mode,
                    "disk_container": container_name,
                })
                initialize_volatile_first_acquisition(
                    case_dir,
                    run_id=run_id,
                    case_created_utc=_utc_now_iso(),
                    acquisition_started_utc=_utc_now_iso(),
                    trigger_time_utc=alert_ts,
                    pre_context_seconds=max(int(traffic_seconds or 0), 120),
                    post_context_seconds=max(int(traffic_seconds or 0), 120),
                )

                # 4) MEMORY (POST interno) + DEBUG COMPLETO (sin eliminar nada)
                update_acquisition_profile(case_dir, run_id=run_id, merge_fields={"memory_started_utc": _utc_now_iso()})
                for t in targets_ok:
                    vm_id = t["vm_id"]
                    vm_ip = t["vm_ip"]
                    role = t["role"]
                    resolved_node = resolve_node_for_remote_ops(instance_id=vm_id, vm_ip=vm_ip)
                    ssh_user = str((resolved_node or {}).get("ssh_user") or "").strip() or _dfir_ssh_user_for_role(role)

                    yield emit(f"[STEP] memory start role={role} ip={vm_ip} user={ssh_user} mode={mem_mode}")
                    payload_mem = {
                        "case_dir": case_dir,
                        "vm_id": vm_id,
                        "vm_ip": vm_ip,
                        "ssh_user": ssh_user,
                        "ssh_key": ssh_key,
                        "mode": mem_mode,
                        "run_id": run_id,
                        "alert_ts_utc": alert_ts
                    }

                    with app.test_request_context(
                        "/api/forensics/acquire/memory_lime",
                        method="POST",
                        json=payload_mem
                    ):
                        resp = api_forensics_acquire_memory()

                    if isinstance(resp, tuple):
                        body, code = resp
                    else:
                        body, code = resp, 200

                    # Intentar leer JSON siempre
                    j = None
                    raw_body = ""
                    try:
                        j = body.get_json(silent=True)
                    except Exception:
                        j = None
                    try:
                        raw_body = body.get_data(as_text=True) if hasattr(body, "get_data") else ""
                    except Exception:
                        raw_body = ""

                    if code != 200:
                        # Mostrar error real
                        err_msg = ""
                        try:
                            err_msg = (j or {}).get("error") or (j or {}).get("msg") or ""
                        except Exception:
                            err_msg = ""

                        yield emit(f"[ERROR] memory failed role={role} http_code={code}")
                        if err_msg:
                            yield emit(f"[ERROR] reason={err_msg}")

                        # stdout/stderr si existen
                        try:
                            if (j or {}).get("stderr"):
                                yield emit("[ERROR] --- stderr (memory) ---")
                                for ln in str(j["stderr"]).splitlines()[-60:]:
                                    yield emit(ln)
                            if (j or {}).get("stdout"):
                                yield emit("[INFO] --- stdout (memory) ---")
                                for ln in str(j["stdout"]).splitlines()[-60:]:
                                    yield emit(ln)
                        except Exception:
                            pass

                        # fallback a raw body si no hay JSON
                        if raw_body and not j:
                            yield emit("[ERROR] --- raw body ---")
                            for ln in raw_body.splitlines()[-60:]:
                                yield emit(ln)

                        payload = {
                            "result": "error",
                            "exit_code": 2,
                            "case_dir": case_dir,
                            "reason": "memory_failed",
                            "role": role,
                            "http_code": code,
                            "details": j or {"raw": raw_body[:4000]}
                        }
                        yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                        return

                    update_acquisition_profile(case_dir, run_id=run_id, merge_fields={"memory_completed_utc": _utc_now_iso()})
                    yield emit(f"[STEP] memory done role={role} mem_dump={(j or {}).get('mem_dump')}")

                # 5) NETWORK CONTEXT IMPORT
                yield emit("[STEP] network_context_import start source=full_scenario_captures")
                try:
                    network_result = import_continuous_network_context(
                        case_dir,
                        run_id=run_id,
                        trigger_time_utc=alert_ts,
                        pre_context_seconds=max(int(traffic_seconds or 0), 120),
                        post_context_seconds=max(int(traffic_seconds or 0), 120),
                    )
                    yield emit(f"[STEP] network_context_import done preserved={network_result.get('preserved_segments')} pending={network_result.get('pending_segments')}")
                except Exception as exc:
                    yield emit(f"[ERROR] network_context_import failed reason={exc}")
                    payload = {"result": "error", "exit_code": 3, "case_dir": case_dir, "reason": "network_context_import_failed", "details": str(exc)}
                    yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                    return

                # 6) DISK (POST interno)
                update_acquisition_profile(case_dir, run_id=run_id, merge_fields={"disk_started_utc": _utc_now_iso()})
                for t in targets_ok:
                    vm_id = t["vm_id"]
                    role = t["role"]

                    yield emit(f"[STEP] disk start role={role} container={container_name}")
                    payload_disk = {
                        "case_dir": case_dir,
                        "vm_id": vm_id,
                        "container_name": container_name,
                        "run_id": run_id,
                        "alert_ts_utc": alert_ts,
                        "noninteractive": True,
                    }

                    with app.test_request_context(
                        "/api/forensics/acquire/disk_kolla",
                        method="POST",
                        json=payload_disk
                    ):
                        resp = api_forensics_acquire_disk()

                    if isinstance(resp, tuple):
                        body, code = resp
                    else:
                        body, code = resp, 200

                    if code != 200:
                        yield emit(f"[ERROR] disk failed role={role} http_code={code}")

                        j = None
                        raw_body = ""
                        try:
                            j = body.get_json(silent=True)
                        except Exception:
                            j = None
                        try:
                            raw_body = body.get_data(as_text=True) if hasattr(body, "get_data") else ""
                        except Exception:
                            raw_body = ""

                        err_msg = ""
                        try:
                            err_msg = (j or {}).get("error") or (j or {}).get("msg") or ""
                        except Exception:
                            err_msg = ""

                        if err_msg:
                            yield emit(f"[ERROR] reason={err_msg}")

                        try:
                            if (j or {}).get("stderr"):
                                yield emit("[ERROR] --- stderr (disk) ---")
                                for ln in str(j["stderr"]).splitlines()[-60:]:
                                    yield emit(ln)
                            if (j or {}).get("stdout"):
                                yield emit("[INFO] --- stdout (disk) ---")
                                for ln in str(j["stdout"]).splitlines()[-60:]:
                                    yield emit(ln)
                        except Exception:
                            pass

                        if raw_body and not j:
                            yield emit("[ERROR] --- raw body ---")
                            for ln in raw_body.splitlines()[-60:]:
                                yield emit(ln)

                        payload = {
                            "result": "error",
                            "exit_code": 4,
                            "case_dir": case_dir,
                            "reason": "disk_failed",
                            "role": role,
                            "http_code": code,
                            "details": j or {"raw": raw_body[:4000]}
                        }
                        yield f"event: done\ndata: {json.dumps(payload)}\n\n"
                        return

                    j = {}
                    try:
                        j = body.get_json(silent=True) or {}
                    except Exception:
                        j = {}

                    yield emit(f"[STEP] disk done role={role} disk_raw={(j or {}).get('disk_raw')}")

                _append_case_event(case_dir, "dfir_orchestration_done", run_id=run_id, meta={"targets_count": len(targets_ok)})
                _append_custody_entry(case_dir, "dfir_orchestration_done", "forensics_api", run_id=run_id, details={"targets_count": len(targets_ok)})
                _register_custody_artifact(case_dir)
                _write_case_digest(case_dir, run_id=run_id)
                _clear_active_preservation_state(case_dir, run_id=run_id, final_state="completed", reason="dfir_orchestration_done")
                preservation_released = True

                elapsed = round(time.time() - start_ts, 3)
                yield emit(f"[SISTEMA] DFIR AUTO finished ok elapsed_s={elapsed}")

                payload = {"result": "ok", "exit_code": 0, "case_dir": case_dir, "run_id": run_id, "elapsed_s": elapsed}
                yield f"event: done\ndata: {json.dumps(payload)}\n\n"

        except Exception as e:
            yield emit(f"[ERROR] DFIR AUTO exception: {e}")
            payload = {"result": "error", "exit_code": 9, "case_dir": case_dir, "reason": str(e)}
            yield f"event: done\ndata: {json.dumps(payload)}\n\n"

        finally:
            if case_dir and not preservation_released:
                try:
                    _clear_active_preservation_state(case_dir, run_id=run_id, final_state="aborted", reason="dfir_auto_orchestrator_terminated_before_completion")
                except Exception:
                    pass
            try:
                DFIR_ORCH_LOCK.release()
            except Exception:
                pass

    return Response(
        sse(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )
