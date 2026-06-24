from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .comparability_service import compare_executions
from .config import (
    CAMPAIGNS_ROOT,
    CAMPAIGN_STATES,
    LEVELS,
    campaign_config_path,
    campaign_dir,
    campaign_manifest_path,
    campaign_methodological_basis_path,
    rel,
)
from .execution_service import aggregate_campaign_state, create_execution_from_campaign
from .job_runner import append_phase, get_job, list_jobs, new_job, start_job, update_job
from .methodological_basis import load_methodological_basis
from ..foc_reconstruction.evidence_lifecycle_dashboard import load_evidence_lifecycle_dashboard
from ..foc_reconstruction.foc_sources import utc_now


def _json_load(path: Path):
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _safe_slug(value: str) -> str:
    out = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "value"))
    return re.sub(r"_+", "_", out).strip("_") or "value"


def _new_campaign_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"CMP-{ts}-{uuid.uuid4().hex[:4].upper()}"


def _execution_summaries(campaign_id: str) -> list[dict]:
    root = campaign_dir(campaign_id)
    out: list[dict] = []
    if not root.is_dir():
        return out
    for level_dir in sorted(root.glob("level_*")):
        for manifest_path in sorted(level_dir.glob("EXEC-*/execution_manifest.json")):
            payload = _json_load(manifest_path) or {}
            out.append(
                {
                    "execution_id": payload.get("execution_id"),
                    "level": payload.get("level"),
                    "status": payload.get("status"),
                    "source_case_id": payload.get("source_case_id"),
                    "execution_path": rel(manifest_path.parent),
                    "updated_at": payload.get("updated_at"),
                }
            )
    return out


def _latest_job_summary(campaign_id: str) -> dict | None:
    jobs_dir = campaign_dir(campaign_id) / "jobs"
    if not jobs_dir.is_dir():
        return None
    latest_path = None
    latest_ts = 0.0
    for item in jobs_dir.glob("*.json"):
        try:
            ts = item.stat().st_mtime
        except Exception:
            continue
        if ts > latest_ts:
            latest_ts = ts
            latest_path = item
    if latest_path is None:
        return None
    payload = _json_load(latest_path) or {}
    return {
        "job_id": payload.get("job_id"),
        "status": payload.get("status"),
        "started_at": payload.get("started_at") or payload.get("requested_at"),
        "finished_at": payload.get("finished_at"),
        "current_phase": payload.get("current_phase"),
        "current_phase_label": payload.get("current_phase_label"),
        "current_phase_detail": payload.get("current_phase_detail"),
        "progress_percent": payload.get("progress_percent"),
        "last_error": ((payload.get("errors") or [{}])[0] or {}).get("message") if payload.get("errors") else None,
        "job_path": rel(latest_path),
    }


def _running_job_for_campaign(campaign_id: str) -> dict | None:
    for item in list_jobs():
        meta = item.get("meta") or {}
        if str(meta.get("campaign_id")) != str(campaign_id):
            continue
        if str(item.get("status")) in {"queued", "running"}:
            return item
    return None


def list_campaigns() -> dict:
    CAMPAIGNS_ROOT.mkdir(parents=True, exist_ok=True)
    campaigns: list[dict] = []
    for item in sorted(CAMPAIGNS_ROOT.glob("CMP-*")):
        manifest = _json_load(item / "campaign_manifest.json")
        if not isinstance(manifest, dict):
            continue
        try:
            manifest = aggregate_campaign_state(str(manifest.get("campaign_id")), manifest)
        except Exception:
            pass
        manifest["executions"] = _execution_summaries(str(manifest.get("campaign_id")))
        campaigns.append(manifest)
    return {"generated_at": utc_now(), "campaigns": campaigns}


def create_campaign(payload: dict) -> dict:
    level = str(payload.get("level") or "A").strip().upper()
    if level not in LEVELS:
        raise ValueError("invalid_level")
    campaign_id = _new_campaign_id()
    root = campaign_dir(campaign_id)
    for name in ["jobs", "logs", "comparisons", "level_A", "level_B", "level_C"]:
        (root / name).mkdir(parents=True, exist_ok=True)

    manifest = {
        "campaign_id": campaign_id,
        "name": str(payload.get("name") or campaign_id),
        "description": str(payload.get("description") or ""),
        "level": level,
        "status": "not_started",
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "execution_count": 0,
        "current_execution_id": None,
        "scenario_id": payload.get("scenario_id") or "not_available",
        "source_mode": "linked_existing_case" if (payload.get("base_case_id") or payload.get("run_case_id") or payload.get("base_case_path") or payload.get("run_case_path")) else "planned_campaign",
        "campaign_path": rel(root),
        "comparisons_path": rel(root / "comparisons"),
    }
    config = {
        "campaign_id": campaign_id,
        "level": level,
        "name": manifest["name"],
        "description": manifest["description"],
        "scenario_id": manifest["scenario_id"],
        "base_case_id": payload.get("base_case_id"),
        "base_case_path": payload.get("base_case_path"),
        "run_case_id": payload.get("run_case_id"),
        "run_case_path": payload.get("run_case_path"),
        "baseline_noise_threshold": float(payload.get("baseline_noise_threshold") or 0.15),
        "baseline_window_seconds": int(payload.get("baseline_window_seconds") or 60),
        "delta_wcpr_allowed": float(payload.get("delta_wcpr_allowed") or 0.10),
        "notes": payload.get("notes") or "",
    }
    _write_json(campaign_manifest_path(campaign_id), manifest)
    _write_json(campaign_config_path(campaign_id), config)
    _write_json(campaign_methodological_basis_path(campaign_id), load_methodological_basis())
    return {"campaign": manifest, "config": config}


def get_campaign(campaign_id: str) -> dict | None:
    manifest = _json_load(campaign_manifest_path(campaign_id))
    if not isinstance(manifest, dict):
        return None
    try:
        manifest = aggregate_campaign_state(campaign_id, manifest)
    except Exception:
        pass
    config = _json_load(campaign_config_path(campaign_id)) or {}
    basis = _json_load(campaign_methodological_basis_path(campaign_id)) or {}
    return {
        "campaign": manifest,
        "config": config,
        "methodological_basis": basis,
        "executions": _execution_summaries(campaign_id),
        "latest_job": _latest_job_summary(campaign_id),
        "running_job": _running_job_for_campaign(campaign_id),
    }


def build_campaign_proposal(case_id: str | None = None, level: str | None = None, scenario_id: str | None = None) -> dict:
    normalized_level = str(level or ("A" if case_id else "B")).strip().upper()
    if normalized_level not in LEVELS:
        normalized_level = "A"
    source_summary = None
    resolved_scenario_id = str(scenario_id or "").strip() or "not_available"
    resolved_scenario_name = "not_available"
    source_case_policy = "read_only" if normalized_level == "A" else "new_execution"
    if case_id:
        dashboard = load_evidence_lifecycle_dashboard(case_id)
        summary = (dashboard or {}).get("summary") or {}
        source_summary = {
            "case_id": case_id,
            "case_path": dashboard.get("case_path"),
            "summary_available": bool(dashboard.get("summary_available")),
        }
        resolved_scenario_id = (
            summary.get("scenario_id")
            or ((summary.get("causal_summary") or {}).get("scenario_id"))
            or resolved_scenario_id
        )
        resolved_scenario_name = summary.get("scenario_name") or "not_available"
    default_name = {
        "A": f"Level A Reanalysis — {case_id or 'linked_case'}",
        "B": f"Level B T0831 Repetition — {resolved_scenario_id}",
        "C": f"Level C Full Redeployment — {resolved_scenario_name if resolved_scenario_name != 'not_available' else resolved_scenario_id}",
    }.get(normalized_level, f"Level {normalized_level} Campaign")
    return {
        "guided_mode_default": True,
        "default_level": normalized_level,
        "source_mode": {
            "A": "linked_existing_case",
            "B": "new_incident_execution",
            "C": "full_redeployment",
        }.get(normalized_level, "linked_existing_case"),
        "campaign_name": default_name,
        "scenario_id": resolved_scenario_id,
        "scenario_name": resolved_scenario_name,
        "linked_source_case": case_id or "",
        "baseline_threshold": 0.15,
        "delta_wcpr_allowed": 0.10,
        "baseline_window_seconds": 60,
        "number_of_repetitions": {"A": 3, "B": 3, "C": 1}.get(normalized_level, 3),
        "methodological_notes": "Controlled repetition campaign for evaluating forensic reconstruction comparability under documented experimental conditions.",
        "ground_truth_seal_mode": "reuse_if_available" if normalized_level == "A" else "generate_before_attack",
        "comparison_profile_after_each_run": True,
        "source_case_policy": source_case_policy,
        "source_summary": source_summary,
        "level_explanation": {
            "A": {
                "title": "Level A — Reanalysis Repeatability",
                "meaning": "Reuses an existing preserved forensic case and repeats the analysis and reconstruction logic over the same preserved evidence.",
                "does_not_do": [
                    "It does not redeploy the scenario.",
                    "It does not execute a new attack.",
                    "It does not perform new acquisition.",
                    "It does not modify the original case."
                ],
                "used_for": "Testing whether the analytical pipeline is repeatable over the same preserved evidence.",
                "required_input": "A linked source case.",
                "auto_generated": [
                    "execution workspace",
                    "execution_manifest.json",
                    "reanalysis profiles",
                    "forensic_comparison_profile.json"
                ],
            },
            "B": {
                "title": "Level B — Controlled Repeated Incident Execution",
                "meaning": "Uses the same deployed scenario and executes controlled repetitions under equivalent and documented conditions.",
                "used_for": "Measuring stability of forensic reconstruction under equivalent experimental conditions.",
                "required_input": "scenario, attack profile, acquisition profile",
                "auto_generated": [
                    "execution workspace",
                    "ground_truth_seal.json",
                    "baseline_noise_profile.json",
                    "detection_trigger_profile.json",
                    "acquisition_profile.json",
                    "preservation_profile.json",
                    "forensic_comparison_profile.json"
                ],
            },
            "C": {
                "title": "Level C — Full Environment Redeployment Reproducibility",
                "meaning": "Redeploys the environment and repeats the experiment from infrastructure setup to forensic reconstruction.",
                "used_for": "Complementary platform-level reproducibility validation.",
                "important": "This level is not the main forensic comparability metric because it introduces additional deployment and configuration variability.",
                "auto_generated": [
                    "deployment manifest",
                    "infrastructure fingerprint",
                    "tool installation validation",
                    "sensor and SIEM/IDS configuration validation"
                ],
            },
        }.get(normalized_level),
    }


def campaign_preflight(payload: dict) -> dict:
    level = str(payload.get("level") or "A").strip().upper()
    case_id = str(payload.get("base_case_id") or payload.get("run_case_id") or "").strip()
    scenario_id = str(payload.get("scenario_id") or "").strip()
    items = []

    def add_item(key: str, ok: bool, why: str, fix: str, auto_generable: bool):
        items.append(
            {
                "requirement": key,
                "status": "ok" if ok else "missing",
                "why_it_matters": why,
                "how_to_fix": fix,
                "can_be_auto_generated": auto_generable,
            }
        )

    if level == "A":
        dashboard = load_evidence_lifecycle_dashboard(case_id) if case_id else {"error": "missing_case_id"}
        add_item("linked source case selected", bool(case_id), "Level A requires a preserved case to reanalyze.", "Select a preserved case or open the manager from the Scientific Lifecycle dashboard.", False)
        add_item("base case path exists", bool(case_id and dashboard.get("case_path")), "The execution workspace must link a real preserved case.", "Choose a valid preserved case.", False)
        add_item("base artifacts are readable", bool(case_id and dashboard.get("summary_available")), "The campaign needs readable preserved artifacts and executive summary context.", "Regenerate the case executive summary if needed.", True)
        add_item("analysis artifacts exist or can be regenerated", bool(case_id), "Comparison profiles depend on analysis and derived outputs.", "Use the linked case and regenerate missing analysis outputs if required.", True)
        add_item("output campaign directory can be created", True, "The module needs an isolated campaign workspace.", "Check filesystem permissions if campaign creation fails.", True)
    elif level == "B":
        add_item("scenario selected", bool(scenario_id and scenario_id != "not_available"), "Level B needs a declared scenario context.", "Provide a scenario ID or select a scenario-linked source.", False)
        add_item("attack profile selected", True, "Repeated incident executions require an explicit attack profile.", "Override the attack profile in Advanced Mode if needed.", True)
        add_item("automated attack script available", True, "Controlled repetition depends on an executable attack path.", "Ensure the attack profile can be resolved before running heavy executions.", True)
        add_item("acquisition profile selected", True, "The repeated run must preserve evidence in a comparable way.", "Override acquisition defaults in Advanced Mode if required.", True)
        add_item("time sync check available", True, "Temporal interpretation depends on measurable synchronization.", "Run time synchronization validation before heavy execution.", True)
        add_item("baseline noise capture available", True, "Level B comparability uses baseline noise as a warning boundary.", "Keep baseline capture enabled.", True)
        add_item("output campaign directory can be created", True, "The module needs an isolated campaign workspace.", "Check filesystem permissions if campaign creation fails.", True)
    else:
        add_item("deployment profile selected", False, "Level C needs a deployment and environment validation profile.", "Provide deployment-aware configuration before running Level C.", False)
        add_item("scenario deployment available", bool(scenario_id and scenario_id != "not_available"), "Level C requires a deployable scenario context.", "Provide a scenario ID and deployment profile.", False)
        add_item("tool installation validation available", True, "Level C comparability depends on environment validation reports.", "Use validation placeholders or future deployment-aware execution.", True)
        add_item("IDS/SIEM configuration profile available", True, "Sensor configuration changes affect reproducibility interpretation.", "Generate configuration validation reports for Level C runs.", True)
        add_item("attack profile selected", True, "The repeated incident must still be explicitly defined.", "Override attack profile in Advanced Mode if needed.", True)
        add_item("acquisition profile selected", True, "The environment-level repetition still needs forensic acquisition logic.", "Override acquisition profile in Advanced Mode if needed.", True)
        add_item("output campaign directory can be created", True, "The module needs an isolated campaign workspace.", "Check filesystem permissions if campaign creation fails.", True)

    ok_count = len([item for item in items if item["status"] == "ok"])
    return {
        "level": level,
        "items": items,
        "ready": ok_count == len(items),
        "ok_count": ok_count,
        "missing_count": len(items) - ok_count,
    }


def update_campaign_state(campaign_id: str, state: str) -> dict:
    if state not in CAMPAIGN_STATES:
        raise ValueError("invalid_campaign_state")
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    manifest["status"] = state
    manifest["updated_at"] = utc_now()
    _write_json(campaign_manifest_path(campaign_id), manifest)
    return manifest


def start_campaign_job(campaign_id: str, overrides: dict | None = None) -> dict:
    overrides = overrides or {}
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    running = _running_job_for_campaign(campaign_id)
    if running:
        return running
    job = new_job(
        job_type="campaign_run_next",
        title=f"Run next execution for {campaign_id}",
        job_path=campaign_dir(campaign_id) / "jobs" / f"job-{uuid.uuid4().hex[:8]}.json",
        meta={"campaign_id": campaign_id, "level": manifest.get("level")},
    )

    def runner(job_id: str, job_path: Path):
        append_phase(job_id, job_path, phase_key="campaign_start", phase_label="Start campaign execution", status="running", progress_percent=4.0, detail="Launching the next execution inside the selected campaign.")
        progress_hook = lambda key, label, percent, detail=None: append_phase(
            job_id,
            job_path,
            phase_key=key,
            phase_label=label,
            status="running",
            progress_percent=percent,
            detail=detail,
        )
        result = create_execution_from_campaign(campaign_id, overrides={**overrides, "_progress_hook": progress_hook})
        append_phase(job_id, job_path, phase_key="finalize", phase_label="Finalize execution job", status="completed", progress_percent=100.0, detail="Execution workspace and derived scientific profiles were registered.")
        update_job(
            job_id,
            job_path,
            current_phase="completed",
            current_phase_label="Completed",
            current_phase_detail="Execution workspace and derived scientific profiles were registered.",
            progress_percent=100.0,
            status="completed" if result.get("status") == "completed" else "completed_with_degradation",
            finished_at=utc_now(),
            generated_artifacts=list((result.get("artifacts") or {}).values()),
            meta={**(job.get("meta") or {}), **result},
        )

    return start_job(job, runner)


def start_campaign(campaign_id: str, overrides: dict | None = None) -> dict:
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")
    manifest["status"] = "running"
    manifest["updated_at"] = utc_now()
    _write_json(campaign_manifest_path(campaign_id), manifest)
    job = start_campaign_job(campaign_id, overrides=overrides)
    return {"campaign": manifest, "job": job}


def start_comparison_job(campaign_id: str | None, execution_ids: list[str], delta_wcpr_allowed: float | None = None) -> dict:
    target_root = campaign_dir(campaign_id) if campaign_id else campaign_dir("_cross_campaign")
    target_root.mkdir(parents=True, exist_ok=True)
    job = new_job(
        job_type="comparability_compare",
        title="Compare registered executions",
        job_path=target_root / "jobs" / f"job-{uuid.uuid4().hex[:8]}.json",
        meta={"campaign_id": campaign_id, "execution_ids": execution_ids},
    )

    def runner(job_id: str, job_path: Path):
        update_job(job_id, job_path, current_phase="load_profiles", progress_percent=20.0)
        result = compare_executions(execution_ids, campaign_id=campaign_id, delta_wcpr_allowed=delta_wcpr_allowed)
        final_status = "failed" if result.get("status") == "Insufficient Data" else "completed"
        update_job(
            job_id,
            job_path,
            current_phase="completed",
            progress_percent=100.0,
            status=final_status,
            finished_at=utc_now(),
            generated_artifacts=list((result.get("artifacts") or {}).values()),
            meta={**(job.get("meta") or {}), **result},
        )

    return start_job(job, runner)
