from __future__ import annotations

import json
from pathlib import Path

from .baseline_noise import build_baseline_noise_profile
from .config import (
    CAMPAIGNS_ROOT,
    LEVEL_A_NOT_APPLICABLE,
    STAGE_KEYS,
    campaign_config_path,
    campaign_dir,
    campaign_level_dir,
    campaign_manifest_path,
    execution_dir,
    rel,
)
from .ground_truth_seal import build_ground_truth_seal
from .profile_builder import build_execution_profiles, load_case_bundle
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


def _load_campaign(campaign_id: str) -> tuple[dict, dict]:
    manifest = _json_load(campaign_manifest_path(campaign_id)) or {}
    config = _json_load(campaign_config_path(campaign_id)) or {}
    return manifest, config


def _execution_index(campaign_id: str, level: str) -> int:
    root = campaign_dir(campaign_id) / campaign_level_dir(level)
    count = 0
    if root.is_dir():
        for item in root.iterdir():
            if item.is_dir() and item.name.startswith("EXEC-"):
                count += 1
    return count + 1


def _execution_manifest_paths(campaign_id: str):
    root = campaign_dir(campaign_id)
    if not root.is_dir():
        return []
    return sorted(root.glob("level_*/EXEC-*/execution_manifest.json"))


def _execution_technical_failures(payload: dict, manifest_path: Path) -> list[str]:
    failures: list[str] = []
    execution_id = str(payload.get("execution_id") or manifest_path.parent.name or "unknown_execution")
    status = str(payload.get("status") or "").lower()
    artifacts = payload.get("artifacts") or {}
    stage_statuses = payload.get("stage_statuses") or {}
    if status in {"failed", "cancelled"}:
        failures.append(f"{execution_id}: execution status is {status}")
    if status in {"completed", "completed_with_degradation"} and not artifacts.get("forensic_comparison_profile"):
        failures.append(f"{execution_id}: missing_required_profile forensic_comparison_profile.json")
    for stage_key, record in stage_statuses.items():
        if str((record or {}).get("status") or "").lower() == "failed":
            failures.append(f"{execution_id}: failed stage {stage_key}")
    return failures


def _execution_scientific_limitations(payload: dict, manifest_path: Path) -> list[str]:
    limitations: list[str] = []
    execution_id = str(payload.get("execution_id") or manifest_path.parent.name or "unknown_execution")
    status = str(payload.get("status") or "").lower()
    if status == "completed_with_degradation":
        limitations.append(f"{execution_id}: execution completed with scientific degradation")
    for stage_key, record in (payload.get("stage_statuses") or {}).items():
        record = record or {}
        stage_status = str(record.get("status") or "").lower()
        reason = str(record.get("reason") or "").strip()
        if stage_status == "completed_with_degradation":
            limitations.append(f"{execution_id}: {stage_key} -> {reason or 'scientific limitation recorded'}")
        elif stage_status == "not_applicable" and stage_key == "ground_truth_sealed":
            limitations.append(f"{execution_id}: ground truth is reused rather than freshly sealed for this level")
    for warning in list(payload.get("warnings") or []):
        limitations.append(f"{execution_id}: {warning}")
    return limitations


def aggregate_campaign_state(campaign_id: str, manifest: dict | None = None) -> dict:
    manifest = dict(manifest or (_json_load(campaign_manifest_path(campaign_id)) or {}))
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")

    execution_paths = _execution_manifest_paths(campaign_id)
    technical_failures: list[str] = []
    scientific_limitations: list[str] = []
    statuses: list[str] = []
    comparable_profiles = 0

    for manifest_path in execution_paths:
        payload = _json_load(manifest_path)
        if not isinstance(payload, dict):
            technical_failures.append(f"{manifest_path.parent.name}: invalid_json execution_manifest.json")
            continue
        statuses.append(str(payload.get("status") or "unknown").lower())
        technical_failures.extend(_execution_technical_failures(payload, manifest_path))
        scientific_limitations.extend(_execution_scientific_limitations(payload, manifest_path))
        if (payload.get("artifacts") or {}).get("forensic_comparison_profile"):
            comparable_profiles += 1

    unique_technical_failures = list(dict.fromkeys(technical_failures))
    unique_scientific_limitations = list(dict.fromkeys(scientific_limitations))

    if not execution_paths:
        campaign_status = manifest.get("status") if manifest.get("status") in {"running", "paused", "stopped"} else "not_started"
        technical_outcome = "not_started"
        scientific_outcome = "not_started"
    elif unique_technical_failures:
        campaign_status = "completed_with_failures"
        technical_outcome = "completed_with_failures"
        scientific_outcome = "completed_with_degradation" if unique_scientific_limitations else "completed"
    elif any(status in {"partial", "queued", "running"} for status in statuses):
        campaign_status = "partial"
        technical_outcome = "partial"
        scientific_outcome = "completed_with_degradation" if unique_scientific_limitations else "partial"
    elif comparable_profiles == 0:
        campaign_status = "insufficient_data"
        technical_outcome = "completed"
        scientific_outcome = "insufficient_data"
    elif any(status == "completed_with_degradation" for status in statuses):
        campaign_status = "completed_with_degradation"
        technical_outcome = "completed"
        scientific_outcome = "completed_with_degradation"
    elif statuses and all(status == "completed" for status in statuses):
        campaign_status = "completed"
        technical_outcome = "completed"
        scientific_outcome = "completed"
    else:
        campaign_status = "partial"
        technical_outcome = "partial"
        scientific_outcome = "partial"

    comparison_readiness = "ready" if comparable_profiles >= 2 else ("partial" if comparable_profiles == 1 else "insufficient_data")
    manifest["execution_count"] = len(execution_paths)
    manifest["status"] = campaign_status
    manifest["technical_outcome"] = technical_outcome
    manifest["scientific_outcome"] = scientific_outcome
    manifest["comparison_readiness"] = comparison_readiness
    manifest["technical_failures"] = unique_technical_failures
    manifest["scientific_limitations"] = unique_scientific_limitations
    manifest["updated_at"] = utc_now()
    _write_json(campaign_manifest_path(campaign_id), manifest)
    return manifest


def _default_stage_record(status: str, note: str = "not started yet") -> dict:
    return {
        "status": status,
        "started_at": None,
        "finished_at": None,
        "duration_seconds": None,
        "reason": note,
        "artifact_path": None,
    }


def _initial_stage_statuses(level: str) -> dict:
    statuses = {}
    for key in STAGE_KEYS:
        if str(level).upper() == "A" and key in LEVEL_A_NOT_APPLICABLE:
            statuses[key] = _default_stage_record("not_applicable", "not applicable to Level A linked-case repeatability runs")
        else:
            statuses[key] = _default_stage_record("not_started")
    return statuses


def _mark_stage(stage_statuses: dict, key: str, status: str, reason: str, artifact_path: str | None = None) -> None:
    record = stage_statuses.get(key) or {}
    record.update(
        {
            "status": status,
            "reason": reason,
            "started_at": record.get("started_at") or utc_now(),
            "finished_at": utc_now(),
            "duration_seconds": 0.0,
            "artifact_path": artifact_path,
        }
    )
    stage_statuses[key] = record


def _derive_stage_statuses(level: str, case_bundle: dict | None, files: dict) -> dict:
    statuses = _initial_stage_statuses(level)
    if not case_bundle:
        return statuses
    summary = case_bundle.get("summary") or {}
    multilayer = summary.get("multilayer_analysis_summary") or {}
    causal = summary.get("causal_summary") or {}
    uncertainty = summary.get("uncertainty_summary") or {}
    final_conclusion = summary.get("final_forensic_conclusion") or {}

    _mark_stage(statuses, "scenario_prepared", "completed", "scenario context linked from source case", files.get("scenario_profile"))
    if level.upper() != "A":
        _mark_stage(statuses, "environment_deployed", "completed_with_degradation", "execution registered from a linked existing case; deployment was not replayed by foc_experimentation")
        _mark_stage(statuses, "tools_installed_or_validated", "completed_with_degradation", "tool state inferred from linked preserved run; no fresh deployment validation was performed")
    if level.upper() == "C":
        _mark_stage(statuses, "baseline_noise_captured", "completed_with_degradation", "baseline noise profile was derived from linked preserved outputs", files.get("baseline_noise_profile"))
    elif level.upper() == "B":
        _mark_stage(statuses, "baseline_noise_captured", "completed_with_degradation", "baseline profile was derived from linked run outputs rather than freshly sampled noise", files.get("baseline_noise_profile"))

    _mark_stage(statuses, "time_sync_validated", "completed", "time synchronization metadata is available from the linked case")
    _mark_stage(statuses, "ground_truth_sealed", "completed_with_degradation", "ground truth seal was reconstructed from preserved source artifacts", files.get("ground_truth_seal"))

    if level.upper() != "A":
        _mark_stage(statuses, "attack_executed", "completed_with_degradation", "attack execution was registered from a linked existing case rather than re-executed by foc_experimentation")
        _mark_stage(statuses, "detection_observed", "completed_with_degradation", "detection state was derived from the linked case")
        _mark_stage(statuses, "trigger_selected", "completed_with_degradation", "trigger state was derived from the linked case")
        _mark_stage(statuses, "acquisition_executed", "completed_with_degradation", "acquisition state was derived from the linked case")
        _mark_stage(statuses, "evidence_preserved", "completed_with_degradation", "preservation state was derived from the linked case")

    _mark_stage(statuses, "integrity_custody_checked", "completed", "integrity and custody artifacts were linked read-only from the source case")

    _mark_stage(
        statuses,
        "multilayer_analysis_completed",
        "completed" if str(multilayer.get("execution_status")) == "completed" else "completed_with_degradation",
        multilayer.get("main_limitation") or "multilayer analysis summary linked from source case",
    )
    _mark_stage(statuses, "timeline_generated", "completed" if (multilayer.get("timeline_entries") or 0) > 0 else "completed_with_degradation", "timeline summary linked from source case")
    _mark_stage(statuses, "cross_layer_findings_generated", "completed" if (multilayer.get("cross_layer_findings") or 0) > 0 else "completed_with_degradation", "cross-layer findings summary linked from source case")
    _mark_stage(statuses, "causal_reconstruction_generated", "completed" if causal.get("status") == "completed" else "completed_with_degradation", causal.get("main_limitation") or "causal reconstruction linked from source case")
    _mark_stage(statuses, "uncertainty_generated", "completed_with_degradation" if ((uncertainty.get("temporal") or {}).get("causal_temporal_ordering_confidence")) in {"limited", "ambiguous", "unknown"} else "completed", "uncertainty summary linked from source case")
    _mark_stage(statuses, "hypothesis_support_generated", "completed" if files.get("forensic_comparison_profile") else "failed", "hypothesis support summary linked from source case")
    _mark_stage(statuses, "executive_summary_generated", "completed", "executive evidence lifecycle summary linked from source case")
    _mark_stage(statuses, "comparison_profile_generated", "completed", "forensic comparison profile generated in campaign workspace", files.get("forensic_comparison_profile"))
    return statuses


def create_execution_from_campaign(campaign_id: str, overrides: dict | None = None) -> dict:
    overrides = overrides or {}
    manifest, config = _load_campaign(campaign_id)
    if not manifest:
        raise FileNotFoundError(f"campaign_not_found:{campaign_id}")

    level = str((overrides.get("level") or config.get("level") or manifest.get("level") or "A")).upper()
    index = _execution_index(campaign_id, level)
    execution_id = f"EXEC-{index:04d}"
    exec_dir = execution_dir(campaign_id, level, execution_id)
    exec_dir.mkdir(parents=True, exist_ok=True)

    source_case_id = overrides.get("source_case_id") or config.get("base_case_id") or config.get("run_case_id")
    source_case_path = overrides.get("source_case_path") or config.get("base_case_path") or config.get("run_case_path")
    progress_hook = overrides.get("_progress_hook")
    case_bundle = load_case_bundle(case_id=source_case_id, case_path=source_case_path) if (source_case_id or source_case_path) else None

    if callable(progress_hook):
        progress_hook("prepare_workspace", "Prepare execution workspace", 8.0, f"Creating isolated workspace for execution {execution_id}.")

    baseline_threshold = float(overrides.get("baseline_noise_threshold") or config.get("baseline_noise_threshold") or 0.15)
    baseline_window_seconds = int(overrides.get("baseline_window_seconds") or config.get("baseline_window_seconds") or 60)
    baseline_enabled = level in {"B", "C"}

    profile_result = build_execution_profiles(
        execution_id=execution_id,
        campaign_id=campaign_id,
        level=level,
        execution_dir=exec_dir,
        case_bundle=case_bundle,
        baseline_noise_enabled=baseline_enabled,
        baseline_window_seconds=baseline_window_seconds,
        baseline_threshold=baseline_threshold,
        baseline_builder=build_baseline_noise_profile,
        seal_builder=build_ground_truth_seal,
        progress_hook=progress_hook,
    )

    if callable(progress_hook):
        progress_hook("derive_stage_statuses", "Derive stage statuses", 92.0, "Calculating stage_statuses from the generated scientific profiles and linked preserved case.")

    stage_statuses = _derive_stage_statuses(level, case_bundle, profile_result.get("files") or {})
    status = "completed_with_degradation" if case_bundle else "partial"
    warnings = list(profile_result.get("warnings") or [])
    if not case_bundle:
        warnings.append("No linked source case was provided. The execution was scaffolded but no scientific profiles could be populated from preserved artifacts.")

    execution_manifest = {
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "level": level,
        "status": status,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "source_case_id": case_bundle.get("case_id") if case_bundle else source_case_id,
        "source_case_path": case_bundle.get("case_rel_path") if case_bundle else source_case_path,
        "base_case_id": config.get("base_case_id"),
        "base_case_path": config.get("base_case_path"),
        "base_artifacts_read_only": True if (level == "A" and case_bundle) else False,
        "run_case_id": case_bundle.get("case_id") if case_bundle else config.get("run_case_id"),
        "run_case_path": case_bundle.get("case_rel_path") if case_bundle else config.get("run_case_path"),
        "stage_statuses": stage_statuses,
        "warnings": warnings,
        "artifacts": profile_result.get("files") or {},
    }
    _write_json(exec_dir / "execution_manifest.json", execution_manifest)
    _write_json(exec_dir / "job_status.json", {"status": status, "updated_at": utc_now(), "current_phase": "execution_registered"})
    _write_json(exec_dir / "execution_log.json", {"events": [{"ts": utc_now(), "event": "execution_registered", "detail": "execution registered by foc_experimentation"}]})

    if callable(progress_hook):
        progress_hook("write_execution_manifest", "Write execution manifest", 97.0, "Persisting execution_manifest.json, job_status.json, and execution_log.json.")

    # Level C report placeholders remain inside the module workspace only.
    if level == "C":
        for name in [
            "deployment_manifest.json",
            "infrastructure_fingerprint.json",
            "tool_installation_report.json",
            "sensor_configuration_report.json",
            "ids_siem_configuration_report.json",
            "plc_deployment_report.json",
            "scada_hmi_deployment_report.json",
            "environment_validation_report.json",
            "redeployment_log.json",
        ]:
            path = exec_dir / name
            if not path.exists():
                _write_json(path, {"status": "not_generated", "reason": "first-phase experimentation module does not redeploy infrastructure automatically"})

    manifest["current_execution_id"] = execution_id
    _write_json(campaign_manifest_path(campaign_id), manifest)
    manifest = aggregate_campaign_state(campaign_id, manifest)

    if callable(progress_hook):
        progress_hook("update_campaign_manifest", "Update campaign manifest", 99.0, "Updating campaign_manifest.json with the new execution registration.")
    return {
        "campaign_id": campaign_id,
        "execution_id": execution_id,
        "execution_dir": rel(exec_dir),
        "status": status,
        "source_case_id": case_bundle.get("case_id") if case_bundle else source_case_id,
        "warnings": warnings,
        "artifacts": profile_result.get("files") or {},
    }


def load_execution(execution_id: str) -> dict | None:
    if not CAMPAIGNS_ROOT.exists():
        return None
    for campaign in CAMPAIGNS_ROOT.iterdir():
        if not campaign.is_dir():
            continue
        for level_dir in campaign.glob("level_*"):
            candidate = level_dir / execution_id / "execution_manifest.json"
            if candidate.is_file():
                payload = _json_load(candidate) or {}
                payload["execution_path"] = rel(candidate.parent)
                payload["execution_abs_path"] = str(candidate.parent.resolve())
                return payload
    return None


def execution_artifacts(execution_id: str) -> dict:
    payload = load_execution(execution_id)
    if not payload:
        return {"error": "execution_not_found", "execution_id": execution_id}
    exec_dir = Path(payload["execution_path"]) if False else None
    artifacts = []
    execution_path = payload.get("execution_abs_path")
    if execution_path:
        base = Path(execution_path)
        if base.exists():
            for item in sorted(base.iterdir()):
                if item.is_file():
                    artifacts.append({"name": item.name, "path": rel(item), "size_bytes": item.stat().st_size})
    return {"execution_id": execution_id, "artifacts": artifacts}


def regenerate_execution_profile(execution_id: str) -> dict:
    payload = load_execution(execution_id)
    if not payload:
        return {"error": "execution_not_found", "execution_id": execution_id}
    return {"status": "not_implemented", "reason": "Use campaign run-next with a new execution or re-register the linked source case in this first-phase module."}
