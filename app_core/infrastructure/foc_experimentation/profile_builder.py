from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from ..foc_reconstruction.evidence_lifecycle_dashboard import load_evidence_lifecycle_dashboard
from ..foc_reconstruction.foc_case_analysis import _case_dir_from_entry, get_case_entry, load_analysis_status, load_time_sync_status
from ..foc_reconstruction.foc_paths import relative_path
from ..foc_reconstruction.foc_sources import utc_now
from ..foc_causal_reconstruction.service import causal_metrics_payload, causal_status_payload, causal_uncertainty_payload
from .scientific_memory import (
    build_analysis_repeatability_profile,
    build_forensic_result_card,
    register_scientific_memory,
)


def _json_load(path: Path | None):
    try:
        if path is None or not path.is_file():
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
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "value"))


def _mtime_iso(path: Path | None) -> str | None:
    try:
        ts = os.path.getmtime(path)
    except Exception:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _sha256_path(path: Path | None) -> str:
    if path is None or not path.is_file():
        return "not_available"
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_case_source(case_id: str | None = None, case_path: str | None = None) -> dict | None:
    if case_id:
        entry = get_case_entry(case_id)
        if not entry:
            return None
        case_dir = _case_dir_from_entry(entry)
        return {
            "case_id": str(entry.get("case_id")),
            "case_path": str(case_dir),
            "case_rel_path": relative_path(case_dir),
            "entry": entry,
        }
    if case_path:
        path = Path(case_path).expanduser().resolve()
        if not path.is_dir():
            return None
        return {
            "case_id": f"case-{_safe_slug(path.name)}",
            "case_path": str(path),
            "case_rel_path": relative_path(path),
            "entry": {
                "case_id": f"case-{_safe_slug(path.name)}",
                "source_case_name": path.name,
                "path": relative_path(path),
            },
        }
    return None


def _match_selector(item: dict, selector: dict | None) -> bool:
    if not selector:
        return True
    def nested_get(payload, dotted):
        value = payload
        for part in str(dotted or "").split("."):
            if not part:
                continue
            if not isinstance(value, dict):
                return None
            value = value.get(part)
        return value
    for key, expected in (selector or {}).items():
        actual = nested_get(item, key)
        if str(actual) != str(expected):
            return False
    return True


def _pick_attack_record(ground_truth: dict, attack_attestation: dict) -> dict:
    selector = ((ground_truth.get("attack_expected") or {}).get("selector") or {})
    for item in (attack_attestation.get("attacks") or []):
        if not isinstance(item, dict):
            continue
        if _match_selector(item, selector):
            return item
    return {}


def _artifact_paths(case_dir: Path) -> dict:
    return {
        "summary": case_dir / "derived" / "executive" / "evidence_lifecycle_summary.json",
        "causal_status": case_dir / "derived" / "reconstruction" / "causal_status.json",
        "reconstruction_metrics": case_dir / "derived" / "reconstruction" / "reconstruction_metrics.json",
        "uncertainty_report": case_dir / "derived" / "reconstruction" / "uncertainty_report.json",
        "hypothesis_support_report": case_dir / "derived" / "evidence_support" / "hypothesis_support_report.json",
        "forensic_storyline": case_dir / "derived" / "evidence_support" / "forensic_storyline.json",
        "claimability_report": case_dir / "derived" / "evidence_support" / "claimability_report.json",
        "manifest": case_dir / "manifest.json",
        "custody": case_dir / "chain_of_custody.log",
        "pipeline": case_dir / "metadata" / "pipeline_events.jsonl",
        "analysis_report": case_dir / "analysis" / "forensic_analysis_report.json",
        "network": case_dir / "analysis" / "03_network" / "network_findings.json",
        "memory": case_dir / "analysis" / "04_memory" / "memory_findings.json",
        "disk": case_dir / "analysis" / "05_disk" / "disk_findings.json",
        "ot": case_dir / "analysis" / "06_ot" / "ot_findings.json",
        "alerts": case_dir / "analysis" / "07_alerts" / "alert_findings.json",
        "timeline": case_dir / "analysis" / "09_timeline" / "unified_forensic_timeline.json",
        "cross_layer": case_dir / "analysis" / "10_findings" / "cross_layer_findings.json",
        "time_sync": case_dir / "metadata" / "time_sync.json",
    }


def load_case_bundle(case_id: str | None = None, case_path: str | None = None) -> dict | None:
    source = resolve_case_source(case_id=case_id, case_path=case_path)
    if not source:
        return None
    entry = source["entry"]
    case_dir = Path(source["case_path"]).resolve()
    case_id_resolved = str(entry.get("case_id") or source["case_id"])
    dashboard = load_evidence_lifecycle_dashboard(case_id_resolved) if get_case_entry(case_id_resolved) else {"summary": _json_load(case_dir / "derived" / "executive" / "evidence_lifecycle_summary.json")}
    summary = (dashboard or {}).get("summary") or _json_load(case_dir / "derived" / "executive" / "evidence_lifecycle_summary.json") or {}
    analysis_status = load_analysis_status(case_id_resolved) if get_case_entry(case_id_resolved) else {}
    time_sync_status = load_time_sync_status(case_id_resolved) if get_case_entry(case_id_resolved) else (_json_load(case_dir / "metadata" / "time_sync.json") or {})
    causal_status = causal_status_payload(case_id_resolved, case_dir) or _json_load(case_dir / "derived" / "reconstruction" / "causal_status.json") or {}
    metrics = causal_metrics_payload(case_id_resolved, case_dir) or _json_load(case_dir / "derived" / "reconstruction" / "reconstruction_metrics.json") or {}
    uncertainty = causal_uncertainty_payload(case_id_resolved, case_dir) or _json_load(case_dir / "derived" / "reconstruction" / "uncertainty_report.json") or {}
    attack_attestation = _json_load(Path("foc-reconstruction") / "attestations" / "attack_attestation.json") or {}
    ground_truth_path_raw = (((causal_status.get("ground_truth_summary") or {}).get("ground_truth_path")) or "")
    ground_truth_path = Path(ground_truth_path_raw).expanduser().resolve() if ground_truth_path_raw else None
    ground_truth = _json_load(ground_truth_path) or {}
    attack_record = _pick_attack_record(ground_truth, attack_attestation)
    paths = _artifact_paths(case_dir)
    return {
        "case_id": case_id_resolved,
        "case_dir": case_dir,
        "case_path": str(case_dir),
        "case_rel_path": relative_path(case_dir),
        "entry": entry,
        "dashboard": dashboard or {},
        "summary": summary or {},
        "analysis_status": analysis_status or {},
        "time_sync_status": time_sync_status or {},
        "causal_status": causal_status or {},
        "metrics": metrics or {},
        "uncertainty": uncertainty or {},
        "ground_truth": ground_truth or {},
        "ground_truth_path": ground_truth_path,
        "attack_record": attack_record or {},
        "paths": paths,
    }


def build_execution_profiles(
    *,
    execution_id: str,
    campaign_id: str,
    level: str,
    execution_dir: Path,
    case_bundle: dict | None,
    baseline_noise_enabled: bool,
    baseline_window_seconds: int,
    baseline_threshold: float,
    baseline_builder,
    seal_builder,
    campaign_config: dict | None = None,
    progress_hook=None,
) -> dict:
    if not case_bundle:
        return {"status": "insufficient_data", "files": {}, "warnings": ["no source case was linked to this execution"]}

    if callable(progress_hook):
        progress_hook("load_case_bundle", "Load linked case context", 12.0, "Reading preserved case summary, analysis, causal status, and uncertainty inputs.")

    summary = case_bundle.get("summary") or {}
    causal = case_bundle.get("causal_status") or {}
    metrics = case_bundle.get("metrics") or {}
    uncertainty = case_bundle.get("uncertainty") or {}
    attack = case_bundle.get("attack_record") or {}
    ground_truth = case_bundle.get("ground_truth") or {}
    trigger = (summary.get("trigger_summary") or {})
    final_conclusion = (summary.get("final_forensic_conclusion") or {})
    paths = case_bundle.get("paths") or {}

    scenario_profile = {
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "level": level,
        "source_case_id": case_bundle.get("case_id"),
        "source_case_path": case_bundle.get("case_rel_path"),
        "scenario_id": summary.get("scenario_id") or ((causal.get("ground_truth_summary") or {}).get("scenario_id")) or "not_available",
        "scenario_name": summary.get("scenario_name") or case_bundle.get("entry", {}).get("source_case_name") or "not_available",
        "created_at": _mtime_iso(case_bundle.get("ground_truth_path")) or utc_now(),
        "base_artifacts_read_only": True,
        "source_label": "linked_existing_case",
    }

    attack_profile = {
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "source_case_id": case_bundle.get("case_id"),
        "technique_id": ((ground_truth.get("attack_expected") or {}).get("technique_id")) or (((attack.get("mitre") or {}).get("technique_id"))) or "not_available",
        "technique_name": ((ground_truth.get("attack_expected") or {}).get("technique_name")) or (((attack.get("mitre") or {}).get("technique_name"))) or "not_available",
        "tool_used": ((ground_truth.get("attack_expected") or {}).get("tool_used")) or (((attack.get("operation") or {}).get("tool_used"))) or "not_available",
        "tool_version": ((ground_truth.get("attack_expected") or {}).get("tool_version")) or (((attack.get("operation") or {}).get("tool_version"))) or "not_available",
        "protocol": ((ground_truth.get("attack_expected") or {}).get("protocol")) or (((attack.get("operation") or {}).get("protocol"))) or "not_available",
        "ot_function": ((ground_truth.get("attack_expected") or {}).get("ot_function")) or (((attack.get("operation") or {}).get("modbus_function"))) or "not_available",
        "register": ((ground_truth.get("attack_expected") or {}).get("register")),
        "expected_value": ((ground_truth.get("attack_expected") or {}).get("expected_value")),
        "attack_id": attack.get("attack_id") or (((ground_truth.get("attack_expected") or {}).get("selector") or {}).get("attack_id")) or "not_available",
        "attack_started_at": (((attack.get("execution") or {}).get("started_at"))) or "not_available",
        "attack_completed_at": (((attack.get("execution") or {}).get("completed_at"))) or "not_available",
        "created_at": (((attack.get("execution") or {}).get("started_at"))) or _mtime_iso(case_bundle.get("ground_truth_path")) or utc_now(),
        "attack_script_reference": attack.get("source_reference") or "not_available",
    }

    ground_truth_payload = ground_truth or {
        "scenario_id": scenario_profile["scenario_id"],
        "attack_expected": {},
        "expected_edges": [],
    }

    scenario_profile_path = execution_dir / "scenario_profile.json"
    attack_profile_path = execution_dir / "attack_profile.json"
    ground_truth_path = execution_dir / "ground_truth.json"
    _write_json(scenario_profile_path, scenario_profile)
    _write_json(attack_profile_path, attack_profile)
    _write_json(ground_truth_path, ground_truth_payload)

    if callable(progress_hook):
        progress_hook("write_profiles", "Write scenario and attack profiles", 28.0, "Writing scenario_profile.json, attack_profile.json, and ground_truth.json into the execution workspace.")

    source_attack_script = None
    attack_ref = attack_profile.get("attack_script_reference")
    if attack_ref and attack_ref != "not_available":
        candidate = Path(attack_ref)
        if not candidate.is_absolute():
            candidate = Path.cwd() / attack_ref
        source_attack_script = candidate.resolve() if candidate.exists() else None
    attack_script_sha256 = _sha256_path(source_attack_script)

    seal = seal_builder(
        ground_truth_id=f"{scenario_profile['scenario_id']}::{execution_id}",
        scenario_id=scenario_profile["scenario_id"],
        execution_id=execution_id,
        ground_truth_path=case_bundle.get("ground_truth_path") or ground_truth_path,
        scenario_profile_path=scenario_profile_path,
        attack_profile_path=attack_profile_path,
        attack_script_path=source_attack_script,
        created_at=_mtime_iso(case_bundle.get("ground_truth_path")) or scenario_profile["created_at"],
        scenario_profile_created_at=scenario_profile["created_at"],
        attack_profile_created_at=attack_profile["created_at"],
        attack_start_time=attack_profile.get("attack_started_at"),
        custody_reference=relative_path(paths.get("custody")) if paths.get("custody") and paths.get("custody").exists() else "not_available",
        generator="foc_experimentation.profile_builder",
    )
    seal_path = execution_dir / "ground_truth_seal.json"
    _write_json(seal_path, seal)

    if callable(progress_hook):
        progress_hook("ground_truth_seal", "Generate ground truth seal", 42.0, "Creating ground_truth_seal.json from preserved inputs and pre-attack references.")

    alerts_summary = (summary.get("alert_triage_summary") or {})
    network_summary = (summary.get("multilayer_analysis_summary") or {})
    ot_summary = (summary.get("modbus_specificity") or {})
    baseline = baseline_builder(
        execution_id=execution_id,
        enabled=baseline_noise_enabled,
        baseline_window_seconds=baseline_window_seconds,
        time_sync=case_bundle.get("time_sync_status") or {},
        alerts_summary=alerts_summary,
        network_summary=network_summary,
        ot_summary=ot_summary,
        threshold=baseline_threshold,
    )
    baseline_path = execution_dir / "baseline_noise_profile.json"
    _write_json(baseline_path, baseline)

    if callable(progress_hook):
        progress_hook("baseline_noise", "Generate baseline noise profile", 52.0, "Writing baseline_noise_profile.json for later comparability checks.")

    detection_trigger_profile = {
        "execution_id": execution_id,
        "selected_trigger": trigger.get("trigger") or "not_available",
        "selected_trigger_rule": trigger.get("triggering_alert_rule_id") or "not_available",
        "selected_trigger_source": trigger.get("trigger_type") or "not_available",
        "selected_trigger_score": trigger.get("trigger_selection_score"),
        "reason_for_selection": trigger.get("trigger_selection_method") or "not_available",
        "stronger_trigger_available": bool(trigger.get("stronger_trigger_available")),
        "trigger_candidates_evaluated": trigger.get("candidate_triggers_evaluated") or 0,
        "trigger_attack_alignment": (((summary.get("causal_summary") or {}).get("trigger_vs_causal_path")) or {}).get("status") or "not_available",
    }
    detection_path = execution_dir / "detection_trigger_profile.json"
    _write_json(detection_path, detection_trigger_profile)

    if callable(progress_hook):
        progress_hook("detection_trigger", "Generate detection and trigger profile", 62.0, "Normalizing selected trigger, trigger rule, and trigger-alignment metadata.")

    acquisition_profile = {
        "execution_id": execution_id,
        "source_case_id": case_bundle.get("case_id"),
        "intervention_status": trigger.get("intervention_status") or "not_available",
        "target_nodes": trigger.get("target_nodes") or [],
        "manifest_path": relative_path(paths.get("manifest")) if paths.get("manifest") and paths.get("manifest").exists() else None,
        "chain_of_custody_path": relative_path(paths.get("custody")) if paths.get("custody") and paths.get("custody").exists() else None,
        "pipeline_path": relative_path(paths.get("pipeline")) if paths.get("pipeline") and paths.get("pipeline").exists() else None,
    }
    acquisition_path = execution_dir / "acquisition_profile.json"
    _write_json(acquisition_path, acquisition_profile)

    preservation_profile = {
        "execution_id": execution_id,
        "manifest_available": bool(paths.get("manifest") and paths["manifest"].exists()),
        "chain_of_custody_available": bool(paths.get("custody") and paths["custody"].exists()),
        "analysis_report_available": bool(paths.get("analysis_report") and paths["analysis_report"].exists()),
        "time_sync_available": bool(paths.get("time_sync") and paths["time_sync"].exists()),
        "manifest_sha256": _sha256_path(paths.get("manifest")),
        "chain_of_custody_sha256": _sha256_path(paths.get("custody")),
    }
    preservation_path = execution_dir / "preservation_profile.json"
    _write_json(preservation_path, preservation_profile)

    if callable(progress_hook):
        progress_hook("acquisition_preservation", "Generate acquisition and preservation profiles", 74.0, "Writing acquisition_profile.json and preservation_profile.json from preserved case artifacts.")

    hypothesis_support = _json_load(paths.get("hypothesis_support_report")) or {}
    claimability = _json_load(paths.get("claimability_report")) or {}

    comparison_profile = {
        "execution_id": execution_id,
        "campaign_id": campaign_id,
        "level": level,
        "source_case_id": case_bundle.get("case_id"),
        "source_case_path": case_bundle.get("case_rel_path"),
        "generated_at": utc_now(),
        "scenario_profile": {
            "scenario_id": scenario_profile["scenario_id"],
            "scenario_name": scenario_profile["scenario_name"],
        },
        "attack_profile": {
            "attack_id": attack_profile["attack_id"],
            "technique_id": attack_profile["technique_id"],
            "protocol": attack_profile["protocol"],
            "register": attack_profile["register"],
            "expected_value": attack_profile["expected_value"],
        },
        "ground_truth_seal": {
            "seal_valid": seal.get("seal_valid"),
            "seal_validation_reason": seal.get("seal_validation_reason"),
        },
        "baseline_noise": {
            "baseline_noise_status": baseline.get("baseline_noise_status"),
            "comparison_threshold": baseline.get("comparison_threshold"),
            "warning_reason": baseline.get("warning_reason"),
        },
        "detection_trigger": detection_trigger_profile,
        "acquisition": acquisition_profile,
        "preservation": preservation_profile,
        "multilayer_analysis": summary.get("multilayer_analysis_summary") or {},
        "causal_reconstruction": {
            "status": (summary.get("causal_summary") or {}).get("status") or causal.get("status") or "not_available",
            "expected_edges": metrics.get("expected_edges"),
            "recovered_edges": metrics.get("recovered_edges"),
            "degraded_edges": metrics.get("degraded_edges"),
            "ambiguous_edges": metrics.get("ambiguous_edges"),
            "missing_edges": metrics.get("missing_edges"),
            "cpr": metrics.get("causal_path_recoverability"),
            "weighted_cpr": metrics.get("weighted_cpr"),
            "reconstruction_confidence": metrics.get("reconstruction_confidence"),
            "main_limitation": ((summary.get("causal_summary") or {}).get("main_limitation")) or ((summary.get("execution_summary") or {}).get("main_limitation")),
        },
        "uncertainty": {
            "temporal_confidence": (((summary.get("uncertainty_summary") or {}).get("temporal")) or {}).get("causal_temporal_ordering_confidence"),
            "max_clock_offset_seconds": (((summary.get("uncertainty_summary") or {}).get("temporal")) or {}).get("max_clock_offset_seconds"),
            "uncertainty_window_seconds": (((summary.get("uncertainty_summary") or {}).get("temporal")) or {}).get("uncertainty_window_seconds"),
            "clock_sync_status": (((summary.get("uncertainty_summary") or {}).get("temporal")) or {}).get("node_clock_synchronization_status"),
            "case_wide_integrity_status": (((summary.get("uncertainty_summary") or {}).get("integrity")) or {}).get("case_wide_integrity_status"),
        },
        "hypothesis_support": {
            "global_support_level": hypothesis_support.get("global_support_level"),
            "global_confidence": hypothesis_support.get("global_confidence"),
            "final_claimability_status": hypothesis_support.get("final_claimability_status"),
        },
        "final_conclusion": final_conclusion,
        "scientific_limitations": list(summary.get("limitations") or []),
        "next_required_actions": list(summary.get("next_required_actions") or []),
        "reports": {
            key: relative_path(path) if path and path.exists() else None
            for key, path in paths.items()
        },
        "claimability": claimability,
    }
    comparison_path = execution_dir / "forensic_comparison_profile.json"
    _write_json(comparison_path, comparison_profile)

    if callable(progress_hook):
        progress_hook("comparison_profile", "Generate forensic comparison profile", 88.0, "Writing forensic_comparison_profile.json for later execution-to-execution comparison.")

    from .comparison_registry import append_to_registry

    result_card_path = execution_dir / "forensic_result_card.json"
    result_card = build_forensic_result_card(
        execution_id=execution_id,
        campaign_id=campaign_id,
        level=level,
        case_bundle=case_bundle,
        scenario_profile=scenario_profile,
        attack_profile=attack_profile,
        ground_truth_payload=ground_truth_payload,
        attack_script_sha256=attack_script_sha256,
        campaign_config=campaign_config or {},
        comparison_profile=comparison_profile,
        comparison_profile_path=comparison_path,
        result_card_path=result_card_path,
        retention_policy="original_case_retained" if case_bundle else "profiles_only_after_archive",
        heavy_artifacts_retained=bool(case_bundle),
    )
    registry = append_to_registry(result_card)
    comparable_with = [
        item.get("result_card_id")
        for item in registry.get("entries", [])
        if item.get("comparison_family_id") == result_card.get("comparison_family_id")
        and item.get("result_card_id") != result_card.get("result_card_id")
    ]
    result_card["comparable_with"] = comparable_with
    _write_json(result_card_path, result_card)
    append_to_registry(result_card)

    scientific_memory = register_scientific_memory(
        case_bundle=case_bundle,
        execution_id=execution_id,
        campaign_id=campaign_id,
        level=level,
        scenario_profile=scenario_profile,
        attack_profile=attack_profile,
        ground_truth_payload=ground_truth_payload,
        comparison_profile=comparison_profile,
        comparison_profile_path=comparison_path,
        result_card=result_card,
        result_card_path=result_card_path,
        campaign_config=campaign_config or {},
    )

    repeatability_path = None
    if str(level).upper() == "A" and case_bundle:
        repeatability = build_analysis_repeatability_profile(
            base_case_id=case_bundle.get("case_id"),
            base_case_path=case_bundle.get("case_rel_path"),
            execution_id=execution_id,
            campaign_id=campaign_id,
            comparison_profile=comparison_profile,
            result_card_id=result_card["result_card_id"],
            comparison_profile_path=comparison_path,
            analysis_profile_id=str((campaign_config or {}).get("analysis_profile_id") or "default_multilayer_analysis_v1"),
            foc_profile_id=str((campaign_config or {}).get("foc_profile_id") or "default_foc_causal_reconstruction_v1"),
        )
        repeatability_path = execution_dir / "analysis_repeatability_profile.json"
        _write_json(repeatability_path, repeatability)

    if callable(progress_hook):
        progress_hook("result_card", "Register lightweight comparison result card", 94.0, "Writing forensic_result_card.json and registering it in the cross-campaign comparison registry.")

    files = {
        "scenario_profile": relative_path(scenario_profile_path),
        "attack_profile": relative_path(attack_profile_path),
        "ground_truth": relative_path(ground_truth_path),
        "ground_truth_seal": relative_path(seal_path),
        "baseline_noise_profile": relative_path(baseline_path),
        "detection_trigger_profile": relative_path(detection_path),
        "acquisition_profile": relative_path(acquisition_path),
        "preservation_profile": relative_path(preservation_path),
        "forensic_comparison_profile": relative_path(comparison_path),
        "forensic_result_card": relative_path(result_card_path),
        "scenario_result_card": scientific_memory.get("scenario_card_path"),
        "case_result_card": scientific_memory.get("case_card_path"),
        "execution_result_card": scientific_memory.get("execution_card_path"),
        "analysis_result_card": scientific_memory.get("analysis_card_path"),
        "scenario_reconstruction_blueprint": scientific_memory.get("blueprint_path"),
        "analysis_repeatability_profile": relative_path(repeatability_path) if repeatability_path else None,
    }
    return {
        "status": "ok",
        "files": files,
        "comparison_profile": comparison_profile,
        "result_card": result_card,
        "scientific_memory": scientific_memory,
    }
