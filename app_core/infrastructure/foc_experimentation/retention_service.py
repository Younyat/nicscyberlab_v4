from __future__ import annotations

import json
import shutil
from pathlib import Path

from .comparison_registry import load_registry as load_comparison_registry
from .config import ARCHIVED_CASES_ROOT, CASE_REGISTRY_PATH, EVIDENCE_STORE_ROOT
from .execution_service import load_execution
from .scientific_memory import append_retention_manifest, build_retention_manifest, load_registry as load_scientific_registry
from ..foc_reconstruction.foc_paths import relative_path
from ..foc_reconstruction.foc_sources import utc_now


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


def _active_case_id() -> str | None:
    path = EVIDENCE_STORE_ROOT / "_active_case.txt"
    try:
        value = path.read_text(encoding="utf-8").strip()
        return value or None
    except Exception:
        return None


def _execution_base_dir(payload: dict) -> Path | None:
    execution_abs_path = payload.get("execution_abs_path")
    if not execution_abs_path:
        return None
    base = Path(execution_abs_path)
    return base if base.exists() else None


def _case_result_card_path(case_id: str) -> Path:
    return CASE_REGISTRY_PATH.parent / case_id / "case_result_card.json"


def _comparison_registry_entry(result_card_id: str | None) -> dict | None:
    if not result_card_id:
        return None
    registry = load_comparison_registry()
    return next((item for item in registry.get("entries", []) if item.get("result_card_id") == result_card_id), None)


def _bool_check(key: str, ok: bool, why: str, fix: str, auto: bool = False) -> dict:
    return {
        "key": key,
        "status": "ok" if ok else "missing",
        "why_it_matters": why,
        "how_to_fix": fix,
        "can_be_auto_generated": auto,
    }


def _case_cleanup_context(execution_id: str, *, campaign_id: str | None = None) -> dict:
    execution = load_execution(execution_id, campaign_id=campaign_id)
    if not execution:
        return {"error": "execution_not_found", "execution_id": execution_id}

    level = str(execution.get("level") or "").upper()
    if level not in {"B", "C"}:
        return {
            "error": "cleanup_not_applicable",
            "execution_id": execution_id,
            "level": level or "unknown",
            "message": "Delete Generated Case Artifacts is only applicable to Level B and Level C executions.",
        }

    base = _execution_base_dir(execution)
    if not base:
        return {"error": "execution_workspace_not_found", "execution_id": execution_id}

    result_card_path = base / "forensic_result_card.json"
    comparison_profile_path = base / "forensic_comparison_profile.json"
    execution_manifest_path = base / "execution_manifest.json"
    retention_manifest_path = base / "retention_manifest.json"
    result_card = _json_load(result_card_path)
    comparison_profile = _json_load(comparison_profile_path)
    execution_manifest = _json_load(execution_manifest_path)
    case_id = (
        (result_card or {}).get("case_id")
        or (execution_manifest or {}).get("run_case_id")
        or execution.get("run_case_id")
    )
    case_result_card_path = _case_result_card_path(case_id) if case_id else None
    case_result_card = _json_load(case_result_card_path) if case_result_card_path else None
    original_case_rel = (
        (result_card or {}).get("original_case_path")
        or (execution_manifest or {}).get("run_case_path")
        or execution.get("run_case_path")
    )
    original_case_path = (Path.cwd() / original_case_rel).resolve() if original_case_rel else None
    comparison_entry = _comparison_registry_entry((result_card or {}).get("result_card_id"))
    preservation_summary = (result_card or {}).get("preservation_summary") or ((comparison_profile or {}).get("preservation") or {})
    chain_of_custody_summary = (case_result_card or {}).get("chain_of_custody_summary") or {}
    analysis_summary = (comparison_profile or {}).get("multilayer_analysis") or {}
    causal_summary = (comparison_profile or {}).get("causal_reconstruction") or {}
    uncertainty_summary = (comparison_profile or {}).get("uncertainty") or {}
    hypothesis_summary = (comparison_profile or {}).get("hypothesis_support") or {}
    final_conclusion = (comparison_profile or {}).get("final_conclusion") or {}
    original_hashes = {
        "manifest_hash": (case_result_card or {}).get("manifest_hash"),
        "case_digest_hash": (case_result_card or {}).get("case_digest_hash"),
    }

    checks = [
        _bool_check(
            "forensic_result_card",
            isinstance(result_card, dict),
            "The lightweight result card is required to preserve scientific comparison memory before cleanup.",
            "Generate or regenerate forensic_result_card.json for this execution.",
        ),
        _bool_check(
            "forensic_comparison_profile",
            isinstance(comparison_profile, dict),
            "Comparability must rely on the normalized forensic profile after heavy artifacts are removed.",
            "Generate forensic_comparison_profile.json before cleanup.",
        ),
        _bool_check(
            "case_result_card",
            isinstance(case_result_card, dict),
            "The case card preserves the lightweight summary of the generated case after heavy artifacts are removed.",
            "Generate or synchronize case_result_card.json before cleanup.",
            True,
        ),
        _bool_check(
            "execution_manifest",
            isinstance(execution_manifest, dict),
            "The execution manifest preserves the execution state and artifact linkage.",
            "Regenerate execution_manifest.json before cleanup.",
        ),
        _bool_check(
            "comparison_registry_entry",
            isinstance(comparison_entry, dict),
            "The comparison registry must retain the result card for future cross-campaign reuse.",
            "Register the result card in comparison_result_registry.json before cleanup.",
            True,
        ),
        _bool_check(
            "preservation_summary",
            bool(preservation_summary),
            "The preserved-case summary is required to remember what evidence existed even after deleting heavy artifacts.",
            "Ensure preservation_summary is present in the result card or comparison profile.",
        ),
        _bool_check(
            "chain_of_custody_summary",
            bool(chain_of_custody_summary),
            "Chain-of-custody summary must survive cleanup.",
            "Populate chain_of_custody_summary in case_result_card.json before cleanup.",
            True,
        ),
        _bool_check(
            "analysis_summary",
            bool(analysis_summary),
            "The multilayer analysis summary is part of the preserved scientific memory.",
            "Populate multilayer analysis summary before cleanup.",
        ),
        _bool_check(
            "causal_metrics",
            causal_summary.get("cpr") is not None and causal_summary.get("weighted_cpr") is not None,
            "Causal metrics must remain available after deleting heavy artifacts.",
            "Generate causal metrics before cleanup.",
        ),
        _bool_check(
            "uncertainty_summary",
            bool(uncertainty_summary),
            "Uncertainty summary must remain available after deleting heavy artifacts.",
            "Generate uncertainty summary before cleanup.",
        ),
        _bool_check(
            "hypothesis_support_summary",
            bool(hypothesis_summary),
            "Hypothesis support summary must remain available after deleting heavy artifacts.",
            "Generate hypothesis support summary before cleanup.",
        ),
        _bool_check(
            "final_conclusion_class",
            bool((result_card or {}).get("final_conclusion_class") or final_conclusion.get("conclusion_class") or final_conclusion.get("summary_class")),
            "The final conclusion class is part of the preserved scientific memory.",
            "Generate final conclusion summary before cleanup.",
        ),
        _bool_check(
            "generated_case_exists",
            bool(original_case_path and original_case_path.exists()),
            "Heavy artifacts can only be deleted if a generated case directory really exists.",
            "Run a real Level B or Level C execution that creates a new forensic case before cleanup.",
        ),
    ]

    hashes_available = bool(original_hashes.get("manifest_hash") not in {None, "", "not_available"} or original_hashes.get("case_digest_hash") not in {None, "", "not_available"})
    checks.append(
        _bool_check(
            "original_hashes",
            hashes_available,
            "Original hashes should be preserved when available so that integrity context survives cleanup.",
            "Generate or synchronize manifest_hash and case_digest_hash if they exist in the original case.",
            True,
        )
    )

    missing_required = [item for item in checks if item["status"] != "ok" and item["key"] != "original_hashes"]
    if case_id == _active_case_id():
        return {
            "error": "active_case_blocked",
            "execution_id": execution_id,
            "case_id": case_id,
            "message": "The generated case is currently marked as active. Cleanup is blocked until a different active case is selected.",
        }

    return {
        "status": "ok",
        "ready": not missing_required,
        "execution": execution,
        "level": level,
        "execution_id": execution_id,
        "campaign_id": execution.get("campaign_id"),
        "case_id": case_id,
        "original_case_path": original_case_path,
        "original_case_rel": original_case_rel,
        "result_card": result_card,
        "comparison_profile": comparison_profile,
        "execution_manifest": execution_manifest,
        "case_result_card": case_result_card,
        "case_result_card_path": relative_path(case_result_card_path) if case_result_card_path and case_result_card_path.exists() else None,
        "comparison_registry_entry": comparison_entry,
        "retention_manifest_path": relative_path(retention_manifest_path) if retention_manifest_path.exists() else None,
        "checks": checks,
        "missing_required": missing_required,
        "preserved_hashes": original_hashes,
    }


def validate_case_cleanup(
    execution_id: str,
    *,
    campaign_id: str | None = None,
    case_id: str | None = None,
    action_type: str = "delete_case_directory",
) -> dict:
    context = _case_cleanup_context(execution_id, campaign_id=campaign_id)
    if context.get("error"):
        return context
    if case_id and case_id != context.get("case_id"):
        return {
            "error": "case_id_mismatch",
            "execution_id": execution_id,
            "case_id": context.get("case_id"),
            "message": "The provided case_id does not match the generated case linked to this execution.",
        }
    return {
        "status": "ok",
        "ready": context["ready"],
        "execution_id": execution_id,
        "campaign_id": context["campaign_id"],
        "case_id": context["case_id"],
        "evaluation_level": context["level"],
        "action_type": action_type,
        "checks": context["checks"],
        "message": (
            "The generated case can be cleaned up. Lightweight scientific comparison data will be preserved."
            if context["ready"]
            else "The generated case cannot be deleted because the lightweight scientific memory is incomplete. Generate the result card, comparison profile, registry entry, and retention manifest before cleanup."
        ),
    }


def prepare_retention_cleanup(
    execution_id: str,
    *,
    campaign_id: str | None = None,
    operator: str = "foc_experimentation",
    reason: str = "Preserve lightweight profiles for future comparison without duplicating heavy evidence.",
    action: str = "archive_metadata_only",
    apply_changes: bool = False,
    confirm_delete: bool = False,
) -> dict:
    if apply_changes and action in {"delete_case_directory", "archive_case_directory"}:
        return delete_generated_case_artifacts(
            execution_id,
            campaign_id=campaign_id,
            action_type=action,
            confirmation="OK" if confirm_delete else "",
            operator=operator,
        )
    payload = validate_case_cleanup(
        execution_id,
        campaign_id=campaign_id,
        action_type="archive_case_directory" if action == "archive_case_directory" else "delete_case_directory",
    )
    if payload.get("error"):
        return payload
    payload["prepared_at"] = utc_now()
    payload["operator"] = operator
    payload["reason"] = reason
    payload["apply_changes"] = apply_changes
    return payload


def delete_generated_case_artifacts(
    execution_id: str,
    *,
    campaign_id: str | None = None,
    case_id: str | None = None,
    operator: str = "foc_experimentation",
    action_type: str = "delete_case_directory",
    confirmation: str = "",
) -> dict:
    if confirmation != "OK":
        return {"error": "confirmation_required", "message": "Type exactly OK to confirm generated-case cleanup."}

    context = _case_cleanup_context(execution_id, campaign_id=campaign_id)
    if context.get("error"):
        return context
    if case_id and case_id != context.get("case_id"):
        return {"error": "case_id_mismatch", "message": "The provided case_id does not match the generated case linked to this execution."}
    if not context["ready"]:
        return {
            "error": "lightweight_scientific_memory_incomplete",
            "message": "The generated case cannot be deleted because the lightweight scientific memory is incomplete. Generate the result card, comparison profile, registry entry, and retention manifest before cleanup.",
            "checks": context["checks"],
        }

    result_card = context["result_card"]
    comparison_profile = context["comparison_profile"]
    execution_manifest = context["execution_manifest"]
    case_result_card = context["case_result_card"]
    original_case_path = context["original_case_path"]
    original_case_rel = context["original_case_rel"]
    base = _execution_base_dir(context["execution"])
    if base is None:
        return {"error": "execution_workspace_not_found", "execution_id": execution_id}

    if not original_case_path or not original_case_path.exists():
        return {"error": "generated_case_not_found", "message": "The generated case directory does not exist anymore."}
    if EVIDENCE_STORE_ROOT.resolve() not in original_case_path.parents:
        return {"error": "case_outside_evidence_store", "message": "The generated case is outside the managed evidence_store root."}

    if action_type not in {"delete_case_directory", "archive_case_directory"}:
        return {"error": "unsupported_action_type", "action_type": action_type}

    preserved_profiles = [
        relative_path(base / "forensic_result_card.json"),
        relative_path(base / "forensic_comparison_profile.json"),
        relative_path(base / "execution_manifest.json"),
    ]
    if context.get("case_result_card_path"):
        preserved_profiles.append(context["case_result_card_path"])
    if (base / "retention_manifest.json").is_file():
        preserved_profiles.append(relative_path(base / "retention_manifest.json"))
    if (base / "analysis_repeatability_profile.json").is_file():
        preserved_profiles.append(relative_path(base / "analysis_repeatability_profile.json"))

    comparison_registry = load_comparison_registry()
    scientific_case_registry = load_scientific_registry(CASE_REGISTRY_PATH)
    registry_refs = {
        "comparison_result_registry": relative_path(Path(comparison_registry.get("source_path"))) if comparison_registry.get("source_path") else relative_path(Path("app_core/infrastructure/forensics/evidence_store/repetition_campaigns/scientific_memory/result_registry/comparison_result_registry.json")),
        "case_registry": relative_path(CASE_REGISTRY_PATH),
    }

    manifest = build_retention_manifest(
        case_id=context["case_id"],
        execution_id=execution_id,
        campaign_id=context["campaign_id"],
        original_case_path=original_case_rel,
        operator=operator,
        reason="Release heavy generated-case artifacts while preserving lightweight scientific comparison memory.",
        preserved_profiles=preserved_profiles,
        preserved_hashes=context["preserved_hashes"],
        what_was_deleted_or_archived=["full case evidence directory", "memory dumps", "disk images", "network captures", action_type],
        heavy_artifacts_retained=(action_type == "archive_case_directory"),
        heavy_artifacts_location=result_card.get("heavy_artifacts_location"),
        comparison_readiness_after_cleanup="ready" if result_card.get("comparison_profile_path") else "insufficient_data",
    )
    archive_target = None
    if action_type == "archive_case_directory":
        ARCHIVED_CASES_ROOT.mkdir(parents=True, exist_ok=True)
        archive_target = ARCHIVED_CASES_ROOT / f"{original_case_path.name}__archived_{utc_now().replace(':', '').replace('-', '')}"
        shutil.move(str(original_case_path), str(archive_target))
    else:
        shutil.rmtree(original_case_path)

    result_card["heavy_artifacts_retained"] = action_type == "archive_case_directory"
    result_card["heavy_artifacts_location"] = relative_path(archive_target) if archive_target else None
    case_result_card["heavy_artifacts_retained"] = action_type == "archive_case_directory"
    case_result_card["retention_policy"] = result_card.get("retention_policy") or "profiles_only_after_archive"
    execution_manifest["heavy_artifacts_retained"] = action_type == "archive_case_directory"
    execution_manifest["cleanup_status"] = "completed"
    execution_manifest["cleanup_action_type"] = action_type
    execution_manifest["heavy_artifacts_location_before_action"] = original_case_rel
    execution_manifest["heavy_artifacts_location_after_action"] = relative_path(archive_target) if archive_target else None
    if archive_target:
        case_result_card["case_path"] = relative_path(archive_target)

    manifest.update(
        {
            "evaluation_level": context["level"],
            "action_type": action_type,
            "deleted_or_archived_at": utc_now(),
            "confirmation_required": True,
            "confirmation_value": "OK",
            "what_was_retained": preserved_profiles,
            "preserved_result_card_path": relative_path(base / "forensic_result_card.json"),
            "preserved_comparison_profile_path": relative_path(base / "forensic_comparison_profile.json"),
            "preserved_case_card_path": context.get("case_result_card_path"),
            "preserved_registry_entries": registry_refs,
            "original_case_path": original_case_rel,
            "heavy_artifacts_location_before_action": original_case_rel,
            "heavy_artifacts_location_after_action": relative_path(archive_target) if archive_target else None,
            "cleanup_status": "completed",
            "cleanup_warnings": [],
        }
    )

    _write_json(base / "forensic_result_card.json", result_card)
    _write_json(base / "execution_manifest.json", execution_manifest)
    if context.get("case_result_card_path"):
        _write_json(Path.cwd() / context["case_result_card_path"], case_result_card)
    append_retention_manifest(manifest)
    manifest_path = base / "retention_manifest.json"
    _write_json(manifest_path, manifest)

    return {
        "status": "ok",
        "execution_id": execution_id,
        "campaign_id": context["campaign_id"],
        "case_id": context["case_id"],
        "action_type": action_type,
        "manifest_path": relative_path(manifest_path),
        "archive_target": relative_path(archive_target) if archive_target else None,
        "message": "Heavy generated-case artifacts were cleaned up. Lightweight scientific comparison memory was preserved.",
    }
