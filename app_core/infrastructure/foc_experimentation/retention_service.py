from __future__ import annotations

import json
import shutil
from pathlib import Path

from .config import EVIDENCE_STORE_ROOT
from .execution_service import load_execution
from .scientific_memory import append_retention_manifest, build_retention_manifest
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
    execution = load_execution(execution_id, campaign_id=campaign_id)
    if not execution:
        return {"error": "execution_not_found", "execution_id": execution_id}
    base = _execution_base_dir(execution)
    if not base:
        return {"error": "execution_workspace_not_found", "execution_id": execution_id}

    result_card_path = base / "forensic_result_card.json"
    comparison_profile_path = base / "forensic_comparison_profile.json"
    execution_manifest_path = base / "execution_manifest.json"
    result_card = _json_load(result_card_path)
    comparison_profile = _json_load(comparison_profile_path)
    execution_manifest = _json_load(execution_manifest_path)
    if not isinstance(result_card, dict):
        return {"error": "missing_forensic_result_card", "execution_id": execution_id}
    if not isinstance(comparison_profile, dict):
        return {"error": "missing_forensic_comparison_profile", "execution_id": execution_id}
    if not isinstance(execution_manifest, dict):
        return {"error": "missing_execution_manifest", "execution_id": execution_id}

    original_case_rel = result_card.get("original_case_path") or execution_manifest.get("run_case_path") or execution_manifest.get("source_case_path")
    original_case_path = (Path.cwd() / original_case_rel).resolve() if original_case_rel else None
    case_id = result_card.get("case_id") or execution_manifest.get("run_case_id") or execution_manifest.get("source_case_id")
    if not case_id:
        return {"error": "case_id_not_available", "execution_id": execution_id}
    if case_id == _active_case_id():
        return {"error": "active_case_blocked", "execution_id": execution_id, "case_id": case_id}

    preservation = result_card.get("preservation_summary") or {}
    preserved_profiles = [
        relative_path(result_card_path),
        relative_path(comparison_profile_path),
        relative_path(execution_manifest_path),
    ]
    if (base / "case_result_card.json").is_file():
        preserved_profiles.append(relative_path(base / "case_result_card.json"))
    if (base / "analysis_repeatability_profile.json").is_file():
        preserved_profiles.append(relative_path(base / "analysis_repeatability_profile.json"))
    if (base / "ground_truth_seal.json").is_file():
        preserved_profiles.append(relative_path(base / "ground_truth_seal.json"))

    if not preservation:
        preservation = {"manifest_available": False, "chain_of_custody_available": False}

    manifest = build_retention_manifest(
        case_id=case_id,
        execution_id=execution_id,
        campaign_id=execution.get("campaign_id"),
        original_case_path=original_case_rel,
        operator=operator,
        reason=reason,
        preserved_profiles=preserved_profiles,
        preserved_hashes={
            "manifest_hash": comparison_profile.get("integrity", {}).get("manifest_hash"),
            "case_digest_hash": comparison_profile.get("integrity", {}).get("case_digest_hash"),
        },
        what_was_deleted_or_archived=[action],
        heavy_artifacts_retained=bool(result_card.get("heavy_artifacts_retained", True)),
        heavy_artifacts_location=result_card.get("heavy_artifacts_location"),
        comparison_readiness_after_cleanup="ready" if result_card.get("comparison_profile_path") else "insufficient_data",
    )
    manifest["prepared_at"] = utc_now()
    manifest["apply_changes"] = apply_changes
    manifest["action"] = action
    manifest["validation"] = {
        "forensic_result_card_available": True,
        "forensic_comparison_profile_available": True,
        "execution_manifest_available": True,
        "preservation_summary_available": bool(preservation),
        "original_case_exists": bool(original_case_path and original_case_path.exists()),
    }

    archive_target = None
    if apply_changes and action in {"archive_case_directory", "delete_case_directory"}:
        if not confirm_delete:
            return {"error": "confirmation_required", "execution_id": execution_id, "action": action}
        if not original_case_path or not original_case_path.exists():
            return {"error": "original_case_not_found", "execution_id": execution_id, "case_id": case_id}
        if EVIDENCE_STORE_ROOT.resolve() not in original_case_path.parents:
            return {"error": "case_outside_evidence_store", "execution_id": execution_id, "case_id": case_id}
        if action == "archive_case_directory":
            archive_target = original_case_path.with_name(f"{original_case_path.name}__archived_{utc_now().replace(':', '').replace('-', '')}")
            shutil.move(str(original_case_path), str(archive_target))
            manifest["heavy_artifacts_retained"] = True
            manifest["heavy_artifacts_location"] = relative_path(archive_target)
        elif action == "delete_case_directory":
            shutil.rmtree(original_case_path)
            manifest["heavy_artifacts_retained"] = False
            manifest["heavy_artifacts_location"] = None

    append_retention_manifest(manifest)
    manifest_path = base / "retention_manifest.json"
    _write_json(manifest_path, manifest)
    return {
        "status": "ok",
        "execution_id": execution_id,
        "case_id": case_id,
        "manifest": manifest,
        "manifest_path": relative_path(manifest_path),
        "archive_target": relative_path(archive_target) if archive_target else None,
    }
