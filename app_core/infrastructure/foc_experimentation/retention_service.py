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

LIGHTWEIGHT_CASE_MAX_BYTES = 500 * 1024 * 1024

LIGHTWEIGHT_CASE_RETAIN_PATHS: tuple[str, ...] = (
    "manifest.json",
    "chain_of_custody.log",
    "metadata/acquisition_profile.json",
    "metadata/critical_evidence_gate.json",
    "metadata/trigger_alert_binding.json",
    "metadata/forensic_intervention.json",
    "metadata/normalized_causal_timestamps.json",
    "metadata/pipeline_events.jsonl",
    "metadata/time_sync.json",
    # 2026-07-20: added so forge_vi_dashboard._per_case_data() can read this after
    # cleanup deletes the heavy case (see that module's README for the full incident:
    # the FORGE-VI Scientific Reproducibility Dashboard was only ever seeing whatever
    # cases happened to still physically exist, which after cleanup was almost none).
    # Purely additive to this tuple -- every existing reader of the bundle is unaffected.
    "metadata/workflow_phase_summary.json",
    "network/traffic_preserved/network_context_manifest.json",
    "analysis/analysis_status.json",
    "analysis/preflight_validation.json",
    "analysis/forensic_analysis_manifest.json",
    "analysis/forensic_analysis_report.json",
    "analysis/forensic_analysis_summary.md",
    "analysis/00_inventory/evidence_inventory.json",
    "analysis/01_integrity_custody/integrity_custody_report.json",
    "analysis/03_network/network_findings.json",
    "analysis/04_memory/memory_preflight.json",
    "analysis/04_memory/memory_findings.json",
    "analysis/05_disk/disk_findings.json",
    "analysis/06_ot/ot_findings.json",
    "analysis/07_alerts/alert_findings.json",
    "analysis/09_timeline/unified_forensic_timeline.json",
    "analysis/10_findings/cross_layer_findings.json",
    "analysis/visual/analysis_visual_summary.json",
    "derived/executive/evidence_lifecycle_summary.json",
    "derived/reconstruction/causal_status.json",
    "derived/reconstruction/reconstruction_metrics.json",
    "derived/reconstruction/uncertainty_report.json",
    "derived/reconstruction/causal_graph.json",
    "derived/evidence_support/hypothesis_support_report.json",
    "derived/evidence_support/claimability_report.json",
    "derived/evidence_support/counter_evidence_report.json",
    "derived/evidence_support/forensic_storyline.json",
)

LIGHTWEIGHT_CASE_RETAIN_GLOBS: tuple[str, ...] = (
    "industrial/ot_export_*.json",
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


def _tree_size_bytes(root: Path) -> int:
    total = 0
    try:
        for item in root.rglob("*"):
            if not item.is_file():
                continue
            try:
                total += item.stat().st_size
            except Exception:
                continue
    except Exception:
        return 0
    return total


def _copy_tree_contents(source_root: Path, target_root: Path) -> None:
    for source in source_root.rglob("*"):
        if not source.is_file():
            continue
        target = target_root / source.relative_to(source_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def _copy_lightweight_case_bundle(*, original_case_path: Path, execution_base: Path, case_id: str) -> dict:
    bundle_root = execution_base / "retained_case_lightweight_bundle" / case_id
    copied_files: list[str] = []
    missing_files: list[str] = []
    copied_rel_paths: set[str] = set()
    for rel_path in LIGHTWEIGHT_CASE_RETAIN_PATHS:
        source = original_case_path / rel_path
        if not source.is_file():
            missing_files.append(rel_path)
            continue
        target = bundle_root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        copied_files.append(relative_path(target))
        copied_rel_paths.add(rel_path.replace("\\", "/"))
    for pattern in LIGHTWEIGHT_CASE_RETAIN_GLOBS:
        matched = False
        for source in original_case_path.glob(pattern):
            if not source.is_file():
                continue
            rel_path = source.relative_to(original_case_path).as_posix()
            if rel_path in copied_rel_paths:
                continue
            target = bundle_root / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            copied_files.append(relative_path(target))
            copied_rel_paths.add(rel_path)
            matched = True
        if not matched:
            missing_files.append(pattern)
    manifest = {
        "generated_at": utc_now(),
        "case_id": case_id,
        "source_case_path": relative_path(original_case_path),
        "bundle_root": relative_path(bundle_root),
        "copied_files": copied_files,
        "missing_optional_files": missing_files,
        "purpose": "Preserve lightweight per-layer analysis evidence after heavy generated-case cleanup.",
    }
    manifest_path = bundle_root / "lightweight_case_bundle_manifest.json"
    _write_json(manifest_path, manifest)
    manifest["bundle_size_bytes"] = _tree_size_bytes(bundle_root)
    manifest["bundle_size_limit_bytes"] = LIGHTWEIGHT_CASE_MAX_BYTES
    manifest["manifest_path"] = relative_path(manifest_path)
    _write_json(manifest_path, manifest)
    return manifest


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


def _ensure_comparison_registry_entry(result_card: dict | None) -> tuple[dict | None, bool]:
    if not isinstance(result_card, dict):
        return None, False
    existing = _comparison_registry_entry(result_card.get("result_card_id"))
    if isinstance(existing, dict):
        return existing, False
    try:
        from .comparison_registry import append_to_registry

        registry = append_to_registry(result_card)
        repaired = next(
            (item for item in registry.get("entries", []) if item.get("result_card_id") == result_card.get("result_card_id")),
            None,
        )
        return repaired, isinstance(repaired, dict)
    except Exception:
        return None, False


def _load_case_reconstruction_metrics(original_case_path: Path | None) -> dict | None:
    return _json_load(original_case_path / "derived/reconstruction/reconstruction_metrics.json") if original_case_path else None


def _load_case_causal_status(original_case_path: Path | None) -> dict | None:
    return _json_load(original_case_path / "derived/reconstruction/causal_status.json") if original_case_path else None


def _repair_causal_summary(
    causal_summary: dict | None,
    *,
    original_case_path: Path | None,
    case_id: str | None,
) -> tuple[dict, list[str]]:
    summary = dict(causal_summary or {})
    repairs: list[str] = []
    has_metrics = summary.get("cpr") is not None and summary.get("weighted_cpr") is not None
    if has_metrics:
        return summary, repairs

    metrics = _load_case_reconstruction_metrics(original_case_path)
    status_payload = _load_case_causal_status(original_case_path)
    if isinstance(metrics, dict):
        summary.setdefault("status", "completed_with_degradation" if metrics.get("main_limitation") else "completed")
        summary["expected_edges"] = metrics.get("expected_edges")
        summary["recovered_edges"] = metrics.get("recovered_edges")
        summary["degraded_edges"] = metrics.get("degraded_edges")
        summary["ambiguous_edges"] = metrics.get("ambiguous_edges")
        summary["missing_edges"] = metrics.get("missing_edges")
        summary["cpr"] = metrics.get("causal_path_recoverability", metrics.get("cpr"))
        summary["weighted_cpr"] = metrics.get("weighted_cpr")
        summary["reconstruction_confidence"] = metrics.get("reconstruction_confidence")
        summary["main_limitation"] = metrics.get("main_limitation")
        if summary.get("cpr") is not None and summary.get("weighted_cpr") is not None:
            repairs.append(
                f"Causal metrics were recovered from {relative_path(original_case_path / 'derived/reconstruction/reconstruction_metrics.json')}"
                if original_case_path
                else "Causal metrics were recovered from preserved reconstruction metrics."
            )
    if isinstance(status_payload, dict):
        summary["status"] = status_payload.get("status") or status_payload.get("state") or summary.get("status")
        summary["main_limitation"] = summary.get("main_limitation") or status_payload.get("reason")
    if case_id and repairs:
        summary.setdefault("repair_note", f"Causal metrics for {case_id} were inferred from preserved reconstruction outputs because the execution profile had not been refreshed after lifecycle completion.")
    return summary, repairs


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
    comparison_entry, comparison_registry_repaired = _ensure_comparison_registry_entry(result_card)
    preservation_summary = (result_card or {}).get("preservation_summary") or ((comparison_profile or {}).get("preservation") or {})
    chain_of_custody_summary = (case_result_card or {}).get("chain_of_custody_summary") or {}
    analysis_summary = (comparison_profile or {}).get("multilayer_analysis") or {}
    causal_summary, causal_repairs = _repair_causal_summary(
        (comparison_profile or {}).get("causal_reconstruction") or {},
        original_case_path=original_case_path,
        case_id=case_id,
    )
    if isinstance(comparison_profile, dict):
        comparison_profile["causal_reconstruction"] = causal_summary
    uncertainty_summary = (comparison_profile or {}).get("uncertainty") or {}
    hypothesis_summary = (comparison_profile or {}).get("hypothesis_support") or {}
    final_conclusion = (comparison_profile or {}).get("final_conclusion") or {}
    original_hashes = {
        "manifest_hash": (case_result_card or {}).get("manifest_hash"),
        "case_digest_hash": (case_result_card or {}).get("case_digest_hash"),
    }
    trigger_alert_binding_path = original_case_path / "metadata" / "trigger_alert_binding.json" if original_case_path else None
    forensic_intervention_path = original_case_path / "metadata" / "forensic_intervention.json" if original_case_path else None
    normalized_timestamps_path = original_case_path / "metadata" / "normalized_causal_timestamps.json" if original_case_path else None
    critical_gate_path = original_case_path / "metadata" / "critical_evidence_gate.json" if original_case_path else None

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
        _bool_check(
            "trigger_alert_binding",
            bool(trigger_alert_binding_path and trigger_alert_binding_path.is_file()),
            "The raw trigger-to-case binding must survive cleanup because later reporting and causal reconstruction depend on it.",
            "Persist metadata/trigger_alert_binding.json before cleanup.",
        ),
        _bool_check(
            "forensic_intervention",
            bool(forensic_intervention_path and forensic_intervention_path.is_file()),
            "The explicit forensic intervention artifact must survive cleanup because it links alert, intervention, and preserved case.",
            "Persist metadata/forensic_intervention.json before cleanup.",
        ),
        _bool_check(
            "normalized_causal_timestamps",
            bool(normalized_timestamps_path and normalized_timestamps_path.is_file()),
            "Normalized causal timestamps must survive cleanup because degraded relations depend on them.",
            "Persist metadata/normalized_causal_timestamps.json before cleanup.",
        ),
        _bool_check(
            "critical_evidence_gate",
            bool(critical_gate_path and critical_gate_path.is_file()),
            "The critical evidence gate result must survive cleanup so the case keeps its scientific-readiness classification.",
            "Persist metadata/critical_evidence_gate.json before cleanup.",
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
        "auto_repairs": [
            *(
                ["Comparison registry entry was auto-registered from the preserved forensic result card."]
                if comparison_registry_repaired
                else []
            ),
            *causal_repairs,
        ],
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
    lightweight_bundle = _copy_lightweight_case_bundle(
        original_case_path=original_case_path,
        execution_base=base,
        case_id=str(context["case_id"] or "case"),
    )
    if int(lightweight_bundle.get("bundle_size_bytes") or 0) > LIGHTWEIGHT_CASE_MAX_BYTES:
        return {
            "error": "lightweight_bundle_exceeds_limit",
            "message": (
                "The lightweight audit bundle exceeds the maximum retained size. "
                "Heavy-case cleanup was aborted to preserve scientific traceability without violating the retention cap."
            ),
            "bundle_size_bytes": int(lightweight_bundle.get("bundle_size_bytes") or 0),
            "bundle_size_limit_bytes": LIGHTWEIGHT_CASE_MAX_BYTES,
            "lightweight_case_bundle_manifest_path": lightweight_bundle.get("manifest_path"),
        }
    preserved_profiles.append(lightweight_bundle.get("manifest_path"))

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
    lightweight_case_audit_path = None
    case_shell_path = None
    if action_type == "archive_case_directory":
        ARCHIVED_CASES_ROOT.mkdir(parents=True, exist_ok=True)
        archive_target = ARCHIVED_CASES_ROOT / f"{original_case_path.name}__archived_{utc_now().replace(':', '').replace('-', '')}"
        shutil.move(str(original_case_path), str(archive_target))
    else:
        shutil.rmtree(original_case_path)
        original_case_path.mkdir(parents=True, exist_ok=True)
        bundle_root = Path.cwd() / str(lightweight_bundle.get("bundle_root") or "")
        if bundle_root.is_dir():
            _copy_tree_contents(bundle_root, original_case_path)
        retention_audit = {
            "generated_at": utc_now(),
            "case_id": context["case_id"],
            "cleanup_status": "completed",
            "case_state": "lightweight_audit_only",
            "heavy_artifacts_deleted_by_platform": True,
            "heavy_artifacts_deletion_reason": "Free disk space for future captures and analyses while preserving scientific auditability.",
            "heavy_artifacts_deleted_is_not_tampering": True,
            "lightweight_case_size_limit_bytes": LIGHTWEIGHT_CASE_MAX_BYTES,
            "lightweight_case_size_bytes": _tree_size_bytes(original_case_path),
            "retained_bundle_manifest_path": lightweight_bundle.get("manifest_path"),
            "retained_bundle_path": lightweight_bundle.get("bundle_root"),
            "retained_categories": [
                "manifest_and_custody",
                "critical_evidence_gate",
                "trigger_alert_binding",
                "forensic_intervention",
                "normalized_timestamps",
                "pipeline_events",
                "network_context_manifest",
                "analysis_outputs",
                "causal_reconstruction_outputs",
                "hashes_and_retention_manifests",
            ],
            "excluded_heavy_categories": [
                "memory_dumps",
                "disk_images",
                "raw_network_captures",
            ],
            "operator": operator,
        }
        lightweight_case_audit_path = original_case_path / "metadata" / "lightweight_retention_audit.json"
        _write_json(lightweight_case_audit_path, retention_audit)
        case_shell_path = original_case_path

    causal_summary = (comparison_profile or {}).get("causal_reconstruction") or {}
    if isinstance(result_card, dict):
        if result_card.get("CPR") is None and causal_summary.get("cpr") is not None:
            result_card["CPR"] = causal_summary.get("cpr")
        if result_card.get("Weighted_CPR") is None and causal_summary.get("weighted_cpr") is not None:
            result_card["Weighted_CPR"] = causal_summary.get("weighted_cpr")
        if result_card.get("recovered_edges") is None and causal_summary.get("recovered_edges") is not None:
            result_card["recovered_edges"] = causal_summary.get("recovered_edges")
        if result_card.get("degraded_edges") is None and causal_summary.get("degraded_edges") is not None:
            result_card["degraded_edges"] = causal_summary.get("degraded_edges")
        if result_card.get("missing_edges") is None and causal_summary.get("missing_edges") is not None:
            result_card["missing_edges"] = causal_summary.get("missing_edges")

    result_card["heavy_artifacts_retained"] = action_type == "archive_case_directory"
    result_card["heavy_artifacts_location"] = relative_path(archive_target) if archive_target else None
    result_card["lightweight_case_bundle_path"] = lightweight_bundle.get("bundle_root")
    case_result_card["heavy_artifacts_retained"] = action_type == "archive_case_directory"
    case_result_card["retention_policy"] = result_card.get("retention_policy") or "profiles_only_after_archive"
    case_result_card["lightweight_case_bundle_path"] = lightweight_bundle.get("bundle_root")
    execution_manifest["heavy_artifacts_retained"] = action_type == "archive_case_directory"
    execution_manifest["cleanup_status"] = "completed"
    execution_manifest["cleanup_action_type"] = action_type
    execution_manifest["heavy_artifacts_location_before_action"] = original_case_rel
    execution_manifest["heavy_artifacts_location_after_action"] = relative_path(archive_target) if archive_target else None
    execution_manifest["lightweight_case_bundle_path"] = lightweight_bundle.get("bundle_root")
    execution_manifest["lightweight_case_shell_path"] = relative_path(case_shell_path) if case_shell_path else None
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
            "preserved_lightweight_case_bundle_path": lightweight_bundle.get("bundle_root"),
            "preserved_lightweight_case_bundle_manifest_path": lightweight_bundle.get("manifest_path"),
            "original_case_path": original_case_rel,
            "heavy_artifacts_location_before_action": original_case_rel,
            "heavy_artifacts_location_after_action": relative_path(archive_target) if archive_target else None,
            "cleanup_status": "completed",
            "cleanup_warnings": list(context.get("auto_repairs") or []),
            "lightweight_case_shell_path": relative_path(case_shell_path) if case_shell_path else None,
            "lightweight_case_audit_path": relative_path(lightweight_case_audit_path) if lightweight_case_audit_path else None,
        }
    )

    _write_json(base / "forensic_comparison_profile.json", comparison_profile)
    _write_json(base / "forensic_result_card.json", result_card)
    _write_json(base / "execution_manifest.json", execution_manifest)
    try:
        from .comparison_registry import append_to_registry

        append_to_registry(result_card)
    except Exception:
        pass
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
        "lightweight_case_bundle_path": lightweight_bundle.get("bundle_root"),
        "lightweight_case_bundle_manifest_path": lightweight_bundle.get("manifest_path"),
        "lightweight_case_shell_path": relative_path(case_shell_path) if case_shell_path else None,
        "lightweight_case_audit_path": relative_path(lightweight_case_audit_path) if lightweight_case_audit_path else None,
        "message": "Heavy generated-case artifacts were cleaned up. A lightweight audit-only case shell and scientific comparison memory were preserved.",
    }
