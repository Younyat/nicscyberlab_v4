from __future__ import annotations

from ..config import (
    ALLOWED_TEMPORAL_CONFIDENCE_STATES,
    DEFAULT_ACQUISITION_JITTER_MS,
    DEFAULT_TIMESTAMP_RESOLUTION_MS,
)


def build_uncertainty_report(case_context: dict, metrics: dict, edges: list[dict]) -> dict:
    temporal_report = case_context.get("timeline_context", {}).get("temporal_report") or {}
    findings = temporal_report.get("findings") if isinstance(temporal_report, dict) else {}
    max_offset_ms = float(findings.get("max_offset_ms") or 0.0)
    timestamp_resolution_ms = float(case_context.get("ground_truth", {}).get("timestamp_resolution_ms") or DEFAULT_TIMESTAMP_RESOLUTION_MS)
    acquisition_jitter_ms = float(case_context.get("ground_truth", {}).get("acquisition_jitter_ms") or DEFAULT_ACQUISITION_JITTER_MS)
    uncertainty_window_ms = max_offset_ms + timestamp_resolution_ms + acquisition_jitter_ms
    synchronized = bool(findings.get("synchronized")) if isinstance(findings, dict) else False

    if not temporal_report:
        temporal_confidence_state = "unknown"
    elif not synchronized:
        temporal_confidence_state = "ambiguous" if max_offset_ms > 0 else "limited"
    elif uncertainty_window_ms <= 1000:
        temporal_confidence_state = "strong"
    elif uncertainty_window_ms <= 60000:
        temporal_confidence_state = "limited"
    else:
        temporal_confidence_state = "ambiguous"
    if temporal_confidence_state not in ALLOWED_TEMPORAL_CONFIDENCE_STATES:
        temporal_confidence_state = "unknown"

    expected_artifacts = list(case_context.get("ground_truth", {}).get("expected_artifacts") or [])
    recovered_expected_artifacts = int(metrics.get("recovered_expected_artifacts") or 0)
    missing_expected_artifacts = [item for item in expected_artifacts if item not in set(metrics.get("recovered_expected_artifact_types") or [])]
    used_refs = {ref for edge in edges for ref in edge.get("evidence_refs", []) if ref}
    verified_refs = {ref for ref in used_refs if ref != "not_available"}

    limitations: list[str] = []
    if not temporal_report:
        limitations.append("Temporal uncertainty remains unknown because time synchronization evidence is unavailable.")
    elif not synchronized:
        limitations.append("Temporal uncertainty is high because preserved time synchronization indicates the environment was not synchronized.")
    if missing_expected_artifacts:
        limitations.append("Some expected scenario artifacts are unavailable for the causal reconstruction input set.")
    if int(metrics.get("missing_edges") or 0) > 0:
        limitations.append("One or more expected causal edges remain missing because required evidence could not be recovered or verified.")

    return {
        "case_id": case_context.get("case_id"),
        "scenario_id": case_context.get("scenario_id"),
        "generated_at": case_context.get("generated_at"),
        "temporal": {
            "max_clock_offset_ms": max_offset_ms,
            "timestamp_resolution_ms": timestamp_resolution_ms,
            "acquisition_jitter_ms": acquisition_jitter_ms,
            "uncertainty_window_ms": uncertainty_window_ms,
            "synchronized": synchronized,
            "temporal_confidence_state": temporal_confidence_state,
        },
        "completeness": {
            "expected_artifacts": len(expected_artifacts),
            "recovered_expected_artifacts": recovered_expected_artifacts,
            "missing_expected_artifacts": missing_expected_artifacts,
            "evidence_completeness_ratio": metrics.get("evidence_completeness_ratio"),
        },
        "causal": {
            "expected_edges": metrics.get("expected_edges"),
            "recovered_edges": metrics.get("recovered_edges"),
            "degraded_edges": metrics.get("degraded_edges"),
            "ambiguous_edges": metrics.get("ambiguous_edges"),
            "missing_edges": metrics.get("missing_edges"),
            "causal_path_recoverability": metrics.get("causal_path_recoverability"),
            "weighted_cpr": metrics.get("weighted_cpr"),
        },
        "integrity": {
            "integrity_verification_ratio": metrics.get("integrity_verification_ratio"),
            "verified_artifacts_used_by_graph": len(verified_refs),
            "artifacts_used_by_graph": len(used_refs),
        },
        "acquisition": {
            "manifest_present": case_context.get("custody_context", {}).get("manifest_present"),
            "chain_of_custody_present": case_context.get("custody_context", {}).get("chain_of_custody_present"),
            "case_manifest_link_present": bool(case_context.get("custody_context", {}).get("case_links_for_case")),
            "analysis_coverage_ratio": metrics.get("analysis_coverage_ratio"),
        },
        "limitations": limitations,
    }
