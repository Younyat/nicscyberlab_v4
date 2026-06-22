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

    max_clock_offset_seconds = round(max_offset_ms / 1000.0, 3)
    uncertainty_window_seconds = round(uncertainty_window_ms / 1000.0, 3)
    if not temporal_report:
        temporal_limitation = "Temporal uncertainty remains unknown because time synchronization evidence is unavailable."
    elif not synchronized:
        temporal_limitation = (
            f"Temporal synchronization is not reliable. The preserved max clock offset is approximately "
            f"{max_clock_offset_seconds:g}s, which makes event ordering ambiguous for causal edges whose "
            f"timestamps fall within the {uncertainty_window_seconds:g}s uncertainty window."
        )
    else:
        temporal_limitation = (
            f"The environment was synchronized; the preserved uncertainty window is approximately "
            f"{uncertainty_window_seconds:g}s."
        )

    temporal_warning = None
    temporal_caution = None
    if temporal_confidence_state in {"ambiguous", "limited"} and max_clock_offset_seconds > 0:
        temporal_warning = (
            f"Temporal ordering is weak because the preserved clock offset is approximately "
            f"{max_clock_offset_seconds:.0f} seconds."
        )
        temporal_caution = (
            "Causal direction for time-dependent edges must be interpreted with caution because event "
            "ordering falls under a large uncertainty window."
        )

    expected_artifacts = list(case_context.get("ground_truth", {}).get("expected_artifacts") or [])
    recovered_expected_artifacts = int(metrics.get("recovered_expected_artifacts") or 0)
    missing_expected_artifacts = [item for item in expected_artifacts if item not in set(metrics.get("recovered_expected_artifact_types") or [])]
    used_refs = {ref for edge in edges for ref in edge.get("evidence_refs", []) if ref}
    verified_refs = {ref for ref in used_refs if ref != "not_available"}

    custody_context = case_context.get("custody_context") or {}
    manifest_total = int(custody_context.get("manifest_artifacts_total") or 0)
    hash_validated = int(custody_context.get("hash_validated_artifacts") or 0)
    custody_chain_valid = bool(custody_context.get("custody_chain_valid"))
    missing_artifacts = list(dict.fromkeys(custody_context.get("missing_artifacts") or []))
    graph_scope_integrity_ratio = round((len(verified_refs) / len(used_refs)), 4) if used_refs else None
    case_wide_integrity_ratio = round((hash_validated / manifest_total), 4) if manifest_total else None

    # Split, per the user's spec, into what the graph itself uses (narrow,
    # often verifiable) vs the case-wide manifest validation (broad, often
    # partial because large memory/disk dumps are hash-skipped by policy).
    # These two scopes answer different questions and must not be blended
    # into one verdict the way the previous single `integrity_status` did.
    graph_artifact_integrity_status = "verified" if (not used_refs or len(verified_refs) == len(used_refs)) else "partial"
    case_wide_integrity_status = "verified" if (case_wide_integrity_ratio == 1.0 and custody_chain_valid and not missing_artifacts) else "partial"
    integrity_status = case_wide_integrity_status  # kept for backward compatibility with existing CSV/markdown/JS

    if graph_artifact_integrity_status == "verified" and case_wide_integrity_status == "partial":
        integrity_limitation = "All graph-referenced artifacts are present, but the case-wide manifest validation is partial."
    elif graph_artifact_integrity_status == "verified" and case_wide_integrity_status == "verified":
        integrity_limitation = "All graph-referenced artifacts are present, and the case-wide manifest validation is verified."
    elif graph_artifact_integrity_status == "partial" and case_wide_integrity_status == "verified":
        integrity_limitation = (
            f"Some artifacts referenced by the causal graph are not accounted for ({len(verified_refs)}/{len(used_refs)}), "
            "even though the case-wide manifest validation is verified."
        )
    else:
        integrity_limitation = (
            f"Some artifacts referenced by the causal graph are not accounted for ({len(verified_refs)}/{len(used_refs)}), "
            "and the case-wide manifest validation is also partial."
        )

    limitations: list[str] = []
    if not temporal_report:
        limitations.append("Temporal uncertainty remains unknown because time synchronization evidence is unavailable.")
    elif not synchronized:
        limitations.append("Temporal uncertainty is high because preserved time synchronization indicates the environment was not synchronized.")
    if missing_expected_artifacts:
        limitations.append("Some expected scenario artifacts are unavailable for the causal reconstruction input set.")
    if int(metrics.get("missing_edges") or 0) > 0:
        limitations.append("One or more expected causal edges remain missing because required evidence could not be recovered or verified.")
    if case_wide_integrity_status == "partial" or graph_artifact_integrity_status == "partial":
        limitations.append(integrity_limitation)
    if temporal_warning:
        limitations.append(temporal_warning)

    return {
        "case_id": case_context.get("case_id"),
        "scenario_id": case_context.get("scenario_id"),
        "generated_at": case_context.get("generated_at"),
        "temporal": {
            "max_clock_offset_ms": max_offset_ms,
            "max_clock_offset_seconds": max_clock_offset_seconds,
            "timestamp_resolution_ms": timestamp_resolution_ms,
            "acquisition_jitter_ms": acquisition_jitter_ms,
            "uncertainty_window_ms": uncertainty_window_ms,
            "uncertainty_window_seconds": uncertainty_window_seconds,
            "synchronized": synchronized,
            "temporal_confidence_state": temporal_confidence_state,
            "temporal_limitation": temporal_limitation,
            "temporal_warning": temporal_warning,
            "temporal_caution": temporal_caution,
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
            "artifacts_used_by_graph": len(used_refs),
            "artifacts_present": len(verified_refs),
            "graph_scope_integrity_ratio": graph_scope_integrity_ratio,
            "case_manifest_artifacts_total": manifest_total,
            "case_manifest_hash_validated": hash_validated,
            "case_wide_integrity_ratio": case_wide_integrity_ratio,
            "custody_chain_valid": custody_chain_valid,
            "graph_artifact_integrity_status": graph_artifact_integrity_status,
            "case_wide_integrity_status": case_wide_integrity_status,
            "integrity_status": integrity_status,
            "integrity_limitation": integrity_limitation,
            # Kept for backward compatibility with the previous, less precise field name.
            "integrity_verification_ratio": case_wide_integrity_ratio,
            "verified_artifacts_used_by_graph": len(verified_refs),
        },
        "acquisition": {
            "manifest_present": case_context.get("custody_context", {}).get("manifest_present"),
            "chain_of_custody_present": case_context.get("custody_context", {}).get("chain_of_custody_present"),
            "case_manifest_link_present": bool(case_context.get("custody_context", {}).get("case_links_for_case")),
            "analysis_coverage_ratio": metrics.get("analysis_coverage_ratio"),
        },
        "limitations": limitations,
    }
