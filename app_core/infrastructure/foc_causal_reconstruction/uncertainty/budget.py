from __future__ import annotations

from ..config import (
    ALLOWED_TEMPORAL_CONFIDENCE_STATES,
    DEFAULT_ACQUISITION_JITTER_MS,
    DEFAULT_TIMESTAMP_RESOLUTION_MS,
)


def extract_temporal_sync_context(case_context: dict) -> dict:
    timeline_context = case_context.get("timeline_context", {}) or {}
    analysis_summary = case_context.get("analysis_summary", {}) or {}
    time_sync = timeline_context.get("time_sync") or analysis_summary.get("time_sync") or {}
    time_sync_before = timeline_context.get("time_sync_before") or analysis_summary.get("time_sync_before") or {}
    time_sync_after = timeline_context.get("time_sync_after") or analysis_summary.get("time_sync_after") or {}
    temporal_report = timeline_context.get("temporal_report") or analysis_summary.get("temporal_report") or {}
    findings = temporal_report.get("findings") if isinstance(temporal_report, dict) else {}

    payload = time_sync if isinstance(time_sync, dict) else {}
    before = time_sync_before if isinstance(time_sync_before, dict) else {}
    after = time_sync_after if isinstance(time_sync_after, dict) else {}

    max_offset_ms = (
        payload.get("max_clock_offset_ms")
        or payload.get("max_offset_ms")
        or (after.get("max_clock_offset_ms") if isinstance(after, dict) else None)
        or findings.get("max_clock_offset_ms")
        or findings.get("max_offset_ms")
        or 0.0
    )
    try:
        max_offset_ms = float(max_offset_ms or 0.0)
    except Exception:
        max_offset_ms = 0.0

    sync_state = str(
        payload.get("temporal_sync_status")
        or payload.get("synchronization_status")
        or ""
    ).strip().lower()
    if sync_state not in {"synchronized", "degraded", "not_synchronized", "unknown"}:
        if isinstance(payload.get("synchronized"), bool):
            sync_state = "synchronized" if payload.get("synchronized") else "not_synchronized"
        elif isinstance(findings.get("synchronized"), bool):
            sync_state = "synchronized" if findings.get("synchronized") else "not_synchronized"
        else:
            sync_state = "unknown" if not payload and not findings else "not_synchronized"

    synchronized = sync_state == "synchronized"
    threshold_ms = payload.get("synchronization_threshold_ms") or payload.get("threshold_ms") or 1000
    degraded_threshold_ms = payload.get("degraded_threshold_ms") or 5000
    correction_applied = bool(payload.get("correction_applied") or payload.get("do_fix_time"))
    worst_node = payload.get("worst_node") if isinstance(payload.get("worst_node"), dict) else {}
    nodes_ok = int(payload.get("nodes_ok") or 0)
    nodes_failed = int(payload.get("nodes_failed") or 0)

    return {
        "source": "time_sync_json" if payload else ("clock_offset_report" if temporal_report else "none"),
        "payload": payload,
        "before": before,
        "after": after,
        "temporal_report": temporal_report if isinstance(temporal_report, dict) else {},
        "max_clock_offset_ms": max_offset_ms,
        "sync_state": sync_state,
        "synchronized": synchronized,
        "threshold_ms": threshold_ms,
        "degraded_threshold_ms": degraded_threshold_ms,
        "correction_applied": correction_applied,
        "worst_node": worst_node if isinstance(worst_node, dict) else {},
        "nodes_ok": nodes_ok,
        "nodes_failed": nodes_failed,
    }


_STATE_SEVERITY = {"strong": 3, "limited": 2, "ambiguous": 1, "unknown": 0}


def _coverage_state(ratio_full: bool, ratio_zero: bool) -> str:
    if ratio_zero:
        return "none"
    if ratio_full:
        return "full"
    return "partial"


def _evidence_timestamp_coverage(edges: list[dict]) -> dict:
    # A clock can be perfectly synchronized while individual artifacts still
    # lack a usable timestamp for a given causal edge - these are two
    # different questions. "Declared" edges are the ones whose ground-truth
    # spec actually requires a temporal comparison (temporal_status is not
    # "not_required"); "resolved" is how many of those produced a real
    # supported/ambiguous/contradicted comparison instead of "unknown".
    declared = [e for e in edges if str(e.get("temporal_status") or "unknown") != "not_required"]
    resolved = [e for e in declared if str(e.get("temporal_status")) in {"supported", "ambiguous", "contradicted"}]
    clearly_ordered = [e for e in resolved if str(e.get("temporal_status")) == "supported"]

    availability = (
        "not_applicable" if not declared else _coverage_state(len(resolved) == len(declared), len(resolved) == 0)
    )
    resolvability = (
        "not_applicable" if not resolved else _coverage_state(len(clearly_ordered) == len(resolved), len(clearly_ordered) == 0)
    )
    return {
        "edges_with_declared_timestamps": len(declared),
        "edges_with_resolved_timestamps": len(resolved),
        "edges_with_clear_temporal_order": len(clearly_ordered),
        "evidence_timestamp_availability": availability,
        "evidence_timestamp_resolvability": resolvability,
    }


def build_uncertainty_report(case_context: dict, metrics: dict, edges: list[dict]) -> dict:
    temporal_context = extract_temporal_sync_context(case_context)
    temporal_report = temporal_context.get("temporal_report") or {}
    max_offset_ms = float(temporal_context.get("max_clock_offset_ms") or 0.0)
    timestamp_resolution_ms = float(case_context.get("ground_truth", {}).get("timestamp_resolution_ms") or DEFAULT_TIMESTAMP_RESOLUTION_MS)
    acquisition_jitter_ms = float(case_context.get("ground_truth", {}).get("acquisition_jitter_ms") or DEFAULT_ACQUISITION_JITTER_MS)
    uncertainty_window_ms = max_offset_ms + timestamp_resolution_ms + acquisition_jitter_ms
    synchronized = bool(temporal_context.get("synchronized"))
    sync_state = str(temporal_context.get("sync_state") or "unknown")

    if sync_state == "unknown" and not temporal_report and not temporal_context.get("payload"):
        temporal_confidence_state = "unknown"
    elif sync_state == "not_synchronized":
        temporal_confidence_state = "ambiguous" if max_offset_ms > 0 else "limited"
    elif sync_state == "degraded":
        temporal_confidence_state = "limited"
    elif uncertainty_window_ms <= 1000:
        temporal_confidence_state = "strong"
    elif uncertainty_window_ms <= 60000:
        temporal_confidence_state = "limited"
    else:
        temporal_confidence_state = "ambiguous"
    if temporal_confidence_state not in ALLOWED_TEMPORAL_CONFIDENCE_STATES:
        temporal_confidence_state = "unknown"
    clock_based_temporal_state = temporal_confidence_state

    # Node clock synchronization is a property of the infrastructure;
    # evidence timestamp availability/resolvability is a property of the
    # preserved artifacts themselves. A synchronized infrastructure does not
    # automatically mean that all forensic artifacts contain usable
    # timestamps for causal ordering, so the final causal_temporal_ordering
    # confidence must take the worst of both signals, not the clock alone.
    timestamp_coverage = _evidence_timestamp_coverage(edges)
    declared_count = timestamp_coverage["edges_with_declared_timestamps"]
    resolved_count = timestamp_coverage["edges_with_resolved_timestamps"]
    availability_state = timestamp_coverage["evidence_timestamp_availability"]
    resolvability_state = timestamp_coverage["evidence_timestamp_resolvability"]

    _IMPLIED_STATE = {"full": "strong", "partial": "limited", "none": "ambiguous"}
    candidates = [("clock_synchronization", clock_based_temporal_state)]
    if declared_count and availability_state != "not_applicable":
        candidates.append(("evidence_timestamp_availability", _IMPLIED_STATE[availability_state]))
    if resolved_count and resolvability_state != "not_applicable":
        candidates.append(("evidence_timestamp_resolvability", _IMPLIED_STATE[resolvability_state]))

    # The final confidence is the worst of all signals - a synchronized
    # clock cannot compensate for artifacts that lack usable timestamps.
    # Ties prefer naming the evidence-side factor over the clock, since that
    # is the more actionable explanation for the user.
    candidates.sort(key=lambda pair: (_STATE_SEVERITY.get(pair[1], 0), pair[0] == "clock_synchronization"))
    limiting_factor, causal_temporal_ordering_confidence = candidates[0]
    if causal_temporal_ordering_confidence not in ALLOWED_TEMPORAL_CONFIDENCE_STATES:
        causal_temporal_ordering_confidence = "unknown"

    if limiting_factor in {"evidence_timestamp_availability", "evidence_timestamp_resolvability"}:
        causal_temporal_ordering_reason = (
            "Some causal edges could not be temporally ordered because the required artifact timestamps "
            "were not available or not resolvable."
        )
    elif declared_count == 0:
        causal_temporal_ordering_reason = (
            "No causal edge in this case declares a required timestamp comparison, so causal temporal "
            "ordering confidence reflects clock synchronization quality only."
        )
    else:
        causal_temporal_ordering_reason = None  # filled in below once temporal_limitation is computed
    temporal_confidence_state = causal_temporal_ordering_confidence  # kept for backward compatibility

    max_clock_offset_seconds = round(max_offset_ms / 1000.0, 3)
    uncertainty_window_seconds = round(uncertainty_window_ms / 1000.0, 3)
    if sync_state == "unknown" and not temporal_report and not temporal_context.get("payload"):
        temporal_limitation = "Temporal uncertainty remains unknown because time synchronization evidence is unavailable."
    elif sync_state == "not_synchronized":
        temporal_limitation = (
            f"Temporal synchronization is not reliable. The preserved max clock offset is approximately "
            f"{max_clock_offset_seconds:g}s, which makes event ordering ambiguous for causal edges whose "
            f"timestamps fall within the {uncertainty_window_seconds:g}s uncertainty window."
        )
    elif sync_state == "degraded":
        temporal_limitation = (
            f"Temporal synchronization is only partially reliable. The preserved max clock offset is approximately "
            f"{max_clock_offset_seconds:g}s, so near-simultaneous edges still require caution."
        )
    else:
        temporal_limitation = (
            f"The environment was synchronized; the preserved uncertainty window is approximately "
            f"{uncertainty_window_seconds:g}s."
        )

    if causal_temporal_ordering_reason is None:
        causal_temporal_ordering_reason = temporal_limitation

    temporal_model_note = (
        "A synchronized infrastructure does not automatically mean that all forensic artifacts contain "
        "usable timestamps for causal ordering."
    )

    temporal_warning = None
    temporal_caution = None
    if causal_temporal_ordering_confidence in {"ambiguous", "limited"}:
        if limiting_factor in {"evidence_timestamp_availability", "evidence_timestamp_resolvability"}:
            temporal_warning = causal_temporal_ordering_reason
        elif max_clock_offset_seconds > 0:
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
    if sync_state == "unknown" and not temporal_report and not temporal_context.get("payload"):
        limitations.append("Temporal uncertainty remains unknown because time synchronization evidence is unavailable.")
    elif sync_state == "not_synchronized":
        limitations.append("Temporal uncertainty is high because preserved time synchronization indicates the environment was not synchronized.")
    elif sync_state == "degraded":
        limitations.append("Temporal uncertainty is limited rather than strong because preserved synchronization remained degraded.")
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
            "temporal_sync_status": sync_state,
            "time_sync_source": temporal_context.get("source"),
            "synchronization_threshold_ms": temporal_context.get("threshold_ms"),
            "degraded_threshold_ms": temporal_context.get("degraded_threshold_ms"),
            "correction_applied": temporal_context.get("correction_applied"),
            "nodes_ok": temporal_context.get("nodes_ok"),
            "nodes_failed": temporal_context.get("nodes_failed"),
            "worst_node": temporal_context.get("worst_node"),
            "before": temporal_context.get("before") or {},
            "after": temporal_context.get("after") or {},
            "before_after_clock_correction_data_available": bool(temporal_context.get("before")) or bool(temporal_context.get("after")),
            # Four distinct questions that must not be collapsed into one
            # number: is the infrastructure clock synchronized; do the
            # preserved artifacts have timestamps at all; can those
            # timestamps be resolved into a usable comparison; and, given
            # both, how confident is the causal ordering itself.
            "node_clock_synchronization_status": sync_state,
            "evidence_timestamp_availability": availability_state,
            "evidence_timestamp_resolvability": resolvability_state,
            "causal_temporal_ordering_confidence": causal_temporal_ordering_confidence,
            "causal_temporal_ordering_reason": causal_temporal_ordering_reason,
            "causal_temporal_ordering_limiting_factor": limiting_factor,
            "temporal_model_note": temporal_model_note,
            "edges_with_declared_timestamps": declared_count,
            "edges_with_resolved_timestamps": resolved_count,
            "edges_with_clear_temporal_order": timestamp_coverage["edges_with_clear_temporal_order"],
            "clock_based_temporal_state": clock_based_temporal_state,
            # Kept for backward compatibility with the markdown/CSV/JS that
            # already read this field name; it is now an alias of the
            # combined causal_temporal_ordering_confidence, not the clock-only value.
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
