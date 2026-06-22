from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

from .config import (
    ALLOWED_CAUSAL_UI_STATES,
    DEFAULT_DERIVED_RELATIVE_DIR,
)
from .evaluators import evaluate_edges
from .graph import build_nodes_from_ground_truth
from .loaders import (
    load_analysis_summary,
    load_custody_context,
    load_foc_context,
    load_timeline_context,
    resolve_ground_truth,
)
from .reports import write_causal_outputs
from .schemas import CausalGraph
from .uncertainty import build_uncertainty_report
from ..foc_reconstruction.foc_paths import project_path, relative_path
from ..foc_reconstruction.foc_sources import utc_now

_RUNNING_CAUSAL: dict[str, threading.Thread] = {}
_CAUSAL_LOCK = threading.Lock()


def _json_load(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _derived_dir(case_path: Path, out_dir: str | None = None) -> Path:
    if out_dir:
        candidate = Path(out_dir)
        return candidate if candidate.is_absolute() else case_path / candidate
    return case_path / DEFAULT_DERIVED_RELATIVE_DIR


def _status_path(case_path: Path) -> Path:
    return _derived_dir(case_path) / "causal_status.json"


def _paths(case_path: Path) -> dict:
    root = _derived_dir(case_path)
    return {
        "root": root,
        "status": root / "causal_status.json",
        "graph": root / "causal_graph.json",
        "uncertainty": root / "uncertainty_report.json",
        "metrics": root / "reconstruction_metrics.json",
        "csv": root / "causal_edges.csv",
        "report": root / "causal_reconstruction_report.md",
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "value"))


def _nested_get(payload, path: str):
    value = payload
    for part in str(path or "").split("."):
        if not part:
            continue
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


def _match_selector(item: dict, selector: dict | None) -> bool:
    if not selector:
        return True
    for key, expected in selector.items():
        actual = _nested_get(item, key)
        if key.endswith("_contains"):
            base_key = key[: -len("_contains")]
            actual = _nested_get(item, base_key)
            if isinstance(actual, list):
                if expected not in actual:
                    return False
            elif expected not in str(actual or ""):
                return False
            continue
        if key.endswith("_one_of"):
            base_key = key[: -len("_one_of")]
            actual = _nested_get(item, base_key)
            if actual not in list(expected or []):
                return False
            continue
        if str(actual) != str(expected):
            return False
    return True


def _resolve_timestamp(case_context: dict, ref: str | None) -> tuple[str | None, str | None]:
    if not ref:
        return None, None
    attack_records = (case_context.get("foc_context", {}).get("attack_attestation") or {}).get("attacks") or []
    interventions = (case_context.get("foc_context", {}).get("forensic_intervention") or {}).get("interventions") or []
    analysis_report = case_context.get("analysis_summary", {}).get("forensic_analysis_report") or {}
    mapping = {
        "attack_started_at": None,
        "attack_completed_at": None,
        "intervention_started_at": None,
        "intervention_completed_at": None,
        "analysis_started_at": case_context.get("analysis_status", {}).get("started_at"),
        "analysis_finished_at": case_context.get("analysis_status", {}).get("finished_at") or analysis_report.get("generated_at"),
        "case_created_at": None,
    }
    primary_attack = case_context.get("primary_attack") or {}
    if primary_attack:
        mapping["attack_started_at"] = _nested_get(primary_attack, "execution.started_at")
        mapping["attack_completed_at"] = _nested_get(primary_attack, "execution.completed_at")
    if interventions:
        mapping["intervention_started_at"] = interventions[0].get("intervention_start_time")
        mapping["intervention_completed_at"] = interventions[0].get("intervention_end_time")
    timeline = case_context.get("timeline_context", {}).get("timeline") or {}
    for event in timeline.get("events") or []:
        event_type = event.get("event_type")
        if event_type == "case_created" and not mapping["case_created_at"]:
            mapping["case_created_at"] = event.get("timestamp")
    source_map = {
        "attack_started_at": "foc-reconstruction/attestations/attack_attestation.json",
        "attack_completed_at": "foc-reconstruction/attestations/attack_attestation.json",
        "intervention_started_at": "foc-reconstruction/attestations/forensic_intervention.json",
        "intervention_completed_at": "foc-reconstruction/attestations/forensic_intervention.json",
        "analysis_started_at": relative_path(case_context["case_path"] / "analysis" / "analysis_status.json"),
        "analysis_finished_at": relative_path(case_context["case_path"] / "analysis" / "forensic_analysis_report.json"),
        "case_created_at": "foc-reconstruction/attestations/forensic_intervention.json",
    }
    return mapping.get(ref), source_map.get(ref)


def _parse_ts(value: str | None) -> float | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).timestamp()
    except Exception:
        return None


def _build_case_context(case_id: str, case_path: Path, analysis_status: dict | None = None, ground_truth_path: str | None = None) -> dict:
    foc_context = load_foc_context()
    analysis_summary = load_analysis_summary(case_path)
    custody_context = load_custody_context(case_path, foc_context, analysis_summary)
    timeline_context = load_timeline_context(case_path, analysis_summary)
    preserved_gt_ref = foc_context.get("artifact_references", {}).get("scenario_ground_truth")
    preserved_gt_path = project_path(*str(preserved_gt_ref).split("/")) if preserved_gt_ref else None
    gt_resolution = resolve_ground_truth(
        scenario_id=str(foc_context.get("scenario_id") or "unknown"),
        scenario_name=str(foc_context.get("scenario_name") or "unknown"),
        preserved_ground_truth_path=preserved_gt_path,
        explicit_path=ground_truth_path,
    )
    ground_truth = gt_resolution.get("payload") if isinstance(gt_resolution.get("payload"), dict) else {}
    primary_selector = ground_truth.get("attack_expected", {}).get("selector") if isinstance(ground_truth.get("attack_expected"), dict) else {}
    attacks = (foc_context.get("attack_attestation") or {}).get("attacks") or []
    primary_attack = next((item for item in attacks if isinstance(item, dict) and _match_selector(item, primary_selector)), None)
    return {
        "case_id": case_id,
        "case_path": case_path,
        "generated_at": utc_now(),
        "foc_context": foc_context,
        "analysis_summary": analysis_summary,
        "analysis_status": analysis_status or {},
        "custody_context": custody_context,
        "timeline_context": timeline_context,
        "ground_truth_resolution": gt_resolution,
        "ground_truth": ground_truth,
        "scenario_id": str(ground_truth.get("scenario_id") or foc_context.get("scenario_id") or "unknown"),
        "scenario_name": str(ground_truth.get("scenario_name") or foc_context.get("scenario_name") or "unknown"),
        "primary_attack": primary_attack,
    }


def _evaluate_requirement(case_context: dict, req_type: str, selector: dict | None) -> dict:
    foc_context = case_context.get("foc_context") or {}
    analysis_summary = case_context.get("analysis_summary") or {}
    custody_context = case_context.get("custody_context") or {}
    limitations: list[str] = []
    evidence_refs: list[str] = []

    if req_type == "attack_attestation":
        records = (foc_context.get("attack_attestation") or {}).get("attacks") or []
        matches = [item for item in records if isinstance(item, dict) and _match_selector(item, selector)]
        if matches:
            attack = matches[0]
            evidence_refs.append(f"foc-reconstruction/attestations/attack_attestation.json#{attack.get('attack_id')}")
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The preserved attack attestation does not contain a record matching the expected attack selector.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "detection_attestation":
        records = (foc_context.get("detection_attestation") or {}).get("observed_detection_rules") or []
        matches = [item for item in records if isinstance(item, dict) and _match_selector(item, selector)]
        if matches:
            item = matches[0]
            evidence_refs.append(f"foc-reconstruction/attestations/detection_attestation.json#{item.get('rule_id')}")
            status = "recovered" if bool(item.get("rule_active")) else "degraded"
            if status != "recovered":
                limitations.append("The detection rule was preserved but is not marked active in the normalized detection attestation.")
            return {"type": req_type, "status": status, "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("No normalized detection rule matched the expected selector.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "alert_correlation":
        records = (foc_context.get("alert_correlation") or {}).get("correlations") or (foc_context.get("alert_correlation") or {}).get("records") or []
        matches = [item for item in records if isinstance(item, dict) and _match_selector(item, selector)]
        if not matches:
            limitations.append("No preserved attack-to-alert correlation record matched the expected selector.")
            return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}
        item = matches[0]
        evidence_refs.append(f"foc-reconstruction/attestations/alert_correlation.json#{item.get('alert_id')}")
        relationship_status = str(item.get("relationship_status") or "").lower()
        correlation_status = str(item.get("correlation_status") or "").lower()
        if relationship_status == "confirmed" or correlation_status == "confirmed":
            status = "recovered"
        elif relationship_status == "inferred" or correlation_status.startswith("inferred") or correlation_status == "weak_candidate":
            status = "degraded"
            limitations.append("The preserved alert correlation is inferred rather than confirmed.")
        else:
            status = "missing"
            limitations.append("The preserved alert correlation is present but not strong enough to support the expected edge as recovered.")
        return {"type": req_type, "status": status, "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "forensic_intervention":
        records = (foc_context.get("forensic_intervention") or {}).get("interventions") or []
        matches = [item for item in records if isinstance(item, dict) and _match_selector(item, selector)]
        if not matches:
            limitations.append("No preserved forensic intervention matched the expected selector.")
            return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}
        item = matches[0]
        evidence_refs.append(f"foc-reconstruction/attestations/forensic_intervention.json#{item.get('case_id')}")
        status = "recovered" if str(item.get("intervention_status") or "").lower() == "completed" else "degraded"
        if status != "recovered":
            limitations.append("The forensic intervention exists but is not marked completed.")
        return {"type": req_type, "status": status, "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "case_manifest_link":
        links = custody_context.get("case_links_for_case") or []
        if links:
            evidence_refs.append("foc-reconstruction/attestations/case_manifest_link.json")
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The case-to-manifest linkage attestation does not include the selected case.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "manifest":
        if custody_context.get("manifest_present"):
            evidence_refs.append(relative_path(custody_context["manifest_path"]))
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The preserved case manifest is missing.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "chain_of_custody":
        if custody_context.get("chain_of_custody_present"):
            evidence_refs.append(relative_path(custody_context["chain_of_custody_path"]))
            status = "recovered" if custody_context.get("custody_chain_valid") else "degraded"
            if status != "recovered":
                limitations.append("The chain of custody exists but the preserved integrity report does not classify it as fully valid.")
            return {"type": req_type, "status": status, "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The preserved chain_of_custody.log is missing.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "forensic_analysis_report":
        report = analysis_summary.get("forensic_analysis_report") or {}
        if report:
            evidence_refs.append(relative_path(case_context["case_path"] / "analysis" / "forensic_analysis_report.json"))
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The multilayer forensic analysis report has not been generated for this case.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "analysis_visual_summary":
        visual = analysis_summary.get("analysis_visual_summary") or {}
        if visual:
            evidence_refs.append(relative_path(case_context["case_path"] / "analysis" / "visual" / "analysis_visual_summary.json"))
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("The normalized visual analysis summary is missing.")
        return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}

    if req_type == "memory_analysis_useful":
        findings = analysis_summary.get("memory_findings") or {}
        dumps_analysed = int(findings.get("dumps_analysed") or 0)
        evidence_refs.append(relative_path(case_context["case_path"] / "analysis" / "04_memory" / "memory_findings.json"))
        if dumps_analysed > 0:
            return {"type": req_type, "status": "recovered", "evidence_refs": evidence_refs, "limitations": limitations}
        limitations.append("Memory analysis exists but no effective dump analysis was recorded.")
        return {"type": req_type, "status": "degraded", "evidence_refs": evidence_refs, "limitations": limitations}

    limitations.append(f"The evaluator does not recognize requirement type `{req_type}`.")
    return {"type": req_type, "status": "missing", "evidence_refs": evidence_refs, "limitations": limitations}


def _evaluate_temporal(case_context: dict, edge_spec: dict) -> str:
    source_ref = edge_spec.get("source_timestamp_ref")
    target_ref = edge_spec.get("target_timestamp_ref")
    if not source_ref or not target_ref:
        return "unknown"
    source_ts, _ = _resolve_timestamp(case_context, str(source_ref))
    target_ts, _ = _resolve_timestamp(case_context, str(target_ref))
    src_value = _parse_ts(source_ts)
    dst_value = _parse_ts(target_ts)
    if src_value is None or dst_value is None:
        return "unknown"

    temporal_report = case_context.get("timeline_context", {}).get("temporal_report") or {}
    findings = temporal_report.get("findings") if isinstance(temporal_report, dict) else {}
    max_offset_ms = float(findings.get("max_offset_ms") or 0.0)
    timestamp_resolution_ms = float(case_context.get("ground_truth", {}).get("timestamp_resolution_ms") or 1000.0)
    acquisition_jitter_ms = float(case_context.get("ground_truth", {}).get("acquisition_jitter_ms") or 1000.0)
    uncertainty_seconds = (max_offset_ms + timestamp_resolution_ms + acquisition_jitter_ms) / 1000.0
    delta = dst_value - src_value
    if delta > uncertainty_seconds:
        return "supported"
    if abs(delta) <= uncertainty_seconds:
        return "ambiguous"
    return "contradicted"


def _analysis_coverage_ratio(case_context: dict) -> tuple[float | None, int, int]:
    expected_layers = list(case_context.get("ground_truth", {}).get("expected_analysis_layers") or [])
    if not expected_layers:
        return None, 0, 0
    visual = case_context.get("analysis_summary", {}).get("analysis_visual_summary") or {}
    layer_statuses = visual.get("layer_statuses") if isinstance(visual, dict) else {}
    useful = 0
    for layer in expected_layers:
        payload = layer_statuses.get(layer) if isinstance(layer_statuses, dict) else None
        if isinstance(payload, dict) and str(payload.get("effective_status")) == "completed_with_useful_output":
            useful += 1
    return useful / len(expected_layers), useful, len(expected_layers)


def _metrics_from_edges(case_context: dict, edges: list[dict]) -> dict:
    expected_edges = len(edges)
    recovered_edges = sum(1 for edge in edges if edge.get("support_status") == "recovered")
    degraded_edges = sum(1 for edge in edges if edge.get("support_status") == "degraded")
    ambiguous_edges = sum(1 for edge in edges if edge.get("support_status") == "ambiguous")
    missing_edges = sum(1 for edge in edges if edge.get("support_status") == "missing")

    weight_by_edge = {
        str(edge.get("edge_id")): float(spec.get("weight") or 1.0)
        for edge, spec in zip(edges, case_context.get("ground_truth", {}).get("expected_edges") or [])
    }
    total_weight = sum(weight_by_edge.values()) or 0.0
    recovered_weight = sum(weight_by_edge.get(str(edge.get("edge_id")), 1.0) for edge in edges if edge.get("support_status") == "recovered")

    expected_artifacts = list(case_context.get("ground_truth", {}).get("expected_artifacts") or [])
    recovered_expected_artifact_types: list[str] = []
    for item in expected_artifacts:
        result = _evaluate_requirement(case_context, str(item), None)
        if result.get("status") != "missing":
            recovered_expected_artifact_types.append(str(item))
    evidence_completeness_ratio = (len(recovered_expected_artifact_types) / len(expected_artifacts)) if expected_artifacts else None

    custody_context = case_context.get("custody_context") or {}
    manifest_total = int(custody_context.get("manifest_artifacts_total") or 0)
    validated = int(custody_context.get("hash_validated_artifacts") or 0)
    integrity_verification_ratio = (validated / manifest_total) if manifest_total else None
    analysis_coverage_ratio, layers_with_useful_output, expected_analysis_layers = _analysis_coverage_ratio(case_context)

    temporal_state = build_uncertainty_report(case_context, {}, edges)["temporal"]["temporal_confidence_state"]
    temporal_penalty = {"strong": 0.0, "limited": 0.05, "ambiguous": 0.12, "unknown": 0.15}.get(temporal_state, 0.15)
    base_confidence = (
        ((recovered_weight / total_weight) if total_weight else 0.0) * 0.45
        + (evidence_completeness_ratio or 0.0) * 0.2
        + (integrity_verification_ratio or 0.0) * 0.2
        + (analysis_coverage_ratio or 0.0) * 0.15
        - ((degraded_edges / expected_edges) if expected_edges else 0.0) * 0.08
        - ((ambiguous_edges / expected_edges) if expected_edges else 0.0) * 0.12
        - temporal_penalty
    )
    reconstruction_confidence = max(0.0, min(1.0, round(base_confidence, 4)))

    main_limitation = None
    if missing_edges:
        main_limitation = "One or more expected causal edges remain missing because required preserved evidence is unavailable or not linked."
    elif ambiguous_edges:
        main_limitation = "At least one causal edge is temporally ambiguous under the preserved uncertainty window."
    elif degraded_edges:
        main_limitation = "At least one causal edge is degraded because supporting evidence is partial or inferred."
    elif not case_context.get("custody_context", {}).get("custody_chain_valid"):
        main_limitation = "Integrity or custody validation remains partial for the artifacts used by the reconstruction."
    else:
        main_limitation = "The preserved evidence supports the reconstructed causal path within the controlled intervention model."

    return {
        "case_id": case_context.get("case_id"),
        "scenario_id": case_context.get("scenario_id"),
        "expected_edges": expected_edges,
        "recovered_edges": recovered_edges,
        "degraded_edges": degraded_edges,
        "ambiguous_edges": ambiguous_edges,
        "missing_edges": missing_edges,
        "causal_path_recoverability": round((recovered_edges / expected_edges), 4) if expected_edges else None,
        "weighted_cpr": round((recovered_weight / total_weight), 4) if total_weight else None,
        "degraded_edge_rate": round((degraded_edges / expected_edges), 4) if expected_edges else None,
        "ambiguous_edge_rate": round((ambiguous_edges / expected_edges), 4) if expected_edges else None,
        "missing_edge_rate": round((missing_edges / expected_edges), 4) if expected_edges else None,
        "recovered_expected_artifacts": len(recovered_expected_artifact_types),
        "recovered_expected_artifact_types": recovered_expected_artifact_types,
        "evidence_completeness_ratio": round(evidence_completeness_ratio, 4) if evidence_completeness_ratio is not None else None,
        "integrity_verification_ratio": round(integrity_verification_ratio, 4) if integrity_verification_ratio is not None else None,
        "analysis_coverage_ratio": round(analysis_coverage_ratio, 4) if analysis_coverage_ratio is not None else None,
        "layers_with_useful_output": layers_with_useful_output,
        "expected_analysis_layers": expected_analysis_layers,
        "temporal_confidence_state": temporal_state,
        "reconstruction_confidence": reconstruction_confidence,
        "main_limitation": main_limitation,
    }


def _markdown_report(case_context: dict, metrics: dict, uncertainty: dict, graph_payload: dict) -> str:
    lines = [
        f"# Causal Reconstruction Report for {case_context.get('case_id')}",
        "",
        "This report is a derived causal-forensic reconstruction from preserved FOC artifacts. It does not replace the primary evidence.",
        "",
        f"- Scenario ID: `{case_context.get('scenario_id')}`",
        f"- Scenario name: `{case_context.get('scenario_name')}`",
        f"- Generated at: `{case_context.get('generated_at')}`",
        f"- Causal path recoverability: `{metrics.get('causal_path_recoverability')}`",
        f"- Weighted CPR: `{metrics.get('weighted_cpr')}`",
        f"- Reconstruction confidence: `{metrics.get('reconstruction_confidence')}`",
        f"- Main limitation: `{metrics.get('main_limitation')}`",
        "",
        "## KPI Summary",
        "",
        f"- Recovered edges: `{metrics.get('recovered_edges')}` / `{metrics.get('expected_edges')}`",
        f"- Degraded edges: `{metrics.get('degraded_edges')}`",
        f"- Ambiguous edges: `{metrics.get('ambiguous_edges')}`",
        f"- Missing edges: `{metrics.get('missing_edges')}`",
        f"- Evidence completeness ratio: `{metrics.get('evidence_completeness_ratio')}`",
        f"- Integrity verification ratio: `{metrics.get('integrity_verification_ratio')}`",
        f"- Analysis coverage ratio: `{metrics.get('analysis_coverage_ratio')}`",
        f"- Temporal confidence state: `{metrics.get('temporal_confidence_state')}`",
        "",
        "## Edge Status Matrix",
        "",
    ]
    for edge in graph_payload.get("edges", []):
        lines.extend(
            [
                f"### {edge.get('edge_id')}",
                f"- Relation: `{edge.get('relation_type')}`",
                f"- Support status: `{edge.get('support_status')}`",
                f"- Confidence: `{edge.get('confidence')}`",
                f"- Temporal status: `{edge.get('temporal_status')}`",
                f"- Semantic status: `{edge.get('semantic_status')}`",
                f"- Integrity status: `{edge.get('integrity_status')}`",
                f"- Required evidence: `{', '.join(edge.get('required_evidence') or []) or 'none'}`",
                f"- Evidence refs: `{', '.join(edge.get('evidence_refs') or []) or 'not_available'}`",
                f"- Missing evidence: `{', '.join(edge.get('missing_evidence') or []) or 'none'}`",
                f"- Limitations: `{'; '.join(edge.get('limitations') or []) or 'none'}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Uncertainty Budget",
            "",
            f"- Temporal confidence state: `{uncertainty.get('temporal', {}).get('temporal_confidence_state')}`",
            f"- Uncertainty window ms: `{uncertainty.get('temporal', {}).get('uncertainty_window_ms')}`",
            f"- Completeness ratio: `{uncertainty.get('completeness', {}).get('evidence_completeness_ratio')}`",
            f"- Integrity ratio: `{uncertainty.get('integrity', {}).get('integrity_verification_ratio')}`",
            "",
            "## Scientific Caution",
            "",
            "The preserved evidence supports this reconstruction under the controlled intervention model. Recovered edges are auditable through the referenced preserved sources, while degraded, ambiguous and missing edges must not be presented as absolute proof of causality.",
            "",
        ]
    )
    return "\n".join(lines)


def _prerequisite_status(case_id: str, case_path: Path, analysis_status: dict | None = None, ground_truth_path: str | None = None) -> dict:
    case_context = _build_case_context(case_id, case_path, analysis_status=analysis_status, ground_truth_path=ground_truth_path)
    analysis_summary = case_context.get("analysis_summary") or {}
    gt_resolution = case_context.get("ground_truth_resolution") or {}
    foc_context = case_context.get("foc_context") or {}
    custody_context = case_context.get("custody_context") or {}
    foc_context_available = bool(foc_context.get("foc_context_summary") or foc_context.get("manifest"))
    manifest_present = bool(case_context.get("custody_context", {}).get("manifest_present"))
    custody_present = bool(case_context.get("custody_context", {}).get("chain_of_custody_present"))
    evidence_links_present = bool(custody_context.get("case_links_for_case"))
    analysis_report_present = bool(analysis_summary.get("forensic_analysis_report"))
    visual_summary_present = bool(analysis_summary.get("analysis_visual_summary"))
    if not foc_context_available:
        state = "not_available"
        reason = "Causal reconstruction is blocked because the normalized FOC context summary is unavailable."
    elif not manifest_present or not custody_present:
        state = "not_available"
        reason = "Causal reconstruction is blocked because the preserved case manifest or chain_of_custody.log is missing."
    elif not evidence_links_present:
        state = "not_available"
        reason = "Causal reconstruction is blocked because the normalized case-to-manifest evidence links are unavailable for this case."
    elif not analysis_report_present or not visual_summary_present:
        state = "blocked_missing_analysis"
        reason = "Causal reconstruction is blocked because multilayer forensic analysis has not been generated for this case."
    elif gt_resolution.get("status") == "missing":
        state = "blocked_missing_ground_truth"
        reason = "Causal reconstruction is blocked because scenario_ground_truth.json is missing for this scenario."
    elif gt_resolution.get("status") == "missing_expected_edges":
        state = "blocked_missing_ground_truth"
        reason = "Causal reconstruction is blocked because scenario_ground_truth.json does not define expected causal edges."
    else:
        state = "ready_to_run"
        reason = "All required preserved FOC and analysis artifacts are available for causal reconstruction."
    if state not in ALLOWED_CAUSAL_UI_STATES:
        state = "not_available"
    return {
        "case_context": case_context,
        "status": state,
        "reason": reason,
        "requirements": {
            "foc_context_available": foc_context_available,
            "manifest_present": manifest_present,
            "chain_of_custody_present": custody_present,
            "evidence_links_present": evidence_links_present,
            "analysis_report_present": analysis_report_present,
            "analysis_visual_summary_present": visual_summary_present,
            "ground_truth_status": gt_resolution.get("status"),
            "ground_truth_path": str(gt_resolution.get("path")) if gt_resolution.get("path") else None,
            "ground_truth_checked_paths": gt_resolution.get("checked_paths") or [],
        },
    }


def summarize_case_causal_state(case_id: str, case_path: str | Path, analysis_status: dict | None = None) -> dict:
    case_path = Path(case_path)
    paths = _paths(case_path)
    prereq = _prerequisite_status(case_id, case_path, analysis_status=analysis_status)
    status_payload = _json_load(paths["status"])
    if isinstance(status_payload, dict):
        status_payload.setdefault("case_id", case_id)
        status_payload.setdefault("scenario_id", prereq["case_context"].get("scenario_id"))
        merged_requirements = dict(prereq["requirements"])
        merged_requirements.update(status_payload.get("requirements") or {})
        status_payload["requirements"] = merged_requirements
        status_payload.setdefault("output_paths", {key: relative_path(path) for key, path in paths.items() if key != "root" and path.exists()})
        if not status_payload.get("metrics_preview") and paths["metrics"].is_file():
            status_payload["metrics_preview"] = _json_load(paths["metrics"])
        return status_payload
    return {
        "case_id": case_id,
        "scenario_id": prereq["case_context"].get("scenario_id"),
        "status": prereq["status"],
        "state": prereq["status"],
        "reason": prereq["reason"],
        "started_at": None,
        "updated_at": utc_now(),
        "finished_at": None,
        "progress_percent": 0,
        "requirements": prereq["requirements"],
        "output_paths": {key: relative_path(path) for key, path in paths.items() if key != "root" and path.exists()},
        "metrics_preview": _json_load(paths["metrics"]) if paths["metrics"].is_file() else None,
    }


def _write_status(case_path: Path, payload: dict) -> None:
    payload["updated_at"] = utc_now()
    _write_json(_status_path(case_path), payload)


def _run_once(case_id: str, case_path: Path, strict: bool = False, degraded_ok: bool = False, ground_truth_path: str | None = None, out_dir: str | None = None) -> dict:
    prereq = _prerequisite_status(case_id, case_path, ground_truth_path=ground_truth_path)
    case_context = prereq["case_context"]
    output_dir = _derived_dir(case_path, out_dir)
    status = {
        "case_id": case_id,
        "scenario_id": case_context.get("scenario_id"),
        "state": prereq["status"],
        "status": prereq["status"],
        "reason": prereq["reason"],
        "started_at": utc_now(),
        "updated_at": utc_now(),
        "finished_at": None,
        "progress_percent": 5,
        "current_step": "verifying_prerequisites",
        "requirements": prereq["requirements"],
        "errors": [],
        "warnings": [],
        "output_paths": {},
        "strict": bool(strict),
        "degraded_ok": bool(degraded_ok),
    }
    _write_status(case_path, status)
    if prereq["status"] != "ready_to_run":
        status["finished_at"] = utc_now()
        status["progress_percent"] = 100
        _write_status(case_path, status)
        return status

    status["status"] = "running"
    status["state"] = "running"
    status["current_step"] = "building_case_context"
    status["progress_percent"] = 15
    _write_status(case_path, status)

    nodes = build_nodes_from_ground_truth(case_context, lambda ref: _resolve_timestamp(case_context, ref))
    status["current_step"] = "evaluating_edges"
    status["progress_percent"] = 45
    _write_status(case_path, status)

    edges = [edge.to_dict() for edge in evaluate_edges(case_context, lambda req, selector=None: _evaluate_requirement(case_context, req, selector), lambda spec: _evaluate_temporal(case_context, spec))]
    metrics = _metrics_from_edges(case_context, edges)
    uncertainty = build_uncertainty_report(case_context, metrics, edges)
    graph = CausalGraph(
        case_id=case_id,
        scenario_id=str(case_context.get("scenario_id") or "unknown"),
        generated_at=utc_now(),
        note="This graph is a derived causal-forensic reconstruction from sealed FOC artifacts. It is not a live monitoring graph.",
        nodes=nodes,
        edges=[],
    )
    graph_payload = graph.to_dict()
    graph_payload["edges"] = edges

    status["current_step"] = "writing_outputs"
    status["progress_percent"] = 75
    _write_status(case_path, status)

    report_text = _markdown_report(case_context, metrics, uncertainty, graph_payload)
    output_paths = write_causal_outputs(output_dir, graph_payload, uncertainty, metrics, report_text)

    if strict and int(metrics.get("missing_edges") or 0) > 0:
        status["status"] = "failed"
        status["state"] = "failed"
        status["reason"] = "Strict mode failed because one or more expected edges are missing."
        status["errors"].append(status["reason"])
    elif int(metrics.get("missing_edges") or 0) > 0 or int(metrics.get("degraded_edges") or 0) > 0 or int(metrics.get("ambiguous_edges") or 0) > 0:
        status["status"] = "completed_with_degradation" if degraded_ok or int(metrics.get("missing_edges") or 0) == 0 else "completed_with_degradation"
        status["state"] = "completed_with_degradation"
        status["reason"] = metrics.get("main_limitation")
    else:
        status["status"] = "completed"
        status["state"] = "completed"
        status["reason"] = "The preserved evidence supports all expected causal edges under the current controlled intervention model."

    status["current_step"] = "completed"
    status["finished_at"] = utc_now()
    status["progress_percent"] = 100
    status["metrics_preview"] = metrics
    status["output_paths"] = {key: relative_path(Path(value)) for key, value in output_paths.items()}
    _write_status(case_path, status)
    return status


def _worker(case_id: str, case_path: Path, strict: bool, degraded_ok: bool, ground_truth_path: str | None, out_dir: str | None) -> None:
    try:
        _run_once(case_id, case_path, strict=strict, degraded_ok=degraded_ok, ground_truth_path=ground_truth_path, out_dir=out_dir)
    except Exception as exc:
        payload = summarize_case_causal_state(case_id, case_path)
        payload.update(
            {
                "status": "failed",
                "state": "failed",
                "reason": str(exc),
                "errors": [str(exc)],
                "finished_at": utc_now(),
                "progress_percent": 100,
                "current_step": "failed",
            }
        )
        _write_status(case_path, payload)
    finally:
        with _CAUSAL_LOCK:
            _RUNNING_CAUSAL.pop(case_id, None)


def run_causal_reconstruction(
    case_id: str,
    case_path: str | Path,
    strict: bool = False,
    degraded_ok: bool = False,
    ground_truth_path: str | None = None,
    out_dir: str | None = None,
) -> dict:
    case_path = Path(case_path)
    prereq = _prerequisite_status(case_id, case_path, ground_truth_path=ground_truth_path)
    if prereq["status"] not in {"ready_to_run", "completed", "completed_with_degradation"}:
        payload = summarize_case_causal_state(case_id, case_path)
        payload["reason"] = prereq["reason"]
        payload["requirements"] = prereq["requirements"]
        _write_status(case_path, payload)
        return payload
    with _CAUSAL_LOCK:
        running = _RUNNING_CAUSAL.get(case_id)
        if running and running.is_alive():
            payload = summarize_case_causal_state(case_id, case_path)
            payload["status"] = "running"
            payload["state"] = "running"
            return payload
        worker = threading.Thread(
            target=_worker,
            args=(case_id, case_path, strict, degraded_ok, ground_truth_path, out_dir),
            daemon=True,
            name=f"foc-causal-{_safe_slug(case_id)}",
        )
        _RUNNING_CAUSAL[case_id] = worker
        worker.start()
    return {
        "case_id": case_id,
        "status": "running",
        "state": "running",
        "started_at": utc_now(),
        "reason": "Causal reconstruction started in background.",
    }


def causal_status_payload(case_id: str, case_path: str | Path) -> dict:
    return summarize_case_causal_state(case_id, case_path)


def causal_metrics_payload(case_id: str, case_path: str | Path) -> dict | None:
    payload = _json_load(_paths(Path(case_path))["metrics"])
    if isinstance(payload, dict):
        payload.setdefault("case_id", case_id)
        return payload
    return None


def causal_graph_payload(case_id: str, case_path: str | Path) -> dict | None:
    payload = _json_load(_paths(Path(case_path))["graph"])
    if isinstance(payload, dict):
        payload.setdefault("case_id", case_id)
        return payload
    return None


def causal_report_payload(case_id: str, case_path: str | Path) -> dict | None:
    paths = _paths(Path(case_path))
    metrics = _json_load(paths["metrics"])
    graph = _json_load(paths["graph"])
    uncertainty = _json_load(paths["uncertainty"])
    report_text = paths["report"].read_text(encoding="utf-8") if paths["report"].is_file() else None
    if not any([metrics, graph, uncertainty, report_text]):
        return None
    return {
        "case_id": case_id,
        "metrics": metrics,
        "graph": graph,
        "uncertainty": uncertainty,
        "report_markdown": report_text,
        "artifact_paths": {key: relative_path(path) for key, path in paths.items() if key != "root" and path.exists()},
    }
