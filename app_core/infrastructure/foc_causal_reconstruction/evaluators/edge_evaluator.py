from __future__ import annotations

from ..config import ALLOWED_SUPPORT_STATUSES, ALLOWED_TEMPORAL_STATES
from ..schemas import CausalEdge


def _unique(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def evaluate_edges(case_context: dict, requirement_evaluator, temporal_evaluator) -> list[CausalEdge]:
    ground_truth = case_context.get("ground_truth") or {}
    expected_edges = ground_truth.get("expected_edges") if isinstance(ground_truth, dict) else []
    expected_edges = expected_edges if isinstance(expected_edges, list) else []
    edges: list[CausalEdge] = []
    for spec in expected_edges:
        spec = spec if isinstance(spec, dict) else {}
        edge_id = str(spec.get("edge_id") or "edge")
        required_evidence = [str(item) for item in (spec.get("required_evidence") or []) if item]
        selectors = spec.get("selectors") if isinstance(spec.get("selectors"), dict) else {}
        requirement_results = [
            requirement_evaluator(req_type, selectors.get(req_type) if isinstance(selectors, dict) else None)
            for req_type in required_evidence
        ]
        evidence_refs = _unique([ref for result in requirement_results for ref in (result.get("evidence_refs") or [])])
        missing_evidence = _unique([result.get("type") for result in requirement_results if result.get("status") == "missing"])
        limitations = _unique([item for result in requirement_results for item in (result.get("limitations") or [])])
        temporal_status = temporal_evaluator(spec)
        if temporal_status not in ALLOWED_TEMPORAL_STATES:
            temporal_status = "unknown"

        if missing_evidence:
            support_status = "missing"
        elif temporal_status in {"ambiguous", "contradicted"}:
            support_status = "ambiguous"
        elif any(result.get("status") in {"degraded", "ambiguous"} for result in requirement_results):
            support_status = "degraded"
        else:
            support_status = "recovered"
        if support_status not in ALLOWED_SUPPORT_STATUSES:
            support_status = "missing"

        if support_status == "recovered":
            confidence = "high"
        elif support_status == "degraded":
            confidence = "medium"
        elif support_status == "ambiguous":
            confidence = "low"
        else:
            confidence = "low"

        integrity_status = "verified"
        if case_context.get("custody_context", {}).get("integrity_report", {}).get("status") == "partial":
            integrity_status = "partial"
            limitations.append("Integrity and custody validation remains partial for this case.")
        semantic_status = "supported"
        if any(result.get("status") == "missing" for result in requirement_results):
            semantic_status = "unsupported"
        elif any(result.get("status") in {"degraded", "ambiguous"} for result in requirement_results):
            semantic_status = "partial"

        edges.append(
            CausalEdge(
                edge_id=edge_id,
                expected_edge_id=edge_id,
                source=str(spec.get("source") or "unknown"),
                target=str(spec.get("target") or "unknown"),
                relation_type=str(spec.get("relation_type") or "derived_relation"),
                required_evidence=required_evidence,
                evidence_refs=evidence_refs,
                missing_evidence=missing_evidence,
                support_status=support_status,
                confidence=confidence,
                temporal_status=temporal_status,
                semantic_status=semantic_status,
                integrity_status=integrity_status,
                limitations=_unique(limitations),
            )
        )
    return edges
