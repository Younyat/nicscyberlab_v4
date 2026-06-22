from __future__ import annotations

from ..schemas import CausalNode


def build_nodes_from_ground_truth(case_context: dict, timestamp_resolver) -> list[CausalNode]:
    ground_truth = case_context.get("ground_truth") or {}
    node_specs = ground_truth.get("nodes") if isinstance(ground_truth, dict) else {}
    node_specs = node_specs if isinstance(node_specs, dict) else {}
    nodes: list[CausalNode] = []
    for node_id, spec in node_specs.items():
        spec = spec if isinstance(spec, dict) else {}
        timestamp_ref = spec.get("timestamp_ref")
        resolved_ts, source_ref = timestamp_resolver(timestamp_ref)
        limitations: list[str] = []
        if timestamp_ref and not resolved_ts:
            limitations.append(f"Timestamp reference `{timestamp_ref}` could not be resolved from preserved sources.")
        nodes.append(
            CausalNode(
                node_id=node_id,
                node_type=str(spec.get("node_type") or "derived_event"),
                layer=str(spec.get("layer") or "derived"),
                timestamp_utc=resolved_ts,
                label=str(spec.get("label") or node_id),
                source_ref=str(spec.get("source_ref") or source_ref or "not_available"),
                evidence_refs=[str(item) for item in (spec.get("evidence_refs") or []) if item],
                limitations=limitations,
            )
        )
    return nodes
