from __future__ import annotations

from ..evidence_support_extract import _build_hypotheses, _LAYER_LABELS

_LAYER_BY_REQ_TYPE = {
    "attack_attestation": "causal_graph",
    "network_modbus_observation": "network",
    "plc_state_observation": "ot",
    "detection_attestation": "alerts",
    "alert_correlation": "alerts",
    "memory_analysis_useful": "memory",
    "forensic_intervention": "custody",
    "case_manifest_link": "custody",
    "manifest": "custody",
    "chain_of_custody": "custody",
    "forensic_analysis_report": "causal_graph",
    "analysis_visual_summary": "causal_graph",
}

_SUPPORTING_DIRECTIONS = {"supports", "partially_supports"}

# The 8 fixed dashboard rows, in display order. attack_attestation /
# forensic_analysis_report / analysis_visual_summary requirements are folded
# into "causal_graph" since the causal engine's own edge evaluation is the
# direct consumer of those attestations - there is no separate raw-evidence
# row for them in the UI.
LAYER_ROWS = ["memory", "network", "disk", "ot", "alerts", "timeline", "custody", "causal_graph"]

# Atoms are routed to the specific edge(s) they are topical evidence for,
# not merely to every edge that shares their evidence_layer - otherwise an
# atom about one claim (e.g. "did the acquisition trigger match the causal
# path") would incorrectly count as contradicting an unrelated edge that
# happens to live in the same layer (e.g. "was Modbus traffic observable by
# the detection surface"). This mapping is small and finite because both the
# atom event types and the causal edges are fixed for this domain model.
_EVENT_TYPE_TO_EDGES = {
    "modbus_tcp_observation": {"edge_attack_execution_to_ot_write", "edge_ot_write_to_network_modbus_write"},
    "modbus_write_absence": {"edge_attack_execution_to_ot_write", "edge_ot_write_to_network_modbus_write"},
    "ot_export_record_count": {"edge_ot_write_to_plc_state_observation"},
    "ot_function_code_aggregate": {"edge_attack_execution_to_ot_write", "edge_ot_write_to_plc_state_observation"},
    "ot_non_write_function_aggregate": {"edge_attack_execution_to_ot_write", "edge_ot_write_to_plc_state_observation"},
    "ids_signature_hit": {"edge_network_modbus_write_to_detection_surface", "edge_detection_surface_to_alert_observation"},
    "trigger_causal_path_mismatch": {"edge_alert_observation_to_forensic_case"},
    "custody_integrity_summary": {"edge_forensic_case_to_preserved_case_evidence", "edge_preserved_case_evidence_to_multilayer_analysis"},
}


def _edge_required_layers(edge: dict) -> set[str]:
    layers = set()
    for req in edge.get("required_evidence") or []:
        layer = _LAYER_BY_REQ_TYPE.get(str(req))
        if layer:
            layers.add(layer)
    return layers


def _node_to_edges(edges: list[dict]) -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for edge in edges:
        edge_id = edge.get("edge_id")
        for node in (edge.get("source"), edge.get("target")):
            if node:
                mapping.setdefault(str(node), set()).add(edge_id)
    return mapping


def _edges_for_atom(atom: dict, node_to_edges: dict[str, set[str]]) -> set[str]:
    event_type = atom.get("event_type") or ""
    if event_type in _EVENT_TYPE_TO_EDGES:
        return set(_EVENT_TYPE_TO_EDGES[event_type])
    relation = str(atom.get("relation_to_hypothesis") or "")
    if relation.startswith("causal_node:"):
        return set(node_to_edges.get(relation.split(":", 1)[1], set()))
    return set()


def build_cross_layer_matrix(causal_graph: dict, atoms: list[dict]) -> dict:
    edges = (causal_graph or {}).get("edges") or []
    node_to_edges = _node_to_edges(edges)
    atoms_by_layer: dict[str, list[dict]] = {}
    for atom in atoms:
        atoms_by_layer.setdefault(atom.get("evidence_layer") or "unknown", []).append(atom)

    atom_edge_map = {atom["atom_id"]: _edges_for_atom(atom, node_to_edges) for atom in atoms if atom.get("evidence_layer") != "causal_graph"}

    relations = []
    for edge in edges:
        edge_id = edge.get("edge_id")
        required_layers = _edge_required_layers(edge)
        own_atom = next((a for a in atoms if a.get("atom_id") == f"causal_{edge_id}"), None)
        cross_atoms = [a for a in atoms if a.get("evidence_layer") != "causal_graph" and edge_id in atom_edge_map.get(a["atom_id"], set())]

        supporting_layers = sorted({a["evidence_layer"] for a in cross_atoms if a.get("support_direction") in _SUPPORTING_DIRECTIONS})
        contradicting_layers = sorted({a["evidence_layer"] for a in cross_atoms if a.get("support_direction") == "contradicts"})
        contributing_layers = set(supporting_layers) | set(contradicting_layers)
        silent_layers = sorted(required_layers - contributing_layers - {"causal_graph"})
        has_full_support = any(a.get("support_direction") == "supports" for a in cross_atoms)
        own_supports = bool(own_atom and own_atom.get("support_direction") in _SUPPORTING_DIRECTIONS)
        timestamp_statuses = {a.get("timestamp_status") for a in cross_atoms} | ({own_atom.get("timestamp_status")} if own_atom else set())
        temporally_unresolved = bool(timestamp_statuses) and timestamp_statuses <= {"unavailable", "not_resolvable"}

        # The causal_graph layer's own evaluation counts as one of the
        # contributing layers when it independently supports the claim, so
        # "multiple layers" means the causal engine's own evidence-backed
        # verdict PLUS at least one other raw evidentiary layer agreeing.
        effective_supporting = set(supporting_layers) | ({"causal_graph"} if own_supports else set())

        if contradicting_layers:
            classification = "contradicted"
        elif len(effective_supporting) >= 2:
            classification = "confirmed_by_multiple_layers"
        elif len(supporting_layers) == 1:
            classification = "supported_by_single_layer" if has_full_support else "partially_supported"
        elif own_supports:
            classification = "inferred"
        else:
            classification = "not_evaluable"

        relations.append(
            {
                "edge_id": edge_id,
                "claim_text": edge.get("meaning") or edge.get("relation_type") or edge_id,
                "required_layers": sorted(required_layers),
                "layers_supporting": sorted(effective_supporting),
                "layers_contradicting": contradicting_layers,
                "layers_silent": silent_layers,
                "classification": classification,
                "temporally_unresolved": temporally_unresolved,
                "own_support_status": edge.get("support_status"),
            }
        )

    layer_contribution_matrix = {}
    for layer in LAYER_ROWS:
        layer_atoms = atoms_by_layer.get(layer, [])
        supports = sum(1 for a in layer_atoms if a.get("support_direction") == "supports")
        partial = sum(1 for a in layer_atoms if a.get("support_direction") == "partially_supports")
        contradicts = sum(1 for a in layer_atoms if a.get("support_direction") == "contradicts")
        not_evaluable = sum(1 for a in layer_atoms if a.get("support_direction") in {"not_evaluable", "neutral"})
        timestamp_statuses = [a.get("timestamp_status") for a in layer_atoms]
        resolvable = sum(1 for status in timestamp_statuses if status in {"precise", "approximate"})
        timestamp_quality = "not_applicable" if not timestamp_statuses else ("resolvable" if resolvable == len(timestamp_statuses) else ("partial" if resolvable else "unresolvable"))
        limitations = sorted({a.get("limitation") for a in layer_atoms if a.get("limitation")})
        layer_contribution_matrix[layer] = {
            "label": _LAYER_LABELS.get(layer, layer),
            "atom_count": len(layer_atoms),
            "supports": supports,
            "partially_supports": partial,
            "contradicts": contradicts,
            "not_evaluable": not_evaluable,
            "timestamp_quality": timestamp_quality,
            "limitation": limitations[0] if limitations else None,
        }

    return {"relations": relations, "layer_contribution_matrix": layer_contribution_matrix}


def compute_global_support_level(matrix: dict, atoms: list[dict]) -> str:
    relations = matrix.get("relations") or []
    if not relations:
        return "not_evaluable"
    confirmed = [r for r in relations if r["classification"] == "confirmed_by_multiple_layers"]
    contradicted = [r for r in relations if r["classification"] == "contradicted"]
    temporally_unresolved = [r for r in relations if r.get("temporally_unresolved")]
    evaluable = [r for r in relations if r["classification"] != "not_evaluable"]
    any_atom_contradicts = any(a.get("support_direction") == "contradicts" for a in atoms)

    if not evaluable:
        return "not_evaluable"
    # Full rejection: every evaluable relation is contradicted and none are
    # confirmed - the hypothesis as a whole is negated, not just one facet of it.
    if contradicted and not confirmed and len(contradicted) == len(evaluable):
        return "contradicted"
    # Hard rule: strong_support requires multi-layer confirmation everywhere
    # evaluable, zero contradictions anywhere, and zero unresolved timing -
    # a synchronized clock or a recovered edge alone can never reach "strong".
    if len(confirmed) >= 2 and not contradicted and not temporally_unresolved and not any_atom_contradicts:
        return "strong_support"
    if confirmed:
        # At least one relation is corroborated by the causal engine plus an
        # independent raw evidentiary layer; contradictions elsewhere are
        # real and cap this below strong, but do not erase the corroboration
        # that does exist.
        return "moderate_support"
    single_or_partial = [r for r in relations if r["classification"] in {"supported_by_single_layer", "partially_supported", "inferred"}]
    if single_or_partial:
        return "weak_support"
    return "insufficient_support"


def build_hypothesis_support_report(case_id: str, ground_truth: dict, attack: dict, matrix: dict, atoms: list[dict], global_support_level: str) -> dict:
    hypotheses = _build_hypotheses(ground_truth, attack)
    hypothesis = hypotheses[0]
    supporting = [a["atom_id"] for a in atoms if a.get("support_direction") == "supports"]
    partial = [a["atom_id"] for a in atoms if a.get("support_direction") == "partially_supports"]
    contradicting = [a["atom_id"] for a in atoms if a.get("support_direction") == "contradicts"]
    missing_required = sorted({layer for r in matrix.get("relations", []) for layer in r.get("layers_silent", [])})
    temporal_limitations = sorted({a.get("limitation") for a in atoms if a.get("timestamp_status") in {"unavailable", "not_resolvable"} and a.get("limitation")})
    integrity_limitations = sorted({a.get("limitation") for a in atoms if a.get("evidence_layer") == "custody" and a.get("limitation")})
    causal_limitations = sorted({a.get("limitation") for a in atoms if a.get("evidence_layer") == "causal_graph" and a.get("limitation")})

    if global_support_level == "contradicted":
        final_claimability_status = "the hypothesis is contradicted by preserved evidence and cannot be claimed."
    elif global_support_level in {"strong_support", "moderate_support"}:
        final_claimability_status = f"the hypothesis can receive {global_support_level.replace('_', ' ')}, not absolute causality."
    else:
        final_claimability_status = f"the hypothesis currently receives only {global_support_level.replace('_', ' ')}; stronger claims are not yet supportable."

    return {
        "case_id": case_id,
        "hypothesis_id": hypothesis["hypothesis_id"],
        "hypothesis_text": hypothesis["hypothesis_text"],
        "global_support_level": global_support_level,
        "global_confidence": "moderate" if global_support_level == "moderate_support" else ("low" if global_support_level in {"weak_support", "insufficient_support"} else ("high" if global_support_level == "strong_support" else "none")),
        "supporting_evidence_atoms": supporting,
        "partially_supporting_evidence_atoms": partial,
        "contradictory_evidence_atoms": contradicting,
        "missing_required_evidence": missing_required,
        "temporal_limitations": temporal_limitations,
        "integrity_limitations": integrity_limitations,
        "causal_limitations": causal_limitations,
        "final_claimability_status": final_claimability_status,
    }


def build_claimability_report(matrix: dict, atoms: list[dict]) -> dict:
    relations = matrix.get("relations") or []
    confirmed_or_single = {r["edge_id"] for r in relations if r["classification"] in {"confirmed_by_multiple_layers", "supported_by_single_layer"}}
    supported_claims = [
        "Evidence was preserved under a manifest and chain of custody.",
        "Multilayer forensic analysis was executed over the preserved case artifacts.",
    ]
    if any(a.get("evidence_layer") == "network" and a.get("support_direction") in _SUPPORTING_DIRECTIONS for a in atoms):
        supported_claims.append("Network evidence supports Modbus TCP protocol activity toward the PLC.")
    if confirmed_or_single:
        supported_claims.append(f"Causal reconstruction recovered {len(confirmed_or_single)} of {len(relations)} expected causal relations with cross-layer or single-layer support.")

    partially_supported_claims = [
        "Register-level Modbus manipulation.",
        "Value-level Modbus manipulation.",
        "PLC or SCADA state relation.",
        "Temporal causal ordering.",
    ]

    unsupported_claims = [
        "Absolute causality.",
        "Court-ready admissibility.",
        "Full production OT generalization.",
        "Direct OT alert to forensic acquisition link.",
    ]
    if any(a.get("event_type") == "modbus_write_absence" for a in atoms):
        unsupported_claims.append("Complete register and value causality at packet-level precision.")

    return {
        "supported_claims": supported_claims,
        "partially_supported_claims": partially_supported_claims,
        "unsupported_or_not_claimable_claims": unsupported_claims,
    }


def build_counter_evidence_report(atoms: list[dict]) -> dict:
    contradictions = [
        {"atom_id": a["atom_id"], "evidence_layer": a["evidence_layer"], "observed_value": a["observed_value"], "limitation": a.get("limitation")}
        for a in atoms
        if a.get("support_direction") == "contradicts"
    ]
    not_evaluable = [
        {"atom_id": a["atom_id"], "evidence_layer": a["evidence_layer"], "limitation": a.get("limitation")}
        for a in atoms
        if a.get("support_direction") in {"not_evaluable", "neutral"} and a.get("limitation")
    ]
    indirect_only = [
        {"atom_id": a["atom_id"], "evidence_layer": a["evidence_layer"], "observed_value": a["observed_value"]}
        for a in atoms
        if a.get("support_strength") == "indirect"
    ]
    temporally_unresolvable = [
        {"atom_id": a["atom_id"], "evidence_layer": a["evidence_layer"]}
        for a in atoms
        if a.get("timestamp_status") in {"unavailable", "not_resolvable"}
    ]
    return {
        "contradicting_evidence": contradictions,
        "missing_or_not_evaluable_evidence": not_evaluable,
        "indirect_only_evidence": indirect_only,
        "temporally_unresolvable_evidence": temporally_unresolvable,
    }


_STORYLINE_TEMPLATE = [
    ("scenario_execution", "A controlled OT Modbus manipulation scenario was executed against the PLC.", ["causal_graph"]),
    ("network_observation", "Network evidence shows Modbus TCP activity involving the PLC.", ["network"]),
    ("protocol_confirmed_partial", "Protocol evidence confirms Modbus TCP; register and value precision are not confirmed at packet level.", ["network", "alerts"]),
    ("ot_partial_state", "OT exports provide partial, read-only state-level support; no write-function evidence is present.", ["ot"]),
    ("acquisition_trigger", "The preserved forensic case was acquired through a host or FIM-oriented trigger.", ["alerts", "custody"]),
    ("trigger_path_mismatch", "The acquisition trigger and the reconstructed OT attack path are not identical.", ["alerts"]),
    ("partial_reconstruction", "The preserved evidence supports a partial reconstruction, not absolute causality.", ["causal_graph"]),
]


def build_forensic_storyline(case_id: str, atoms: list[dict], global_support_level: str) -> dict:
    atoms_by_layer: dict[str, list[dict]] = {}
    for atom in atoms:
        atoms_by_layer.setdefault(atom.get("evidence_layer") or "unknown", []).append(atom)

    steps = []
    for index, (step_key, description, layers) in enumerate(_STORYLINE_TEMPLATE, start=1):
        supporting_atoms = []
        for layer in layers:
            supporting_atoms.extend(a["atom_id"] for a in atoms_by_layer.get(layer, []))
        if not supporting_atoms:
            continue
        timestamps = [a.get("timestamp") for a in atoms if a["atom_id"] in supporting_atoms and a.get("timestamp")]
        statuses = {a.get("timestamp_status") for a in atoms if a["atom_id"] in supporting_atoms}
        limitations = sorted({a.get("limitation") for a in atoms if a["atom_id"] in supporting_atoms and a.get("limitation")})
        steps.append(
            {
                "step_id": f"step_{index}_{step_key}",
                "event_description": description,
                "supporting_atoms": supporting_atoms,
                "evidence_layers": layers,
                "timestamp": timestamps[0] if timestamps else None,
                "timestamp_status": "precise" if "precise" in statuses else ("approximate" if "approximate" in statuses else "unavailable"),
                "confidence": "moderate" if global_support_level == "moderate_support" else global_support_level.replace("_support", ""),
                "limitation": limitations[0] if limitations else None,
            }
        )
    return {"case_id": case_id, "global_support_level": global_support_level, "steps": steps}
