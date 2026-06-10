import hashlib
from pathlib import Path

from .foc_bootstrap import make_id, read_id_mapping
from .foc_paths import project_path, relative_path
from .foc_schema import clone, empty_artifact_reference, empty_relationship_edge
from .foc_sources import read_json_file, read_jsonl_file, utc_now


def _edge_id(*parts: str) -> str:
    raw = "|".join(parts)
    return make_id("rel", raw)


def _artifact_id(*parts: str) -> str:
    raw = "|".join(parts)
    return make_id("art", raw)


def _evidence_id(*parts: str) -> str:
    raw = "|".join(parts)
    return make_id("evd", raw)


def _add_edge(edges: list[dict], from_type: str, from_id: str, relation: str, to_type: str, to_id: str, **kwargs) -> None:
    edge = clone(empty_relationship_edge())
    edge.update(
        {
            "edge_id": _edge_id(from_type, from_id, relation, to_type, to_id),
            "from_type": from_type,
            "from_id": from_id,
            "relation": relation,
            "to_type": to_type,
            "to_id": to_id,
        }
    )
    edge.update(kwargs)
    edges.append(edge)


def _infer_case_artifacts(case_dir: Path, warnings: list[dict]) -> list[dict]:
    manifest = read_json_file(case_dir / "manifest.json", warnings) or {}
    case_id = make_id("case", case_dir.name)
    out = []
    for entry in manifest.get("artifacts", []) or []:
        rel_path = entry.get("rel_path") or ""
        ref = clone(empty_artifact_reference())
        ref.update(
            {
                "artifact_id": _artifact_id(case_dir.name, rel_path),
                "evidence_id": _evidence_id(case_dir.name, rel_path),
                "id_origin": "derived_from_path",
                "artifact_type": entry.get("type", "unknown"),
                "path": f"{relative_path(case_dir)}/{rel_path}" if rel_path else relative_path(case_dir),
                "case_id": case_id,
                "related_instance_id": "unresolved",
                "related_node_id": "unresolved",
                "sha256": entry.get("sha256"),
                "size": entry.get("size"),
                "status": "indexed",
                "details": {"ts": entry.get("ts")},
            }
        )
        out.append(ref)
    return out


def build_indexes(scenario_bom: dict, tools_bom: dict, timeline: dict, sources_bundle: dict, id_mapping: dict | None = None) -> dict:
    warnings: list[dict] = []
    scenario_id = scenario_bom.get("scenario_id", "unknown")
    relationships: list[dict] = []
    artifacts_index: list[dict] = []
    id_mapping = id_mapping or read_id_mapping() or {}

    for node in scenario_bom.get("nodes", []):
        node_id = node.get("node_id", "unknown")
        _add_edge(relationships, "scenario", scenario_id, "contains_node", "node", node_id)

    for binding in scenario_bom.get("node_instance_bindings", []):
        _add_edge(
            relationships,
            "node",
            binding.get("node_id", "unknown"),
            "binds_instance",
            "instance",
            binding.get("instance_id", "unresolved"),
            status=binding.get("status", "unresolved"),
            relationship_status="confirmed" if binding.get("status") == "bound" else "inferred",
        )

    node_by_name = {node.get("name"): node for node in scenario_bom.get("nodes", []) if node.get("name")}
    binding_by_instance = {
        binding.get("instance_id"): binding
        for binding in scenario_bom.get("node_instance_bindings", [])
        if binding.get("instance_id")
    }
    for node in tools_bom.get("nodes", []):
        node_name = node.get("instance_name", "")
        matching_node = node_by_name.get(node_name)
        node_id = matching_node.get("node_id") if matching_node else binding_by_instance.get(node.get("instance_id"), {}).get("node_id", "unresolved")
        for tool in node.get("desired_tools", []):
            _add_edge(relationships, "node", node_id, "desired_tool", "tool", tool, status="ok")
        for tool in node.get("installed_tools", []):
            _add_edge(relationships, "node", node_id, "installed_tool", "tool", tool, status="ok")

    attack_mapping_by_path = {
        entry.get("source_path"): entry
        for entry in (id_mapping.get("mappings", {}).get("attacks", []) or [])
    }
    timeline_alerts_by_attack = {}
    for event in timeline.get("events", []):
        if event.get("event_type") != "detection_alert":
            continue
        attack_id = event.get("related_attack_id", "unresolved")
        alert_id = event.get("related_alert_id", "unresolved")
        if attack_id in {"", "unresolved", "unknown"}:
            continue
        timeline_alerts_by_attack.setdefault(attack_id, set()).add(alert_id)

    for path in sorted(project_path("app_core", "infrastructure", "attack", "outputs").glob("*/result.json")):
        data = read_json_file(path, warnings)
        if not isinstance(data, dict):
            continue
        mapping_entry = attack_mapping_by_path.get(relative_path(path), {})
        attack_id = mapping_entry.get("attack_id", make_id("atk", data.get("attack_id") or relative_path(path)))
        execution_id = path.parent.name
        target_role = str(data.get("target_role") or "").lower()
        node_id = "unresolved"
        for node in scenario_bom.get("nodes", []):
            if str(node.get("type") or "").lower() == target_role:
                node_id = node.get("node_id", "unresolved")
                break
        _add_edge(relationships, "node", node_id, "attack_execution", "attack", attack_id, evidence=[relative_path(path)], details={"execution_id": execution_id}, relationship_status="inferred" if node_id == "unresolved" else "confirmed")

        matching_alerts = sorted(timeline_alerts_by_attack.get(attack_id, set()))
        if matching_alerts:
            for alert_id in matching_alerts:
                _add_edge(
                    relationships,
                    "attack_execution",
                    execution_id,
                    "produced_alert",
                    "alert",
                    alert_id,
                    relationship_status="confirmed" if alert_id not in {"unresolved", "unknown"} else "inferred",
                )
        else:
            _add_edge(relationships, "attack", attack_id, "produced_alert", "alert", "unresolved", status="unresolved", relationship_status="inferred")

    triage_events = {}
    for event in timeline.get("events", []):
        if event.get("event_type") == "triage_result":
            triage_events[event.get("related_alert_id", "unresolved")] = event
    for alert_id in triage_events.keys():
        _add_edge(relationships, "alert", alert_id, "triaged_as", "triage", alert_id)

    case_dirs = sorted(project_path("app_core", "infrastructure", "forensics", "evidence_store").glob("CASE-*"))
    cases_index = []
    for case_dir in case_dirs:
        case_id = make_id("case", case_dir.name)
        case_artifacts = _infer_case_artifacts(case_dir, warnings)
        artifacts_index.extend(case_artifacts)
        cases_index.append(
            {
                "case_id": case_id,
                "source_case_name": case_dir.name,
                "path": relative_path(case_dir),
                "artifacts_count": len(case_artifacts),
                "manifest_path": f"{relative_path(case_dir)}/manifest.json",
                "pipeline_path": f"{relative_path(case_dir)}/metadata/pipeline_events.jsonl",
                "custody_path": f"{relative_path(case_dir)}/chain_of_custody.log",
            }
        )
        for artifact in case_artifacts:
            _add_edge(relationships, "case", case_id, "contains_artifact", "artifact", artifact["artifact_id"])
            _add_edge(relationships, "evidence", artifact["evidence_id"], "preserved_in", "artifact", artifact["artifact_id"])
            if "/analysis/" in artifact["path"] or artifact["artifact_type"] in {"vol3_output_dir", "tsk_output_dir"}:
                _add_edge(relationships, "evidence", artifact["evidence_id"], "supports_analysis", "artifact", artifact["artifact_id"])

    for src in sources_bundle.get("sources", []):
        if src.get("status") != "present":
            continue
        if src.get("kind") != "file":
            continue
        artifact = clone(empty_artifact_reference())
        artifact.update(
            {
                "artifact_id": _artifact_id(src.get("path", "")),
                "evidence_id": "not_available",
                "id_origin": "derived_from_path",
                "artifact_type": src.get("source_type", "source_file"),
                "path": src.get("path", ""),
                "case_id": "not_available",
                "related_instance_id": "unresolved",
                "related_node_id": "unresolved",
                "sha256": src.get("sha256"),
                "size": src.get("size"),
                "status": src.get("status", "unknown"),
                "details": {"mtime": src.get("mtime")},
            }
        )
        artifacts_index.append(artifact)

    return {
        "generated_at": utc_now(),
        "warnings": warnings,
        "sources_index": sources_bundle,
        "artifacts_index": {"generated_at": utc_now(), "artifacts": artifacts_index},
        "relationships_index": {"generated_at": utc_now(), "scenario_id": scenario_id, "edges": relationships},
        "cases_index": {"generated_at": utc_now(), "cases": cases_index},
    }
