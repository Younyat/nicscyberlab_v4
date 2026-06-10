import hashlib
import re
from pathlib import Path

from .foc_bootstrap import make_id
from .foc_paths import project_path, relative_path
from .foc_schema import clone, empty_scenario_bom, empty_tools_bom
from .foc_sources import read_json_file, utc_now


def _normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (value or "").lower())


def _safe_instance_filename(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", (value or "").lower())
    return f"{safe}_tools.json"


def _infer_type_from_name(value: str) -> str:
    name = (value or "").lower()
    if "plc" in name:
        return "industrial_plc"
    if "fuxa" in name or "scada" in name:
        return "industrial_scada"
    if "victim" in name:
        return "victim"
    if "monitor" in name:
        return "monitor"
    if "attack" in name:
        return "attack"
    return "unknown"


def _build_scenario_id(scenario_name: str, base_path: Path) -> str:
    seed = f"{scenario_name}|{relative_path(base_path)}"
    return make_id("scn", seed)


def _load_base_scenario(warnings: list[dict]) -> tuple[dict, Path]:
    path = project_path("scenario", "scenario_file.json")
    data = read_json_file(path, warnings) or {}
    return data if isinstance(data, dict) else {}, path


def _load_industrial_scenario(warnings: list[dict]) -> tuple[dict, Path]:
    paths = sorted(project_path("industrial-scenario", "scenarios").glob("industrial_*.json"))
    if not paths:
        return {}, project_path("industrial-scenario", "scenarios", "industrial_*.json")
    path = paths[-1]
    data = read_json_file(path, warnings) or {}
    return data if isinstance(data, dict) else {}, path


def _load_industrial_state(warnings: list[dict]) -> tuple[dict, Path]:
    path = project_path("industrial-scenario", "state", "industrial_state.json")
    data = read_json_file(path, warnings) or {}
    return data if isinstance(data, dict) else {}, path


def _load_tmp_tool_files(warnings: list[dict]) -> list[dict]:
    out = []
    for path in sorted(project_path("tools-installer-tmp").glob("*.json")):
        data = read_json_file(path, warnings)
        if isinstance(data, dict):
            data["_source_path"] = relative_path(path)
            out.append(data)
    return out


def _load_installed_tool_files(warnings: list[dict]) -> list[dict]:
    out = []
    for path in sorted(project_path("tools-installer", "installed").glob("*.json")):
        data = read_json_file(path, warnings)
        if isinstance(data, dict):
            data["_source_path"] = relative_path(path)
            out.append(data)
    return out


def _infer_node_bindings(nodes: list[dict], tmp_tools: list[dict], installed_tools: list[dict], id_mapping: dict | None = None) -> list[dict]:
    mapping_nodes = (id_mapping or {}).get("mappings", {}).get("nodes", [])
    mapping_by_source = {entry.get("source_id"): entry for entry in mapping_nodes}
    by_name = {}
    for record in tmp_tools + installed_tools:
        instance_name = record.get("name") or record.get("instance_name") or ""
        if instance_name:
            raw_instance_id = record.get("id") or record.get("instance_id") or ""
            normalized_instance_id = f"inst-{raw_instance_id[:8]}" if raw_instance_id else make_id("inst", instance_name, record.get("ip") or record.get("ip_floating") or "")
            by_name[_normalize_name(instance_name)] = {
                "instance_id": normalized_instance_id,
                "openstack_instance_id": raw_instance_id or "not_available",
                "instance_name": instance_name,
                "id_origin": "derived_from_existing_id" if raw_instance_id else "derived_from_hash",
            }

    bindings = []
    for node in nodes:
        node_name = node.get("name") or ""
        norm = _normalize_name(node_name)
        match = by_name.get(norm, {})
        if not match and node.get("industrial"):
            if "plc" in norm:
                for key, value in by_name.items():
                    if "plc" in key:
                        match = value
                        break
            elif "scada" in norm:
                for key, value in by_name.items():
                    if "fuxa" in key or "scada" in key:
                        match = value
                        break
        bindings.append(
            {
                "node_id": (mapping_by_source.get(node.get("id")) or {}).get("node_id", make_id("node", node.get("id", "unknown"), node_name, node.get("type", "unknown"))),
                "node_name": node_name,
                "instance_id": match.get("instance_id", "unresolved"),
                "openstack_instance_id": match.get("openstack_instance_id", "not_available"),
                "instance_name": match.get("instance_name", "unresolved"),
                "id_origin": match.get("id_origin", "unknown"),
                "status": "bound" if match else "unresolved",
            }
        )
    return bindings


def build_scenario_bom(id_mapping: dict | None = None) -> tuple[dict, dict]:
    warnings: list[dict] = []
    bom = clone(empty_scenario_bom())

    base_scenario, base_path = _load_base_scenario(warnings)
    industrial_scenario, industrial_path = _load_industrial_scenario(warnings)
    industrial_state, industrial_state_path = _load_industrial_state(warnings)
    tmp_tools = _load_tmp_tool_files(warnings)
    installed_tools = _load_installed_tool_files(warnings)

    scenario_name = (
        industrial_scenario.get("scenario_name")
        or base_scenario.get("scenario_name")
        or "unknown"
    )
    mapping_scenario = (id_mapping or {}).get("mappings", {}).get("scenario", {})
    scenario_id = mapping_scenario.get("scenario_id") or _build_scenario_id(scenario_name, base_path)
    scenario_origin = mapping_scenario.get("id_origin", "derived_from_hash")

    nodes = industrial_scenario.get("nodes") or base_scenario.get("nodes") or []
    edges = industrial_scenario.get("edges") or base_scenario.get("edges") or []
    mapping_nodes = (id_mapping or {}).get("mappings", {}).get("nodes", [])
    mapping_by_source = {entry.get("source_id"): entry for entry in mapping_nodes}

    normalized_nodes = []
    for node in nodes:
        mapped = mapping_by_source.get(node.get("id"), {})
        entry = dict(node)
        entry["node_id"] = mapped.get("node_id", make_id("node", node.get("id", "unknown"), node.get("name", "unknown"), node.get("type", "unknown")))
        entry["source_node_id"] = node.get("id", "unknown")
        entry["id_origin"] = mapped.get("id_origin", "derived_from_existing_id" if node.get("id") else "derived_from_hash")
        normalized_nodes.append(entry)

    edge_nodes = {node.get("source_node_id"): node.get("node_id") for node in normalized_nodes}
    normalized_edges = []
    for edge in edges:
        new_edge = dict(edge)
        new_edge["source_node_id"] = edge_nodes.get(edge.get("source"), "unresolved")
        new_edge["target_node_id"] = edge_nodes.get(edge.get("target"), "unresolved")
        normalized_edges.append(new_edge)

    it_nodes = [n for n in normalized_nodes if not n.get("industrial")]
    ot_nodes = [n for n in normalized_nodes if n.get("industrial")]
    deployment_properties = {
        node.get("id", f"node-{idx}"): (node.get("properties") or {})
        for idx, node in enumerate(base_scenario.get("nodes") or [], start=1)
    }
    industrial_linkages = []
    for node in ot_nodes:
        industrial_linkages.append(
            {
                "ot_node_id": node.get("node_id", "unknown"),
                "ot_node_name": node.get("name", "unknown"),
                "linked_to": edge_nodes.get(node.get("linked_to"), node.get("linked_to") or "unresolved"),
                "relationship_status": "confirmed" if node.get("linked_to") else "unresolved",
            }
        )

    node_types = sorted({str(node.get("type", "unknown")) for node in normalized_nodes})
    node_roles = sorted({str(node.get("type", "unknown")) for node in normalized_nodes})
    node_instance_bindings = _infer_node_bindings(normalized_nodes, tmp_tools, installed_tools, id_mapping=id_mapping)

    bom.update(
        {
            "scenario_id": scenario_id,
            "scenario_name": scenario_name,
            "id_origin": scenario_origin,
            "generated_at": utc_now(),
            "base_scenario_path": relative_path(base_path),
            "nodes": normalized_nodes,
            "edges": normalized_edges,
            "it_nodes": it_nodes,
            "ot_nodes": ot_nodes,
            "node_roles": node_roles,
            "node_types": node_types,
            "deployment_properties": deployment_properties,
            "ot_extensions": ot_nodes,
            "industrial_linkages": industrial_linkages,
            "node_instance_bindings": node_instance_bindings,
            "scenario_state": {
                "industrial_state": industrial_state or {},
                "industrial_deployment": industrial_scenario.get("deployment") or {},
            },
            "source_files": [
                relative_path(base_path),
                relative_path(industrial_path) if industrial_path.exists() else "industrial-scenario/scenarios/industrial_*.json",
                relative_path(industrial_state_path),
            ],
            "warnings": warnings,
        }
    )

    context = {
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "nodes": normalized_nodes,
        "node_by_name": {_normalize_name(n.get("name", "")): n for n in normalized_nodes if n.get("name")},
        "node_by_id": {n.get("node_id"): n for n in normalized_nodes if n.get("node_id")},
        "node_by_source_id": {n.get("source_node_id"): n for n in normalized_nodes if n.get("source_node_id")},
        "node_instance_bindings": node_instance_bindings,
    }
    return bom, context


def _infer_log_status(log_path: Path) -> str:
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore").lower()
    except Exception:
        return "unknown"
    if any(token in text for token in ("[success]", "instalado exitosamente", "instalado con exito", "éxito", "exito:")):
        return "completed"
    if any(token in text for token in ("fatal:", "failed!", "[fail]", "non-zero return code")):
        return "failed"
    if "error:" in text and "failed=0" not in text:
        return "failed"
    if "success" in text or "instalado" in text or "play recap" in text:
        return "completed"
    return "unknown"


def _match_instance_log(name_part: str, instance_name: str) -> str | None:
    pattern = re.escape(instance_name)
    pattern = pattern.replace(r"\ ", r"[ _-]+").replace(r"\_", r"[ _-]+").replace(r"\-", r"[ _-]+")
    match = re.match(rf"^{pattern}(?:[ _-]+(?P<tool>.*))?$", name_part, flags=re.IGNORECASE)
    if not match:
        return None
    return (match.group("tool") or "unknown").strip() or "unknown"


def build_tools_bom(scenario_context: dict, id_mapping: dict | None = None) -> dict:
    warnings: list[dict] = []
    bom = clone(empty_tools_bom())
    generated_at = utc_now()

    tmp_files = _load_tmp_tool_files(warnings)
    installed_files = _load_installed_tool_files(warnings)
    log_files = sorted(project_path("tools-installer", "logs").glob("*.log"))

    node_map: dict[str, dict] = {}
    orphan_tool_artifacts: list[dict] = []
    historical_tool_artifacts: list[dict] = []
    host_tool_artifacts: list[dict] = []

    def ensure_node(instance_id: str, instance_name: str, node_type: str) -> dict:
        key = instance_id or _normalize_name(instance_name) or f"unresolved-{len(node_map)+1}"
        if key not in node_map:
            node_map[key] = {
                "instance_id": instance_id or "unresolved",
                "instance_name": instance_name or "unknown",
                "node_type": node_type or _infer_type_from_name(instance_name),
                "desired_tools": [],
                "installed_tools": [],
                "failed_tools": [],
                "pending_tools": [],
                "installation_logs": [],
                "tool_status_map": {},
                "log_status_map": {},
                "log_sources": {},
                "installed_timestamps": {},
                "ip": "not_available",
                "ip_private": "not_available",
                "ip_floating": "not_available",
                "tool_states": [],
            }
        return node_map[key]

    def classify_aux_artifact(source_path: str, artifact_type: str, reason: str, instance_name: str = "not_available", instance_id: str = "not_available"):
        entry = {
            "source_path": source_path,
            "artifact_type": artifact_type,
            "instance_name": instance_name,
            "instance_id": instance_id,
            "relationship_status": reason,
        }
        path_lower = source_path.lower()
        if "host_manage" in path_lower:
            host_tool_artifacts.append({**entry, "relationship_status": "host_level"})
        elif artifact_type == "tools_log":
            historical_tool_artifacts.append(entry)
        else:
            orphan_tool_artifacts.append(entry)

    node_by_name = scenario_context.get("node_by_name", {})
    bindings = scenario_context.get("node_instance_bindings", []) or []
    active_bindings = [item for item in bindings if item.get("status") == "bound"]
    binding_by_name = {_normalize_name(item.get("instance_name") or item.get("node_name") or ""): item for item in active_bindings}
    binding_by_instance = {item.get("openstack_instance_id"): item for item in active_bindings if item.get("openstack_instance_id") not in {"not_available", None, ""}}
    canonical_tmp_by_name = {
        _normalize_name(item.get("instance_name") or item.get("node_name") or ""): _safe_instance_filename(item.get("instance_name") or item.get("node_name") or "")
        for item in active_bindings
    }

    # Seed only the real scenario-bound nodes first so logs cannot create pseudo-nodes.
    for binding in active_bindings:
        node_name = binding.get("node_name") or binding.get("instance_name") or "unknown"
        instance_name = binding.get("instance_name") or node_name
        node_type = (
            node_by_name.get(_normalize_name(node_name), {}).get("type")
            or node_by_name.get(_normalize_name(instance_name), {}).get("type")
            or _infer_type_from_name(instance_name)
        )
        node = ensure_node(binding.get("instance_id") or "unresolved", instance_name, node_type)
        node["openstack_instance_id"] = binding.get("openstack_instance_id", "not_available")
        node["id_origin"] = binding.get("id_origin", "unknown")
        node["node_name"] = node_name

    for record in tmp_files:
        instance_id = record.get("id") or "unresolved"
        instance_name = record.get("name") or "unknown"
        binding = binding_by_instance.get(instance_id) or binding_by_name.get(_normalize_name(instance_name))
        if not binding:
            classify_aux_artifact(record["_source_path"], "tools_tmp", "unmatched_active_instance", instance_name=instance_name, instance_id=instance_id)
            continue
        if Path(record["_source_path"]).name != canonical_tmp_by_name.get(_normalize_name(instance_name), ""):
            historical_tool_artifacts.append(
                {
                    "source_path": record["_source_path"],
                    "artifact_type": "tools_tmp",
                    "instance_name": instance_name,
                    "instance_id": instance_id,
                    "relationship_status": "noncanonical_tmp_source",
                }
            )
            continue
        normalized_instance_id = f"inst-{instance_id[:8]}" if instance_id and instance_id != "unresolved" else make_id("inst", instance_name, record.get("ip") or record.get("ip_floating") or "")
        raw_type = record.get("type") or ""
        node_type = raw_type if raw_type and raw_type != "generic" else (node_by_name.get(_normalize_name(instance_name), {}).get("type") or _infer_type_from_name(instance_name))
        node = ensure_node(normalized_instance_id, instance_name, node_type)
        node["openstack_instance_id"] = instance_id
        node["id_origin"] = "derived_from_existing_id" if instance_id and instance_id != "unresolved" else "derived_from_hash"
        node["ip"] = record.get("ip") or node.get("ip", "not_available")
        node["ip_private"] = record.get("ip_private") or node.get("ip_private", "not_available")
        node["ip_floating"] = record.get("ip_floating") or node.get("ip_floating", "not_available")
        node["node_name"] = binding.get("node_name", node.get("node_name", instance_name))
        desired = record.get("tools") or {}
        for tool_name, state in desired.items():
            normalized_tool_id = f"tool-{tool_name.strip().lower().replace(' ', '_')}"
            if normalized_tool_id not in node["desired_tools"]:
                node["desired_tools"].append(normalized_tool_id)
            current_state = str(state).strip().lower()
            node["tool_status_map"][normalized_tool_id] = current_state
            if current_state == "installed":
                if normalized_tool_id not in node["installed_tools"]:
                    node["installed_tools"].append(normalized_tool_id)
                if normalized_tool_id in node["pending_tools"]:
                    node["pending_tools"].remove(normalized_tool_id)
                if normalized_tool_id in node["failed_tools"]:
                    node["failed_tools"].remove(normalized_tool_id)
            elif current_state in {"pending", "installing", "uninstalling"}:
                if normalized_tool_id not in node["pending_tools"]:
                    node["pending_tools"].append(normalized_tool_id)
            elif current_state in {"error", "failed"}:
                if normalized_tool_id not in node["failed_tools"]:
                    node["failed_tools"].append(normalized_tool_id)

    for record in installed_files:
        instance_id = record.get("instance_id") or "unresolved"
        instance_name = record.get("instance_name") or "unknown"
        binding = binding_by_instance.get(instance_id) or binding_by_name.get(_normalize_name(instance_name))
        if not binding:
            classify_aux_artifact(record["_source_path"], "tools_installed", "unmatched_active_instance", instance_name=instance_name, instance_id=instance_id)
            continue
        normalized_instance_id = f"inst-{instance_id[:8]}" if instance_id and instance_id != "unresolved" else make_id("inst", instance_name)
        node_type = node_by_name.get(_normalize_name(instance_name), {}).get("type") or _infer_type_from_name(instance_name)
        node = ensure_node(normalized_instance_id, instance_name, node_type)
        node["openstack_instance_id"] = instance_id
        node["id_origin"] = "derived_from_existing_id" if instance_id and instance_id != "unresolved" else "derived_from_hash"
        installed = record.get("installed_tools") or {}
        for tool_name, installed_at in installed.items():
            normalized_tool_id = f"tool-{tool_name.strip().lower().replace(' ', '_')}"
            if normalized_tool_id not in node["installed_tools"]:
                node["installed_tools"].append(normalized_tool_id)
            node["installed_timestamps"][normalized_tool_id] = installed_at
            if normalized_tool_id not in node["desired_tools"]:
                node["desired_tools"].append(normalized_tool_id)
            if normalized_tool_id in node["pending_tools"]:
                node["pending_tools"].remove(normalized_tool_id)
            if normalized_tool_id in node["failed_tools"] and node["tool_status_map"].get(normalized_tool_id) not in {"error", "failed"}:
                node["failed_tools"].remove(normalized_tool_id)

    known_nodes = []
    for node in node_map.values():
        known_nodes.append(
            {
                "instance_name": node["instance_name"],
                "norm_name": _normalize_name(node["instance_name"]),
                "node": node,
            }
        )

    for log_path in log_files:
        rel = relative_path(log_path)
        name_part = log_path.stem
        match = None
        for candidate in sorted(known_nodes, key=lambda item: len(item["instance_name"]), reverse=True):
            tool_match = _match_instance_log(name_part, candidate["instance_name"])
            if tool_match is not None:
                match = candidate
                tool_name = tool_match
                break

        if match:
            instance_name = match["instance_name"]
            node = match["node"]
        else:
            classify_aux_artifact(rel, "tools_log", "unmatched_active_instance", instance_name=name_part, instance_id="not_available")
            continue

        node["installation_logs"].append(rel)
        normalized_tool_id = f"tool-{tool_name.strip().lower().replace(' ', '_')}" if tool_name != "unknown" else "tool-unknown"
        if normalized_tool_id != "tool-unknown":
            log_status = _infer_log_status(log_path)
            node["log_status_map"][normalized_tool_id] = log_status
            node["log_sources"][normalized_tool_id] = rel

    for node in node_map.values():
        all_tools = sorted(set(node.get("desired_tools", [])) | set(node.get("installed_tools", [])) | set(node.get("failed_tools", [])) | set(node.get("pending_tools", [])) | set(node.get("tool_status_map", {}).keys()))
        tool_states = []
        for tool_id in all_tools:
            tmp_state = node.get("tool_status_map", {}).get(tool_id)
            log_state = node.get("log_status_map", {}).get(tool_id)
            installed_ts = node.get("installed_timestamps", {}).get(tool_id)
            installed_present = tool_id in node.get("installed_tools", [])
            failed_present = tool_id in node.get("failed_tools", [])
            pending_present = tool_id in node.get("pending_tools", [])
            desired_present = tool_id in node.get("desired_tools", [])

            state = "desired_only"
            recommended_action = "none"
            failed_source = "not_available"
            installed_source = "not_available"
            desired_source = "not_available"
            current_state = tmp_state or log_state or "not_available"

            if desired_present:
                desired_source = "tools-installer-tmp"
            if installed_present:
                installed_source = f"tools-installer/installed/{node.get('openstack_instance_id', 'unknown')}.json"
            if failed_present or tmp_state in {"failed", "error"} or log_state == "failed":
                failed_source = node.get("log_sources", {}).get(tool_id, "tools-installer/logs")

            if installed_present and (failed_present or log_state == "failed"):
                state = "state_conflict"
                recommended_action = "inspect installation log and installed JSON"
            elif installed_present or tmp_state == "installed":
                state = "installed"
            elif failed_present or tmp_state in {"failed", "error"}:
                state = "failed"
                recommended_action = "inspect installation log"
            elif pending_present or tmp_state in {"pending", "installing", "uninstalling"}:
                state = "pending"
                recommended_action = "wait for or complete installation workflow"

            if installed_present and not installed_ts:
                installed_ts = "not_available"

            tool_states.append(
                {
                    "tool_id": tool_id,
                    "state": state,
                    "current_state": current_state,
                    "installed_timestamp": installed_ts or "not_available",
                    "desired_source": desired_source,
                    "installed_source": installed_source,
                    "failed_source": failed_source,
                    "recommended_action": recommended_action,
                }
            )
        node["tool_states"] = tool_states

    bom.update(
        {
            "scenario_id": scenario_context.get("scenario_id", "unknown"),
            "generated_at": generated_at,
            "nodes": sorted([
                {
                    **node,
                    "desired_tools": sorted(set(node.get("desired_tools", []))),
                    "installed_tools": sorted(set(node.get("installed_tools", []))),
                    "failed_tools": sorted(set(node.get("failed_tools", []))),
                    "pending_tools": sorted(set(node.get("pending_tools", []))),
                    "installation_logs": sorted(set(node.get("installation_logs", []))),
                }
                for node in node_map.values()
            ], key=lambda item: item.get("instance_name", "")),
            "active_nodes_count": len(node_map),
            "orphan_tool_artifacts": orphan_tool_artifacts,
            "historical_tool_artifacts": historical_tool_artifacts,
            "host_tool_artifacts": host_tool_artifacts,
            "host_tool_inventory": [],
            "source_files": (
                [record["_source_path"] for record in tmp_files]
                + [record["_source_path"] for record in installed_files]
                + [relative_path(path) for path in log_files]
            ),
            "warnings": warnings,
        }
    )
    return bom
