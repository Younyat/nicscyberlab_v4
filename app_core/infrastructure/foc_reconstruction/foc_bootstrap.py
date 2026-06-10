import hashlib
import json
import shutil
from pathlib import Path

from .foc_config import FOC_OUTPUT_DIR, GENERATED_FILES, ensure_output_layout
from .foc_events import record_foc_event
from .foc_paths import project_path, relative_path
from .foc_sources import collect_sources, read_json_file, utc_now


def _short_hash(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()[:8]


def make_id(prefix: str, *parts: str) -> str:
    seed = "|".join(str(part or "") for part in parts)
    return f"{prefix}-{_short_hash(seed)}"


def has_existing_foc_manifest() -> bool:
    return GENERATED_FILES["manifest"].is_file()


def detect_existing_sources() -> dict:
    return collect_sources()


def _file_hash_seed(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        try:
            st = path.stat()
            return f"{relative_path(path)}|{st.st_size}|{st.st_mtime}"
        except Exception:
            return relative_path(path)


def _scenario_mapping(warnings: list[dict]) -> dict:
    scenario_path = project_path("scenario", "scenario_file.json")
    industrial_paths = sorted(project_path("industrial-scenario", "scenarios").glob("industrial_*.json"))
    scenario_data = read_json_file(scenario_path, warnings) if scenario_path.is_file() else {}
    industrial_data = read_json_file(industrial_paths[-1], warnings) if industrial_paths else {}
    scenario_name = (industrial_data or {}).get("scenario_name") or (scenario_data or {}).get("scenario_name") or "unknown"
    scenario_id = make_id("scn", _file_hash_seed(scenario_path), scenario_name)
    return {
        "scenario_id": scenario_id,
        "scenario_name": scenario_name,
        "source_path": relative_path(scenario_path),
        "id_origin": "derived_from_hash",
        "origin_basis": "scenario_file",
    }


def _tool_id(tool_name: str) -> dict:
    return {
        "tool_id": f"tool-{(tool_name or 'unknown').strip().lower().replace(' ', '_')}",
        "tool_name": tool_name or "unknown",
        "id_origin": "derived_from_existing_id" if tool_name else "unknown",
    }


def _instance_mapping(instance_name: str, raw_instance_id: str, ip_value: str = "") -> dict:
    raw_instance_id = (raw_instance_id or "").strip()
    if raw_instance_id:
        return {
            "instance_id": f"inst-{raw_instance_id[:8]}",
            "openstack_instance_id": raw_instance_id,
            "id_origin": "derived_from_existing_id",
        }
    return {
        "instance_id": make_id("inst", instance_name, ip_value),
        "openstack_instance_id": "not_available",
        "id_origin": "derived_from_hash",
    }


def derive_missing_ids(sources: dict) -> dict:
    warnings: list[dict] = []
    scenario = _scenario_mapping(warnings)

    mappings = {
        "scenario": scenario,
        "nodes": [],
        "instances": [],
        "tools": [],
        "attacks": [],
        "alerts": [],
        "cases": [],
        "artifacts": [],
    }

    scenario_path = project_path("scenario", "scenario_file.json")
    industrial_paths = sorted(project_path("industrial-scenario", "scenarios").glob("industrial_*.json"))
    scenario_data = read_json_file(scenario_path, warnings) or {}
    industrial_data = read_json_file(industrial_paths[-1], warnings) if industrial_paths else {}
    nodes = (industrial_data or {}).get("nodes") or scenario_data.get("nodes") or []

    tmp_records = []
    for path in sorted(project_path("tools-installer-tmp").glob("*.json")):
        data = read_json_file(path, warnings)
        if isinstance(data, dict):
            tmp_records.append(data)

    installed_records = []
    for path in sorted(project_path("tools-installer", "installed").glob("*.json")):
        data = read_json_file(path, warnings)
        if isinstance(data, dict):
            installed_records.append(data)

    by_name = {}
    for record in tmp_records + installed_records:
        name = record.get("name") or record.get("instance_name") or ""
        if not name:
            continue
        by_name[name.lower()] = record

    seen_tool_names = set()
    for node in nodes:
        source_node_id = node.get("id") or "unknown"
        node_name = node.get("name") or "unknown"
        node_type = node.get("type") or "unknown"
        node_id = make_id("node", source_node_id, node_name, node_type, relative_path(scenario_path))
        instance_record = by_name.get(node_name.lower(), {})
        raw_instance_id = instance_record.get("id") or instance_record.get("instance_id") or ""
        instance_meta = _instance_mapping(node_name, raw_instance_id, instance_record.get("ip") or instance_record.get("ip_floating") or "")
        mappings["nodes"].append(
            {
                "node_id": node_id,
                "source_id": source_node_id,
                "instance_id": instance_meta["instance_id"],
                "openstack_instance_id": instance_meta["openstack_instance_id"],
                "name": node_name,
                "type": node_type,
                "source_path": relative_path(industrial_paths[-1]) if industrial_paths else relative_path(scenario_path),
                "id_origin": "derived_from_existing_id" if source_node_id else "derived_from_hash",
            }
        )
        mappings["instances"].append(
            {
                "instance_id": instance_meta["instance_id"],
                "openstack_instance_id": instance_meta["openstack_instance_id"],
                "name": node_name,
                "id_origin": instance_meta["id_origin"],
            }
        )
        for tool_name in (instance_record.get("tools") or {}).keys():
            if tool_name not in seen_tool_names:
                seen_tool_names.add(tool_name)
                mappings["tools"].append(_tool_id(tool_name))

    for record in installed_records:
        for tool_name in (record.get("installed_tools") or {}).keys():
            if tool_name not in seen_tool_names:
                seen_tool_names.add(tool_name)
                mappings["tools"].append(_tool_id(tool_name))
        path = project_path("tools-installer", "installed", f"{record.get('instance_id')}.json")
        mappings["artifacts"].append(
            {
                "artifact_id": make_id("art", relative_path(path), str(path.stat().st_mtime) if path.exists() else "", str(path.stat().st_size) if path.exists() else ""),
                "artifact_type": "installed_tools",
                "source_path": relative_path(path),
                "id_origin": "derived_from_path",
            }
        )

    for path in sorted(project_path("app_core", "infrastructure", "attack", "outputs").glob("*/result.json")):
        data = read_json_file(path, warnings)
        if not isinstance(data, dict):
            continue
        mappings["attacks"].append(
            {
                "attack_id": make_id("atk", data.get("attack_id") or path.parent.name, relative_path(path)),
                "source_attack_id": data.get("attack_id", "unknown"),
                "source_path": relative_path(path),
                "id_origin": "derived_from_existing_id" if data.get("attack_id") else "derived_from_path",
            }
        )
        mappings["artifacts"].append(
            {
                "artifact_id": make_id("art", relative_path(path), str(path.stat().st_size)),
                "artifact_type": "attack_result",
                "source_path": relative_path(path),
                "id_origin": "derived_from_path",
            }
        )

    for session_dir in sorted(project_path("app_core", "infrastructure", "forensics", "alerts_store").glob("ALERTS-*")):
        alerts_path = session_dir / "alerts.jsonl"
        triage_path = session_dir / "triage.jsonl"
        if alerts_path.is_file():
            for alert in _read_jsonl(alerts_path):
                raw_event_id = alert.get("event_id") or relative_path(alerts_path)
                mappings["alerts"].append(
                    {
                        "alert_id": f"alr-{str(raw_event_id)[:8]}" if alert.get("event_id") else make_id("alr", raw_event_id),
                        "source_event_id": alert.get("event_id", "unknown"),
                        "source_path": relative_path(alerts_path),
                        "id_origin": "derived_from_existing_id" if alert.get("event_id") else "derived_from_path",
                    }
                )
        if triage_path.is_file():
            mappings["artifacts"].append(
                {
                    "artifact_id": make_id("art", relative_path(triage_path), str(triage_path.stat().st_size)),
                    "artifact_type": "triage_log",
                    "source_path": relative_path(triage_path),
                    "id_origin": "derived_from_path",
                }
            )

    for case_dir in sorted(project_path("app_core", "infrastructure", "forensics", "evidence_store").glob("CASE-*")):
        case_id = make_id("case", case_dir.name)
        mappings["cases"].append(
            {
                "case_id": case_id,
                "source_case_name": case_dir.name,
                "source_path": relative_path(case_dir),
                "id_origin": "derived_from_filename",
            }
        )
        manifest_path = case_dir / "manifest.json"
        mappings["artifacts"].append(
            {
                "artifact_id": make_id("art", relative_path(manifest_path), str(manifest_path.stat().st_size) if manifest_path.exists() else ""),
                "artifact_type": "case_manifest",
                "source_path": relative_path(manifest_path),
                "id_origin": "derived_from_path",
            }
        )

    return {
        "generated_at": utc_now(),
        "bootstrap_mode": True,
        "mappings": mappings,
        "warnings": warnings,
    }


def write_id_mapping(mapping: dict) -> None:
    ensure_output_layout()
    with GENERATED_FILES["id_mapping"].open("w", encoding="utf-8") as fh:
        json.dump(mapping, fh, indent=2, ensure_ascii=False)


def read_id_mapping() -> dict | None:
    try:
        if not GENERATED_FILES["id_mapping"].is_file():
            return None
        with GENERATED_FILES["id_mapping"].open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return out
    return out


def _backup_existing_outputs() -> str:
    ensure_output_layout()
    ts = utc_now().replace(":", "").replace("-", "")
    backup_dir = FOC_OUTPUT_DIR / "backups" / ts
    backup_dir.mkdir(parents=True, exist_ok=True)
    for key, path in GENERATED_FILES.items():
        if path.exists():
            dest = backup_dir / path.relative_to(FOC_OUTPUT_DIR)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
    return relative_path(backup_dir)


def bootstrap_existing_context(force: bool = False) -> dict:
    if has_existing_foc_manifest() and not force:
        return {
            "status": "already_initialized",
            "message": "FOC manifest already exists. Use /api/foc/regenerate to refresh it.",
        }

    backup_path = None
    if has_existing_foc_manifest() and force:
        backup_path = _backup_existing_outputs()

    sources = detect_existing_sources()
    mapping = derive_missing_ids(sources)
    write_id_mapping(mapping)
    result = {
        "status": "bootstrapped",
        "bootstrap_mode": True,
        "id_mapping_path": relative_path(GENERATED_FILES["id_mapping"]),
        "backup_path": backup_path,
        "warnings": mapping.get("warnings", []),
    }
    record_foc_event("foc_bootstrap_completed", result)
    return result
