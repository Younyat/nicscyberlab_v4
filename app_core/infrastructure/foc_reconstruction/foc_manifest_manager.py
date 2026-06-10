import json
import logging
from pathlib import Path

from .foc_bootstrap import bootstrap_existing_context, read_id_mapping
from .foc_bom_builder import build_scenario_bom, build_tools_bom
from .foc_config import GENERATED_FILES, READ_ONLY_MODE, ensure_output_layout
from .foc_events import record_foc_event
from .foc_hashing import hash_file
from .foc_indexer import build_indexes
from .foc_paths import generated_relative_paths, relative_path
from .foc_schema import clone, empty_foc_manifest
from .foc_sources import collect_sources, utc_now
from .foc_timeline_builder import build_timeline

logger = logging.getLogger(__name__)


def _write_json(path: Path, payload: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False, sort_keys=False)


def _safe_read_json(path: Path) -> dict | list | None:
    try:
        if not path.is_file():
            return None
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _lifecycle_state(sources_bundle: dict) -> str:
    paths = {item.get("path"): item for item in sources_bundle.get("sources", [])}
    scenario_ref = paths.get("scenario/scenario_file.json", {})
    if scenario_ref.get("status") == "present":
        deployment_ref = paths.get("scenario/deployment_status.json", {})
        destroy_ref = paths.get("scenario/destroy_status.json", {})
        if (deployment_ref.get("mtime") or 0) >= (destroy_ref.get("mtime") or 0):
            return "active"
        destroy = _safe_read_json(Path(destroy_ref.get("path", "")))
        if isinstance(destroy, dict) and str(destroy.get("status", "")).lower() == "success":
            return "destroyed"
        return "active"
    return "unknown"


def _hash_generated_file(path: Path) -> str:
    return hash_file(path) if path.is_file() else ""


def regenerate_foc(bootstrap_mode: bool = False) -> dict:
    ensure_output_layout()
    warnings: list[dict] = []
    id_mapping = read_id_mapping()
    if id_mapping is None:
        bootstrap_existing_context(force=False)
        id_mapping = read_id_mapping() or {"generated_at": utc_now(), "bootstrap_mode": True, "mappings": {}, "warnings": []}

    scenario_bom, scenario_context = build_scenario_bom(id_mapping=id_mapping)
    tools_bom = build_tools_bom(scenario_context, id_mapping=id_mapping)
    timeline = build_timeline(scenario_context, id_mapping=id_mapping)
    sources_bundle = collect_sources()
    indexes = build_indexes(scenario_bom, tools_bom, timeline, sources_bundle, id_mapping=id_mapping)

    _write_json(GENERATED_FILES["scenario_bom"], scenario_bom)
    _write_json(GENERATED_FILES["tools_bom"], tools_bom)
    _write_json(GENERATED_FILES["timeline"], timeline)
    _write_json(GENERATED_FILES["id_mapping"], id_mapping)
    _write_json(GENERATED_FILES["sources_index"], indexes["sources_index"])
    _write_json(GENERATED_FILES["artifacts_index"], indexes["artifacts_index"])
    _write_json(GENERATED_FILES["relationships_index"], indexes["relationships_index"])
    _write_json(GENERATED_FILES["cases_index"], indexes["cases_index"])

    hashes_payload = {
        "generated_at": utc_now(),
        "hashes": {
            relative_path(path): _hash_generated_file(path)
            for path in GENERATED_FILES.values()
            if path.name != "foc_manifest.json"
        },
    }
    _write_json(GENERATED_FILES["hashes_index"], hashes_payload)

    existing_manifest = _safe_read_json(GENERATED_FILES["manifest"])
    manifest = clone(empty_foc_manifest())
    if isinstance(existing_manifest, dict) and existing_manifest.get("created_at"):
        manifest["created_at"] = existing_manifest["created_at"]
    else:
        manifest["created_at"] = utc_now()

    manifest["foc_id"] = f"foc-{scenario_context.get('scenario_id', 'unknown')}"
    manifest["scenario_id"] = scenario_context.get("scenario_id", "unknown")
    manifest["scenario_name"] = scenario_context.get("scenario_name", "unknown")
    manifest["updated_at"] = utc_now()
    manifest["reconstructed_at"] = utc_now()
    manifest["lifecycle_state"] = _lifecycle_state(sources_bundle)
    manifest["read_only_reconstruction"] = READ_ONLY_MODE
    manifest["bootstrap_mode"] = bool(bootstrap_mode or id_mapping.get("bootstrap_mode"))
    manifest["id_mapping_path"] = generated_relative_paths()["id_mapping"]
    manifest["scenario_bom"]["sha256"] = _hash_generated_file(GENERATED_FILES["scenario_bom"])
    manifest["tools_bom"]["sha256"] = _hash_generated_file(GENERATED_FILES["tools_bom"])
    manifest["timeline"]["sha256"] = _hash_generated_file(GENERATED_FILES["timeline"])
    manifest["warnings"] = (
        id_mapping.get("warnings", [])
        + 
        scenario_bom.get("warnings", [])
        + tools_bom.get("warnings", [])
        + timeline.get("warnings", [])
        + sources_bundle.get("warnings", [])
        + indexes.get("warnings", [])
        + warnings
    )
    manifest["generation_status"] = "warnings" if manifest["warnings"] else "ok"
    manifest["source_indexes"] = {
        "sources": generated_relative_paths()["sources_index"],
        "artifacts": generated_relative_paths()["artifacts_index"],
        "relationships": generated_relative_paths()["relationships_index"],
        "cases": generated_relative_paths()["cases_index"],
    }

    _write_json(GENERATED_FILES["manifest"], manifest)
    hashes_payload["hashes"][relative_path(GENERATED_FILES["manifest"])] = _hash_generated_file(GENERATED_FILES["manifest"])
    _write_json(GENERATED_FILES["hashes_index"], hashes_payload)
    record_foc_event(
        "foc_regenerated",
        {
            "scenario_id": manifest["scenario_id"],
            "bootstrap_mode": manifest["bootstrap_mode"],
            "generation_status": manifest["generation_status"],
        },
    )
    logger.info("FOC regeneration completed with status=%s", manifest["generation_status"])
    return manifest


def read_generated_json(path: Path) -> dict | list | None:
    return _safe_read_json(path)
