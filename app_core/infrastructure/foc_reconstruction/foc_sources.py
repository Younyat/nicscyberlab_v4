import json
from pathlib import Path
import re

from .foc_hashing import safe_sha256
from .foc_paths import SOURCE_DEFINITIONS, existing_paths, relative_path
from .foc_schema import clone, empty_source_reference


def utc_now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def safe_stat(path: Path) -> dict:
    try:
        st = path.stat()
        return {"mtime": st.st_mtime, "size": st.st_size}
    except Exception:
        return {"mtime": None, "size": None}


def read_json_file(path: Path, warnings: list[dict]) -> dict | list | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except Exception as exc:
        warnings.append(
            {
                "kind": "json_read_error",
                "path": relative_path(path),
                "message": str(exc),
            }
        )
        return None


def read_jsonl_file(path: Path, warnings: list[dict]) -> list[dict]:
    out: list[dict] = []
    try:
        with path.open("r", encoding="utf-8") as fh:
            for idx, line in enumerate(fh, start=1):
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception as exc:
                    warnings.append(
                        {
                            "kind": "jsonl_line_error",
                            "path": relative_path(path),
                            "line": idx,
                            "message": str(exc),
                        }
                    )
    except FileNotFoundError:
        return out
    except Exception as exc:
        warnings.append(
            {
                "kind": "jsonl_read_error",
                "path": relative_path(path),
                "message": str(exc),
            }
        )
    return out


def build_source_reference(path: Path, source_type: str, kind: str) -> dict:
    ref = clone(empty_source_reference())
    ref["source_id"] = f"src::{source_type}::{relative_path(path)}"
    ref["source_type"] = source_type
    ref["path"] = relative_path(path)
    ref["kind"] = kind
    ref["status"] = "present"
    stats = safe_stat(path)
    ref["mtime"] = stats["mtime"]
    ref["size"] = stats["size"]
    sha256, hash_reason = safe_sha256(path, stats["size"]) if kind == "file" else (None, "directory")
    ref["sha256"] = sha256
    ref["details"] = {"hash_reason": hash_reason}
    return ref


def _pattern_base_dir(pattern: str) -> Path | None:
    parts = []
    for part in Path(pattern).parts:
        if re.search(r"[\*\?\[]", part):
            break
        parts.append(part)
    if not parts:
        return None
    return Path(*parts)


def collect_sources() -> dict:
    warnings: list[dict] = []
    sources: list[dict] = []
    cases: list[dict] = []

    for definition in SOURCE_DEFINITIONS:
        paths = existing_paths(definition["pattern"])
        if not paths:
            ref = clone(empty_source_reference())
            ref["source_id"] = f"src::{definition['source_type']}::{definition['pattern']}"
            ref["source_type"] = definition["source_type"]
            ref["path"] = definition["pattern"]
            ref["kind"] = definition["kind"]
            base_dir = _pattern_base_dir(definition["pattern"])
            base_exists = (base_dir is not None and base_dir.is_dir())
            ref["status"] = "empty" if base_exists else "missing"
            ref["details"] = {"pattern": definition["pattern"], "base_dir": str(base_dir) if base_dir else None}
            sources.append(ref)
            continue

        for path in paths:
            ref = build_source_reference(path, definition["source_type"], definition["kind"])
            if definition["source_type"] == "forensics_case_dir":
                case_id = path.name
                ref["details"]["case_id"] = case_id
                manifest_path = path / "manifest.json"
                pipeline_path = path / "metadata" / "pipeline_events.jsonl"
                custody_path = path / "chain_of_custody.log"
                case_info = {
                    "case_id": case_id,
                    "path": ref["path"],
                    "manifest_present": manifest_path.is_file(),
                    "pipeline_present": pipeline_path.is_file(),
                    "custody_present": custody_path.is_file(),
                }
                cases.append(case_info)
            sources.append(ref)

    generated_at = utc_now()
    status = "ok" if not warnings else "warnings"
    return {
        "generated_at": generated_at,
        "status": status,
        "warnings": warnings,
        "sources": sources,
        "cases": cases,
    }
