from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ..config import SCENARIOS_ROOT


def _load_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_expected_edges(expected_edges: list) -> tuple[str, str | None]:
    if not isinstance(expected_edges, list) or not expected_edges:
        return "invalid", "expected_edges is missing or empty."
    required_keys = {"edge_id", "source", "target", "required_evidence"}
    for index, edge in enumerate(expected_edges):
        if not isinstance(edge, dict):
            return "invalid", f"expected_edges[{index}] is not an object."
        missing_keys = required_keys - edge.keys()
        if missing_keys:
            return "invalid", f"expected_edges[{index}] is missing required keys: {sorted(missing_keys)}."
    return "valid", None


def resolve_ground_truth(
    scenario_id: str,
    scenario_name: str,
    preserved_ground_truth_path: Path | None = None,
    explicit_path: str | None = None,
) -> dict:
    candidates: list[Path] = []
    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())
    if scenario_id and scenario_id != "unknown":
        candidates.append(SCENARIOS_ROOT / scenario_id / "scenario_ground_truth.json")
    if scenario_name and scenario_name != "unknown":
        candidates.append(SCENARIOS_ROOT / scenario_name / "scenario_ground_truth.json")
    if preserved_ground_truth_path:
        candidates.append(Path(preserved_ground_truth_path))

    seen: set[str] = set()
    normalized_candidates: list[Path] = []
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        normalized_candidates.append(candidate)

    loaded_at = _now_iso()
    for candidate in normalized_candidates:
        payload = _load_json(candidate)
        if not isinstance(payload, dict):
            continue
        expected_edges = payload.get("expected_edges")
        validation_status, validation_reason = _validate_expected_edges(expected_edges)
        if validation_status == "valid":
            return {
                "status": "ok",
                "path": candidate,
                "payload": payload,
                "checked_paths": [str(path) for path in normalized_candidates],
                "version": payload.get("ground_truth_version"),
                "loaded_at": loaded_at,
                "validation_status": validation_status,
                "validation_reason": None,
            }
        return {
            "status": "missing_expected_edges",
            "path": candidate,
            "payload": payload,
            "checked_paths": [str(path) for path in normalized_candidates],
            "reason": "scenario_ground_truth.json exists but does not declare valid expected_edges.",
            "version": payload.get("ground_truth_version"),
            "loaded_at": loaded_at,
            "validation_status": validation_status,
            "validation_reason": validation_reason,
        }
    return {
        "status": "missing",
        "path": None,
        "payload": None,
        "checked_paths": [str(path) for path in normalized_candidates],
        "reason": "No scenario_ground_truth.json was found in the checked scenario paths.",
        "version": None,
        "loaded_at": loaded_at,
        "validation_status": "invalid",
        "validation_reason": "No scenario_ground_truth.json was found.",
    }
