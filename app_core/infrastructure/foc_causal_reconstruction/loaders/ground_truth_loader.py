from __future__ import annotations

import json
from pathlib import Path

from ..config import SCENARIOS_ROOT


def _load_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


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

    for candidate in normalized_candidates:
        payload = _load_json(candidate)
        if not isinstance(payload, dict):
            continue
        expected_edges = payload.get("expected_edges")
        if isinstance(expected_edges, list) and expected_edges:
            return {
                "status": "ok",
                "path": candidate,
                "payload": payload,
                "checked_paths": [str(path) for path in normalized_candidates],
            }
        return {
            "status": "missing_expected_edges",
            "path": candidate,
            "payload": payload,
            "checked_paths": [str(path) for path in normalized_candidates],
            "reason": "scenario_ground_truth.json exists but does not declare expected_edges.",
        }
    return {
        "status": "missing",
        "path": None,
        "payload": None,
        "checked_paths": [str(path) for path in normalized_candidates],
        "reason": "No scenario_ground_truth.json was found in the checked scenario paths.",
    }
