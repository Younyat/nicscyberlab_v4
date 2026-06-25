from __future__ import annotations

import json
from pathlib import Path

from .baseline_noise import build_baseline_noise_profile
from .config import LEGACY_COMPARISON_REGISTRY_PATH, RESULT_REGISTRY_PATH
from .ground_truth_seal import build_ground_truth_seal
from .profile_builder import build_execution_profiles, load_case_bundle
from .scientific_memory import (
    build_forensic_result_card as build_forensic_result_card_payload,
    compute_comparison_family_id,
    compute_scenario_fingerprint,
    ensure_scientific_memory_layout,
    load_registry as load_scientific_registry,
)


def _json_load(path: Path | None):
    try:
        if path is None or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def load_registry() -> dict:
    ensure_scientific_memory_layout()
    registry = load_scientific_registry(RESULT_REGISTRY_PATH)
    # Keep the legacy path in sync for backward compatibility with earlier UI/API consumers.
    legacy = load_scientific_registry(LEGACY_COMPARISON_REGISTRY_PATH)
    if len(legacy.get("entries", [])) > len(registry.get("entries", [])):
        return legacy
    return registry


def append_to_registry(result_card: dict) -> dict:
    from .scientific_memory import load_registry as load_memory_registry

    ensure_scientific_memory_layout()
    for registry_path in (RESULT_REGISTRY_PATH, LEGACY_COMPARISON_REGISTRY_PATH):
        registry = load_memory_registry(registry_path)
        entries = [
            item
            for item in registry.get("entries", [])
            if item.get("execution_id") != result_card.get("execution_id")
            and item.get("result_card_id") != result_card.get("result_card_id")
        ]
        entries.append(result_card)
        _write_json(registry_path, {"generated_at": load_memory_registry(registry_path).get("generated_at"), "entries": entries})
    registry = load_memory_registry(RESULT_REGISTRY_PATH)
    return registry


def build_forensic_result_card(**kwargs) -> dict:
    return build_forensic_result_card_payload(**kwargs)


def find_comparable_families(
    *,
    scenario_fingerprint: str | None = None,
    scenario_id: str | None = None,
    expected_edges: list | None = None,
    exclude_execution_id: str | None = None,
) -> list[dict]:
    entries = load_registry().get("entries", [])
    matches = [
        item
        for item in entries
        if (
            (scenario_fingerprint and item.get("scenario_fingerprint") == scenario_fingerprint)
            or (not scenario_fingerprint and scenario_id and item.get("scenario_id") == scenario_id)
            or (not scenario_fingerprint and not scenario_id)
        )
        and item.get("execution_id") != exclude_execution_id
    ]
    matches.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
    return matches


def find_recommended_comparable_result(
    *,
    scenario_id: str,
    scenario_fingerprint: str | None = None,
    attack_profile_id: str | None = None,
    trigger_policy: str | None = None,
    acquisition_profile_id: str | None = None,
) -> dict | None:
    matches = find_comparable_families(scenario_fingerprint=scenario_fingerprint, scenario_id=scenario_id)
    if not matches:
        return None

    def score(item: dict) -> tuple[int, str]:
        exact = 0
        if attack_profile_id and item.get("attack_profile_id") == attack_profile_id:
            exact += 3
        if trigger_policy and item.get("trigger_policy") == trigger_policy:
            exact += 2
        if acquisition_profile_id and item.get("acquisition_profile_id") == acquisition_profile_id:
            exact += 2
        return (exact, str(item.get("created_at") or ""))

    matches.sort(key=score, reverse=True)
    return matches[0]


def register_existing_case_as_result_card(case_id: str) -> dict:
    case_bundle = load_case_bundle(case_id=case_id)
    if not case_bundle:
        return {"error": "case_not_found", "case_id": case_id}

    case_dir = Path(case_bundle["case_path"])
    execution_dir = case_dir / "derived" / "experimentation"
    execution_dir.mkdir(parents=True, exist_ok=True)
    execution_id = f"REGISTERED-{case_bundle['case_id']}"

    profile_result = build_execution_profiles(
        execution_id=execution_id,
        campaign_id="not_applicable_registered_case",
        level="A",
        execution_dir=execution_dir,
        case_bundle=case_bundle,
        baseline_noise_enabled=False,
        baseline_window_seconds=60,
        baseline_threshold=0.15,
        baseline_builder=build_baseline_noise_profile,
        seal_builder=build_ground_truth_seal,
        campaign_config={
            "analysis_profile_id": "default_multilayer_analysis_v1",
            "foc_profile_id": "default_foc_causal_reconstruction_v1",
            "trigger_policy_id": "highest_severity_alert_v1",
            "acquisition_profile_id": "default_kolla_lime_tshark_v1",
            "detection_policy_id": "wazuh_suricata_alert_ingestion_v1",
        },
    )
    if profile_result.get("status") != "ok":
        return {"error": "insufficient_case_data", "case_id": case_id, "details": profile_result.get("warnings")}

    result_card = _json_load(execution_dir / "forensic_result_card.json")
    if not result_card:
        return {"error": "result_card_not_generated", "case_id": case_id}
    return result_card
