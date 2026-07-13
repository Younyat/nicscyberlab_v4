from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .config import BLUEPRINTS_DIR, SCENARIO_REGISTRY_PATH
from .scientific_memory import _write_json, load_registry, upsert_registry_entry
from .scientific_memory_sync import get_active_scenario_memory_hint, sync_active_scenario_memory
from ..foc_reconstruction.foc_paths import project_path, relative_path
from ..foc_reconstruction.foc_sources import utc_now


def _json_load(path: Path | None):
    try:
        if path is None or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _scenario_card_path(scenario_fingerprint: str) -> Path:
    return SCENARIO_REGISTRY_PATH.parent / scenario_fingerprint / "scenario_result_card.json"


def _scenario_manifest_path(scenario_fingerprint: str) -> Path:
    return SCENARIO_REGISTRY_PATH.parent / scenario_fingerprint / "scenario_destruction_manifest.json"


def _active_paths() -> dict:
    return {
        "repo_root": project_path(),
        "it_scenario_file": project_path("scenario", "scenario_file.json"),
        "it_destroy_script": project_path("scenario", "destroy_scenario_openstack_mejorado.sh"),
        "industrial_scenario_file": project_path("industrial-scenario", "scenarios", "industrial_industrial_file.json"),
        "industrial_state_file": project_path("industrial-scenario", "state", "industrial_state.json"),
        "admin_openrc": project_path("admin-openrc.sh"),
    }


def _find_scenario_card(scenario_id: str | None = None) -> dict | None:
    registry = load_registry(SCENARIO_REGISTRY_PATH)
    entries = registry.get("entries", [])
    if not entries:
        return None

    _sort_key = lambda item: str(item.get("generated_at") or item.get("created_at") or "")

    if scenario_id:
        matches = [item for item in entries if item.get("scenario_id") == scenario_id]
        if matches:
            return sorted(matches, key=_sort_key, reverse=True)[0]

    active_hint = get_active_scenario_memory_hint()
    active_id = active_hint.get("scenario_id")

    # If the hint returned a sentinel (scenario files deleted after destruction),
    # fall back to the most recent registry entry — the scenario card is still
    # valid and contains the blueprint path needed for Level C redeployment.
    if not active_id or active_id in ("not_available", "unknown", ""):
        return sorted(entries, key=_sort_key, reverse=True)[0]

    matches = [item for item in entries if item.get("scenario_id") == active_id]
    if matches:
        active_matches = [item for item in matches if item.get("active_scenario_exists")]
        if active_matches:
            return sorted(active_matches, key=_sort_key, reverse=True)[0]
        return sorted(matches, key=_sort_key, reverse=True)[0]

    # No match for the active_id either — return most recent entry as last resort
    return sorted(entries, key=_sort_key, reverse=True)[0]


def _scenario_validation_checks(card: dict, blueprint_path: Path, active_hint: dict) -> list[dict]:
    associated_campaigns = list(card.get("associated_campaigns") or [])
    associated_cases = list(card.get("associated_cases") or [])
    associated_result_cards = list(card.get("associated_result_cards") or [])
    return [
        {
            "key": "scenario_result_card",
            "status": "ok" if bool(card) else "missing",
            "why_it_matters": "The scenario card preserves the lightweight scenario memory after destruction.",
            "how_to_fix": "Generate or synchronize scenario_result_card.json before destroying the active environment.",
            "can_be_auto_generated": True,
        },
        {
            "key": "scenario_reconstruction_blueprint",
            "status": "ok" if blueprint_path.is_file() else "missing",
            "why_it_matters": "Level C redeployment needs a valid lightweight blueprint before destroying the current environment.",
            "how_to_fix": "Preserve scenario_reconstruction_blueprint.json before destruction.",
            "can_be_auto_generated": True,
        },
        {
            "key": "scenario_registry_entry",
            "status": "ok" if bool(card.get("scenario_fingerprint")) else "missing",
            "why_it_matters": "The scenario registry preserves the scenario fingerprint and associated references after destruction.",
            "how_to_fix": "Synchronize the scenario registry entry before destruction.",
            "can_be_auto_generated": True,
        },
        {
            "key": "associated_campaigns",
            "status": "ok" if bool(associated_campaigns) else "missing",
            "why_it_matters": "Campaign references should survive destruction for reproducibility traceability.",
            "how_to_fix": "Register the scenario against at least one campaign before destruction when applicable.",
            "can_be_auto_generated": True,
        },
        {
            "key": "associated_cases",
            "status": "ok" if bool(associated_cases) else "missing",
            "why_it_matters": "Associated case references help preserve the scientific history of the scenario.",
            "how_to_fix": "Synchronize case registry links before destruction when cases already exist.",
            "can_be_auto_generated": True,
        },
        {
            "key": "associated_result_cards",
            "status": "ok" if bool(associated_result_cards) else "missing",
            "why_it_matters": "Result-card references preserve comparison continuity after environment destruction.",
            "how_to_fix": "Ensure at least one result card is associated with the scenario before destruction when available.",
            "can_be_auto_generated": True,
        },
        {
            "key": "scenario_fingerprint",
            "status": "ok" if bool(card.get("scenario_fingerprint")) else "missing",
            "why_it_matters": "Scenario drift and redeployment equivalence depend on the preserved fingerprint.",
            "how_to_fix": "Synchronize the scenario card before destruction.",
            "can_be_auto_generated": True,
        },
        {
            "key": "topology_fingerprint",
            "status": "ok" if bool(card.get("topology_fingerprint")) else "missing",
            "why_it_matters": "Topology fingerprint is required for later comparability and drift checks.",
            "how_to_fix": "Synchronize the scenario card before destruction.",
            "can_be_auto_generated": True,
        },
        {
            "key": "redeployment_readiness",
            "status": "ok" if blueprint_path.is_file() and bool(card.get("can_be_redeployed")) else "missing",
            "why_it_matters": "Destroying the active environment without redeployment readiness would block future Level C reconstruction.",
            "how_to_fix": "Preserve a valid scenario reconstruction blueprint before destruction.",
            "can_be_auto_generated": True,
        },
        {
            "key": "active_scenario_exists",
            "status": "ok" if active_hint.get("active_scenario_exists") else "missing",
            "why_it_matters": "The destroy action only applies to an active scenario.",
            "how_to_fix": "Select or deploy an active scenario before destruction.",
            "can_be_auto_generated": False,
        },
    ]


def validate_scenario_destruction(*, scenario_id: str | None = None, campaign_id: str | None = None, action_type: str = "destroy_full_scenario") -> dict:
    sync_active_scenario_memory()
    active_hint = get_active_scenario_memory_hint()
    card = _find_scenario_card(scenario_id or active_hint.get("scenario_id"))
    if not card:
        return {
            "error": "scenario_not_found",
            "message": "No active scenario card could be found for Level C destruction.",
        }
    blueprint_rel = card.get("reconstruction_blueprint_path")
    blueprint_path = (Path.cwd() / blueprint_rel).resolve() if blueprint_rel else BLUEPRINTS_DIR / f"{card.get('scenario_fingerprint')}_scenario_reconstruction_blueprint.json"
    checks = _scenario_validation_checks(card, blueprint_path, active_hint)

    # Keys that are purely traceability metadata — missing ones are warnings, NOT hard blockers.
    # Blocking the destruction because a campaign isn't linked yet would prevent Level C from
    # ever starting on a fresh scenario that hasn't run any Level B campaigns yet.
    _TRACEABILITY_ONLY_KEYS = {"associated_campaigns", "associated_cases", "associated_result_cards"}

    missing_blocking = [
        item for item in checks
        if item["status"] != "ok" and item["key"] not in _TRACEABILITY_ONLY_KEYS
    ]
    missing_warnings = [
        item for item in checks
        if item["status"] != "ok" and item["key"] in _TRACEABILITY_ONLY_KEYS
    ]

    ready = not missing_blocking and blueprint_path.is_file()
    return {
        "status": "ok",
        "ready": ready,
        "scenario_id": card.get("scenario_id"),
        "campaign_id": campaign_id,
        "scenario_card_id": card.get("scenario_card_id"),
        "scenario_fingerprint": card.get("scenario_fingerprint"),
        "topology_fingerprint": card.get("topology_fingerprint"),
        "action_type": action_type,
        "checks": checks,
        "missing_blocking": [c["key"] for c in missing_blocking],
        "missing_warnings": [c["key"] for c in missing_warnings],
        "message": (
            "The active scenario can be destroyed for Level C redeployment."
            if ready
            else "The scenario cannot be destroyed because core redeployment prerequisites are missing. Ensure the blueprint and active scenario exist."
        ),
        "blueprint_path": relative_path(blueprint_path) if blueprint_path else None,
    }


def _run_it_destroy_script(paths: dict) -> tuple[bool, str, str]:
    script = paths["it_destroy_script"]
    if not script.is_file():
        return False, "", "IT destroy script was not found."
    process = subprocess.run(
        ["bash", str(script), "tf_out"],
        cwd=str(paths["repo_root"]),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return process.returncode == 0, process.stdout, process.stderr


def _best_effort_delete_openstack_server(name: str, paths: dict) -> tuple[bool, str]:
    if not name:
        return False, "No server name was provided."
    admin_openrc = paths["admin_openrc"]
    if not admin_openrc.is_file():
        return False, "admin-openrc.sh was not found."
    command = (
        f"source {admin_openrc} >/dev/null 2>&1 && "
        f"if openstack server show '{name}' >/dev/null 2>&1; then openstack server delete '{name}'; else exit 0; fi"
    )
    process = subprocess.run(
        ["bash", "-lc", command],
        cwd=str(paths["repo_root"]),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if process.returncode == 0:
        return True, process.stdout.strip()
    return False, process.stderr.strip() or process.stdout.strip() or f"Failed to delete server {name}."


def destroy_full_scenario(*, scenario_id: str | None = None, campaign_id: str | None = None, action_type: str = "destroy_full_scenario", confirmation: str = "", operator: str = "foc_experimentation") -> dict:
    if confirmation != "OK":
        return {"error": "confirmation_required", "message": "Type exactly OK to confirm full scenario destruction."}

    validation = validate_scenario_destruction(scenario_id=scenario_id, campaign_id=campaign_id, action_type=action_type)
    if validation.get("error"):
        return validation
    if not validation.get("ready"):
        return {
            "error": "scenario_blueprint_missing",
            "message": "The scenario cannot be destroyed because no valid scenario reconstruction blueprint exists. Preserve the lightweight scenario memory before destroying the active environment.",
            "checks": validation.get("checks"),
        }

    paths = _active_paths()
    card = _find_scenario_card(validation.get("scenario_id"))
    if not card:
        return {"error": "scenario_not_found", "message": "Scenario card not found during destruction."}

    industrial_scenario = _json_load(paths["industrial_scenario_file"]) or {}
    industrial_state = _json_load(paths["industrial_state_file"]) or {}
    candidate_server_names = {
        str((((industrial_scenario.get("deployment") or {}).get("plc_instance") or {}).get("name") or "")).strip(),
        str((((industrial_scenario.get("deployment") or {}).get("scada_instance") or {}).get("name") or "")).strip(),
        "PLC_Instance",
        "FUXA_Instance",
    }
    candidate_server_names = {item for item in candidate_server_names if item}

    resources_destroyed: list[str] = []
    resources_failed: list[str] = []

    it_ok, it_stdout, it_stderr = _run_it_destroy_script(paths)
    if it_ok:
        resources_destroyed.append("IT scenario destroy script")
    else:
        resources_failed.append(f"IT destroy script: {it_stderr or 'unknown error'}")

    for name in sorted(candidate_server_names):
        ok, message = _best_effort_delete_openstack_server(name, paths)
        if ok:
            resources_destroyed.append(f"OT instance {name}")
        else:
            resources_failed.append(f"OT instance {name}: {message}")

    for file_key in ("industrial_scenario_file", "industrial_state_file", "it_scenario_file"):
        path = paths[file_key]
        try:
            if path.exists():
                path.unlink()
                resources_destroyed.append(relative_path(path))
        except Exception as exc:
            resources_failed.append(f"{relative_path(path)}: {exc}")

    card["active_scenario_exists"] = False
    card["destroyed_at"] = utc_now()
    upsert_registry_entry(SCENARIO_REGISTRY_PATH, "scenario_fingerprint", card)
    card_path = _scenario_card_path(card["scenario_fingerprint"])
    _write_json(card_path, card)

    manifest = {
        "scenario_id": card.get("scenario_id"),
        "scenario_card_id": card.get("scenario_card_id"),
        "scenario_fingerprint": card.get("scenario_fingerprint"),
        "topology_fingerprint": card.get("topology_fingerprint"),
        "destruction_requested_at": utc_now(),
        "destruction_completed_at": utc_now(),
        "operator": operator,
        "confirmation_required": True,
        "confirmation_value": "OK",
        "resources_destroyed": resources_destroyed,
        "resources_failed": resources_failed,
        "scientific_memory_retained": [
            relative_path(SCENARIO_REGISTRY_PATH),
            card.get("reconstruction_blueprint_path"),
            relative_path(card_path),
        ],
        "blueprint_path": card.get("reconstruction_blueprint_path"),
        "scenario_registry_entry": relative_path(SCENARIO_REGISTRY_PATH),
        "associated_campaigns": list(card.get("associated_campaigns") or []),
        "associated_cases": list(card.get("associated_cases") or []),
        "associated_result_cards": list(card.get("associated_result_cards") or []),
        "redeployment_readiness_after_destruction": "ready" if bool(card.get("can_be_redeployed")) and bool(card.get("reconstruction_blueprint_path")) else "blocked",
        "destruction_status": "completed" if not resources_failed else ("completed_with_failures" if resources_destroyed else "failed"),
        "destruction_warnings": resources_failed,
    }
    manifest_path = _scenario_manifest_path(card["scenario_fingerprint"])
    _write_json(manifest_path, manifest)

    return {
        "status": "ok",
        "scenario_id": card.get("scenario_id"),
        "scenario_fingerprint": card.get("scenario_fingerprint"),
        "manifest_path": relative_path(manifest_path),
        "resources_destroyed": resources_destroyed,
        "resources_failed": resources_failed,
        "message": "The active scenario was destroyed for Level C redeployment while preserving scientific comparison memory.",
    }

