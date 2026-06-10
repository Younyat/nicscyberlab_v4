from pathlib import Path

from .foc_config import GENERATED_FILES, PROJECT_ROOT

SOURCE_DEFINITIONS = [
    {"source_type": "scenario", "pattern": "scenario/scenario_file.json", "kind": "file"},
    {"source_type": "deployment_status", "pattern": "scenario/deployment_status.json", "kind": "file"},
    {"source_type": "destroy_status", "pattern": "scenario/destroy_status.json", "kind": "file"},
    {"source_type": "industrial_scenario", "pattern": "industrial-scenario/scenarios/industrial_*.json", "kind": "file"},
    {"source_type": "industrial_state", "pattern": "industrial-scenario/state/industrial_state.json", "kind": "file"},
    {"source_type": "tools_tmp", "pattern": "tools-installer-tmp/*.json", "kind": "file"},
    {"source_type": "tools_installed", "pattern": "tools-installer/installed/*.json", "kind": "file"},
    {"source_type": "tools_log", "pattern": "tools-installer/logs/*.log", "kind": "file"},
    {"source_type": "industrial_log", "pattern": "industrial-scenario/logs/*/*.log", "kind": "file"},
    {"source_type": "attack_output", "pattern": "app_core/infrastructure/attack/outputs/*/result.json", "kind": "file"},
    {"source_type": "alerts_session_file", "pattern": "app_core/infrastructure/forensics/alerts_store/ALERTS-*/*", "kind": "file"},
    {"source_type": "forensics_case_dir", "pattern": "app_core/infrastructure/forensics/evidence_store/CASE-*", "kind": "dir"},
]


def project_path(*parts: str) -> Path:
    return PROJECT_ROOT.joinpath(*parts)


def relative_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT.resolve())).replace("\\", "/")
    except Exception:
        return str(path)


def existing_paths(pattern: str) -> list[Path]:
    return sorted(PROJECT_ROOT.glob(pattern))


def generated_relative_paths() -> dict:
    return {name: relative_path(path) for name, path in GENERATED_FILES.items()}
