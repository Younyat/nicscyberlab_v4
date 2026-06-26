from __future__ import annotations

from pathlib import Path

from ..foc_reconstruction.foc_paths import project_path, relative_path

CAMPAIGNS_ROOT = project_path("app_core", "infrastructure", "forensics", "evidence_store", "repetition_campaigns")
EVIDENCE_STORE_ROOT = project_path("app_core", "infrastructure", "forensics", "evidence_store")
ARCHIVED_CASES_ROOT = EVIDENCE_STORE_ROOT / "_archived_heavy_cases"
METHODOLOGICAL_BASIS_FILE = project_path("app_core", "infrastructure", "foc_experimentation", "methodological_basis.json")
SCIENTIFIC_MEMORY_ROOT = CAMPAIGNS_ROOT / "scientific_memory"
SCENARIO_REGISTRY_DIR = SCIENTIFIC_MEMORY_ROOT / "scenario_registry"
CASE_REGISTRY_DIR = SCIENTIFIC_MEMORY_ROOT / "case_registry"
EXECUTION_REGISTRY_DIR = SCIENTIFIC_MEMORY_ROOT / "execution_registry"
RESULT_REGISTRY_DIR = SCIENTIFIC_MEMORY_ROOT / "result_registry"
ANALYSIS_REGISTRY_DIR = SCIENTIFIC_MEMORY_ROOT / "analysis_registry"
RETENTION_REGISTRY_DIR = SCIENTIFIC_MEMORY_ROOT / "retention_registry"
BLUEPRINTS_DIR = SCIENTIFIC_MEMORY_ROOT / "blueprints"
LEGACY_COMPARISON_REGISTRY_DIR = CAMPAIGNS_ROOT / "comparison_registry"

SCENARIO_REGISTRY_PATH = SCENARIO_REGISTRY_DIR / "scenario_registry.json"
CASE_REGISTRY_PATH = CASE_REGISTRY_DIR / "case_registry.json"
EXECUTION_REGISTRY_PATH = EXECUTION_REGISTRY_DIR / "execution_registry.json"
RESULT_REGISTRY_PATH = RESULT_REGISTRY_DIR / "comparison_result_registry.json"
ANALYSIS_REGISTRY_PATH = ANALYSIS_REGISTRY_DIR / "analysis_registry.json"
RETENTION_REGISTRY_PATH = RETENTION_REGISTRY_DIR / "retention_registry.json"
LEGACY_COMPARISON_REGISTRY_PATH = LEGACY_COMPARISON_REGISTRY_DIR / "comparison_result_registry.json"

CAMPAIGN_STATES = {
    "not_started",
    "running",
    "paused",
    "completed",
    "completed_with_degradation",
    "completed_with_failures",
    "partial",
    "insufficient_data",
    "failed",
    "stopped",
}

EXECUTION_STATES = {
    "queued",
    "running",
    "completed",
    "completed_with_degradation",
    "partial",
    "failed",
    "cancelled",
}

STAGE_STATES = {
    "not_started",
    "running",
    "completed",
    "completed_with_degradation",
    "failed",
    "skipped",
    "not_applicable",
}

COMPARABILITY_STATES = {
    "Comparable",
    "Comparable With Degradation",
    "Not Comparable",
    "Insufficient Data",
}

LEVELS = {"A", "B", "C"}

STAGE_KEYS = [
    "scenario_prepared",
    "environment_deployed",
    "tools_installed_or_validated",
    "baseline_noise_captured",
    "time_sync_validated",
    "ground_truth_sealed",
    "attack_executed",
    "detection_observed",
    "trigger_selected",
    "acquisition_executed",
    "evidence_preserved",
    "integrity_custody_checked",
    "multilayer_analysis_completed",
    "timeline_generated",
    "cross_layer_findings_generated",
    "causal_reconstruction_generated",
    "uncertainty_generated",
    "hypothesis_support_generated",
    "executive_summary_generated",
    "comparison_profile_generated",
]

LEVEL_A_NOT_APPLICABLE = {
    "environment_deployed",
    "tools_installed_or_validated",
    "baseline_noise_captured",
    "attack_executed",
    "detection_observed",
    "trigger_selected",
    "acquisition_executed",
    "evidence_preserved",
}

DEFAULT_BASELINE_NOISE_THRESHOLD = 0.15
DEFAULT_DELTA_WCPR_ALLOWED = 0.10
DEFAULT_EPSILON = 1e-9


def campaign_level_dir(level: str) -> str:
    normalized = str(level or "").strip().upper()
    return f"level_{normalized}" if normalized in LEVELS else "level_A"


def campaign_dir(campaign_id: str) -> Path:
    return CAMPAIGNS_ROOT / str(campaign_id)


def campaign_manifest_path(campaign_id: str) -> Path:
    return campaign_dir(campaign_id) / "campaign_manifest.json"


def campaign_config_path(campaign_id: str) -> Path:
    return campaign_dir(campaign_id) / "campaign_config.json"


def campaign_methodological_basis_path(campaign_id: str) -> Path:
    return campaign_dir(campaign_id) / "methodological_basis.json"


def execution_dir(campaign_id: str, level: str, execution_id: str) -> Path:
    return campaign_dir(campaign_id) / campaign_level_dir(level) / str(execution_id)


def rel(path: Path | None) -> str | None:
    return relative_path(path) if path is not None else None
