from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FOC_OUTPUT_DIR = PROJECT_ROOT / "foc-reconstruction"
READ_ONLY_MODE = True
HASH_ALGORITHM = "sha256"

HASH_SMALL_FILE_MAX_BYTES = 8 * 1024 * 1024
HASH_REASONABLE_BINARY_MAX_BYTES = 64 * 1024 * 1024

GENERATED_FILES = {
    "manifest": FOC_OUTPUT_DIR / "foc_manifest.json",
    "scenario_bom": FOC_OUTPUT_DIR / "scenario_bom.json",
    "tools_bom": FOC_OUTPUT_DIR / "tools_bom.json",
    "timeline": FOC_OUTPUT_DIR / "timeline.json",
    "attack_attestation": FOC_OUTPUT_DIR / "attestations" / "attack_attestation.json",
    "detection_attestation": FOC_OUTPUT_DIR / "attestations" / "detection_attestation.json",
    "alerts_normalized": FOC_OUTPUT_DIR / "attestations" / "alerts_normalized.json",
    "alert_correlation": FOC_OUTPUT_DIR / "attestations" / "alert_correlation.json",
    "alert_correlation_summary": FOC_OUTPUT_DIR / "attestations" / "alert_correlation_summary.json",
    "acquisition_profile": FOC_OUTPUT_DIR / "attestations" / "acquisition_profile.json",
    "forensic_intervention": FOC_OUTPUT_DIR / "attestations" / "forensic_intervention.json",
    "forensic_analysis_manifest": FOC_OUTPUT_DIR / "attestations" / "forensic_analysis_manifest.json",
    "scenario_ground_truth": FOC_OUTPUT_DIR / "attestations" / "scenario_ground_truth.json",
    "case_manifest_link": FOC_OUTPUT_DIR / "attestations" / "case_manifest_link.json",
    "foc_context_summary": FOC_OUTPUT_DIR / "attestations" / "foc_context_summary.json",
    "foc_readiness_report": FOC_OUTPUT_DIR / "validation" / "foc_readiness_report.json",
    "id_mapping": FOC_OUTPUT_DIR / "indexes" / "id_mapping.json",
    "sources_index": FOC_OUTPUT_DIR / "indexes" / "sources_index.json",
    "artifacts_index": FOC_OUTPUT_DIR / "indexes" / "artifacts_index.json",
    "relationships_index": FOC_OUTPUT_DIR / "indexes" / "relationships_index.json",
    "cases_index": FOC_OUTPUT_DIR / "indexes" / "cases_index.json",
    "hashes_index": FOC_OUTPUT_DIR / "hashes" / "hashes_index.json",
}


def ensure_output_layout() -> None:
    for path in (
        FOC_OUTPUT_DIR,
        FOC_OUTPUT_DIR / "indexes",
        FOC_OUTPUT_DIR / "hashes",
        FOC_OUTPUT_DIR / "attestations",
        FOC_OUTPUT_DIR / "validation",
        FOC_OUTPUT_DIR / "reports",
        FOC_OUTPUT_DIR / "cache",
        FOC_OUTPUT_DIR / "backups",
    ):
        path.mkdir(parents=True, exist_ok=True)
