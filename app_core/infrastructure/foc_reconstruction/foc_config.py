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
        FOC_OUTPUT_DIR / "reports",
        FOC_OUTPUT_DIR / "cache",
        FOC_OUTPUT_DIR / "backups",
    ):
        path.mkdir(parents=True, exist_ok=True)
