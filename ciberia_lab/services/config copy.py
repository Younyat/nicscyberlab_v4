from pathlib import Path


MODULE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = MODULE_ROOT.parent

EXTERNAL_DIR = MODULE_ROOT / "external"
EXTERNAL_REPO_ROOT = EXTERNAL_DIR / "CiberIA_O1_A1"

FRAMEWORK_DIR = EXTERNAL_REPO_ROOT / "Framework"
ANALYSIS_DIR = EXTERNAL_REPO_ROOT / "Analysis - AIR"

GENERATED_DIR = MODULE_ROOT / "generated"
MODELS_DIR = MODULE_ROOT / "models"
UPLOADS_DIR = MODULE_ROOT / "uploads"

GENERATED_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MODEL_PATH = FRAMEWORK_DIR / "stacked_model_original.pkl"
ACTIVE_MODEL_PATH = MODELS_DIR / "active_model.pkl"

DATA_SPLIT_FILES = {
    "2017": FRAMEWORK_DIR / "data_split_2017.pkl",
    "2018": FRAMEWORK_DIR / "data_split_2018.pkl",
    "unsw": FRAMEWORK_DIR / "data_split_unsw.pkl",
}