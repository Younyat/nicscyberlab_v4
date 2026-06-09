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
DATASETS_CUSTOM_DIR = MODULE_ROOT / "datasets_custom"

GENERATED_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
DATASETS_CUSTOM_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MODEL_PATH = FRAMEWORK_DIR / "stacked_model_original.pkl"
ACTIVE_MODEL_PATH = MODELS_DIR / "active_model.pkl"

BASE_PROFILE_INFO = {
    "2017": {
        "profile": "2017",
        "title": "CIC-IDS2017",
        "notebook": "Framework.ipynb",
        "goal": "Model creation and analysis for CIC-IDS2017",
        "split_file": str(FRAMEWORK_DIR / "data_split_2017.pkl"),
        "base_model_file": str(FRAMEWORK_DIR / "stacked_model_original.pkl"),
        "mode": "baseline_framework_artifact",
        "source": "built_in",
    },
    "2018": {
        "profile": "2018",
        "title": "CIC-IDS2018",
        "notebook": "Framework copy.ipynb",
        "goal": "Model creation and analysis for CIC-IDS2018",
        "split_file": str(FRAMEWORK_DIR / "data_split_2018.pkl"),
        "base_model_file": str(FRAMEWORK_DIR / "stacked_model_original.pkl"),
        "mode": "framework_profile",
        "source": "built_in",
    },
    "unsw": {
        "profile": "unsw",
        "title": "UNSW-NB15",
        "notebook": "Framework copy 2.ipynb",
        "goal": "Model creation and analysis for UNSW-NB15",
        "split_file": str(FRAMEWORK_DIR / "data_split_unsw.pkl"),
        "base_model_file": str(FRAMEWORK_DIR / "stacked_model_original.pkl"),
        "mode": "framework_profile",
        "source": "built_in",
    },
}

DATA_SPLIT_FILES = {
    "2017": FRAMEWORK_DIR / "data_split_2017.pkl",
    "2018": FRAMEWORK_DIR / "data_split_2018.pkl",
    "unsw": FRAMEWORK_DIR / "data_split_unsw.pkl",
}