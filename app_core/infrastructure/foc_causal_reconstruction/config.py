from pathlib import Path

from ..foc_reconstruction.foc_paths import project_path

FOC_ROOT = project_path("foc-reconstruction")
SCENARIOS_ROOT = project_path("scenarios")
DEFAULT_DERIVED_RELATIVE_DIR = Path("derived") / "reconstruction"
DEFAULT_TIMESTAMP_RESOLUTION_MS = 1000.0
DEFAULT_ACQUISITION_JITTER_MS = 1000.0

ALLOWED_SUPPORT_STATUSES = {"recovered", "degraded", "ambiguous", "missing"}
ALLOWED_TEMPORAL_STATES = {"supported", "ambiguous", "contradicted", "unknown", "not_required"}
ALLOWED_TEMPORAL_CONFIDENCE_STATES = {"strong", "limited", "ambiguous", "unknown"}
ALLOWED_CAUSAL_UI_STATES = {
    "not_available",
    "blocked_missing_ground_truth",
    "blocked_missing_analysis",
    "ready_to_run",
    "running",
    "completed",
    "completed_with_degradation",
    "failed",
}

# Execution vs. reconstruction-quality vs. interpretive-confidence are three
# distinct axes. Conflating them (e.g. showing "Progress: 100%" as if it meant
# "causal reconstruction is strong") is the exact confusion this module must avoid.
ALLOWED_EXECUTION_STATUSES = {"not_started", "running", "completed", "failed"}
ALLOWED_RECONSTRUCTION_STATES = {
    "not_available",
    "blocked",
    "completed",
    "completed_with_degradation",
    "weak_reconstruction",
    "failed",
}
ALLOWED_SCIENTIFIC_CONFIDENCE = {"strong", "limited", "weak", "ambiguous", "unknown"}

# CPR -> human label, checked in descending order of threshold.
CPR_LABEL_THRESHOLDS = [
    (0.80, "mostly_recoverable"),
    (0.50, "partially_recoverable"),
    (0.25, "weak_recoverability"),
    (0.0, "low_recoverability"),
]

