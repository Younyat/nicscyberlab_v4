from pathlib import Path

from ..foc_reconstruction.foc_paths import project_path

FOC_ROOT = project_path("foc-reconstruction")
SCENARIOS_ROOT = project_path("scenarios")
DEFAULT_DERIVED_RELATIVE_DIR = Path("derived") / "reconstruction"
DEFAULT_TIMESTAMP_RESOLUTION_MS = 1000.0
DEFAULT_ACQUISITION_JITTER_MS = 1000.0

ALLOWED_SUPPORT_STATUSES = {"recovered", "degraded", "ambiguous", "missing"}
ALLOWED_TEMPORAL_STATES = {"supported", "ambiguous", "contradicted", "unknown"}
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

