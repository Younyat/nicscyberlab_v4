from __future__ import annotations

from .config import (
    ALLOWED_EXECUTION_STATUSES,
    ALLOWED_RECONSTRUCTION_STATES,
    ALLOWED_SCIENTIFIC_CONFIDENCE,
)

# execution_status: did the module run technically.
# reconstruction_state: how good is the causal reconstruction it produced.
# scientific_confidence: how much interpretive weight the result can carry.
# These three are independent axes on purpose - "Progress: 100%" only ever
# speaks to execution_status, never to the other two.


def derive_status_triad(
    *,
    execution_phase: str,
    ground_truth_status: str | None = None,
    metrics: dict | None = None,
    integrity_status: str | None = None,
    strict_failed: bool = False,
    failure_reason: str | None = None,
) -> dict:
    if execution_phase == "not_started":
        result = {
            "execution_status": "not_started",
            "reconstruction_state": "not_available",
            "scientific_confidence": "unknown",
            "reason": "Causal reconstruction has not been executed for this case yet.",
        }
    elif execution_phase == "running":
        result = {
            "execution_status": "running",
            "reconstruction_state": "not_available",
            "scientific_confidence": "unknown",
            "reason": "Causal reconstruction is currently executing.",
        }
    elif execution_phase == "exception":
        result = {
            "execution_status": "failed",
            "reconstruction_state": "failed",
            "scientific_confidence": "unknown",
            "reason": failure_reason or "Causal reconstruction failed during execution.",
        }
    elif execution_phase == "blocked":
        reconstruction_state = "not_available" if ground_truth_status in {"missing", "missing_expected_edges", None} else "blocked"
        result = {
            "execution_status": "completed",
            "reconstruction_state": reconstruction_state,
            "scientific_confidence": "unknown",
            "reason": failure_reason or "Causal reconstruction is blocked because required prerequisites are unavailable.",
        }
    elif execution_phase == "ran" and strict_failed:
        result = {
            "execution_status": "completed",
            "reconstruction_state": "failed",
            "scientific_confidence": "unknown",
            "reason": failure_reason or "Strict mode failed because one or more expected edges are missing.",
        }
    elif execution_phase == "ran":
        metrics = metrics or {}
        cpr = float(metrics.get("causal_path_recoverability") or 0.0)
        ambiguous_rate = float(metrics.get("ambiguous_edge_rate") or 0.0)
        missing_edges = int(metrics.get("missing_edges") or 0)
        degraded_edges = int(metrics.get("degraded_edges") or 0)
        ambiguous_edges = int(metrics.get("ambiguous_edges") or 0)
        temporal_state = metrics.get("temporal_confidence_state")

        if missing_edges == 0 and degraded_edges == 0 and ambiguous_edges == 0:
            reconstruction_state = "completed"
        elif cpr < 0.25:
            reconstruction_state = "weak_reconstruction"
        else:
            reconstruction_state = "completed_with_degradation"

        if ground_truth_status != "ok":
            scientific_confidence = "unknown"
        elif ambiguous_rate > 0.20:
            scientific_confidence = "ambiguous"
        elif cpr < 0.25:
            scientific_confidence = "weak"
        elif cpr < 0.80 or integrity_status == "partial" or temporal_state != "strong":
            scientific_confidence = "limited"
        else:
            scientific_confidence = "strong"

        reason = metrics.get("interpretation") or metrics.get("main_limitation") or "Causal reconstruction completed."
        result = {
            "execution_status": "completed",
            "reconstruction_state": reconstruction_state,
            "scientific_confidence": scientific_confidence,
            "reason": reason,
        }
    else:
        result = {
            "execution_status": "failed",
            "reconstruction_state": "failed",
            "scientific_confidence": "unknown",
            "reason": f"Unrecognized execution phase `{execution_phase}`.",
        }

    if result["execution_status"] not in ALLOWED_EXECUTION_STATUSES:
        result["execution_status"] = "failed"
    if result["reconstruction_state"] not in ALLOWED_RECONSTRUCTION_STATES:
        result["reconstruction_state"] = "not_available"
    if result["scientific_confidence"] not in ALLOWED_SCIENTIFIC_CONFIDENCE:
        result["scientific_confidence"] = "unknown"
    return result
