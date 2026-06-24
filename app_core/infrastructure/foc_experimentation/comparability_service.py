from __future__ import annotations

import json
import math
import uuid
from pathlib import Path

from .baseline_noise import relative_difference
from .config import (
    COMPARABILITY_STATES,
    DEFAULT_DELTA_WCPR_ALLOWED,
    campaign_config_path,
    campaign_dir,
    campaign_manifest_path,
    rel,
)
from .execution_service import load_execution
from ..foc_reconstruction.foc_sources import utc_now


def _json_load(path: Path | None):
    try:
        if path is None or not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _profile_path(execution: dict) -> Path | None:
    execution_path = execution.get("execution_path")
    if not execution_path:
        return None
    base = Path.cwd() / execution_path
    candidate = base / "forensic_comparison_profile.json"
    return candidate if candidate.is_file() else None


def _support_rank(value: str | None) -> int:
    order = {
        "strong_support": 4,
        "moderate_support": 3,
        "weak_support": 2,
        "limited_support": 1,
        "contradicted": 0,
    }
    return order.get(str(value or "").strip(), -1)


def _has_degradation(profile: dict) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    causal = profile.get("causal_reconstruction") or {}
    uncertainty = profile.get("uncertainty") or {}
    baseline = profile.get("baseline_noise") or {}
    detection = profile.get("detection_trigger") or {}
    if str(causal.get("status")) == "completed_with_degradation" or (causal.get("degraded_edges") or 0) > 0:
        reasons.append("causal reconstruction contains degraded edges")
    if str(uncertainty.get("temporal_confidence")) in {"limited", "ambiguous", "unknown"}:
        reasons.append("temporal ordering confidence is not strong")
    if str(baseline.get("baseline_noise_status")) == "comparability_warning":
        reasons.append("baseline noise profile raised a comparability warning")
    if str(detection.get("trigger_attack_alignment")) in {"trigger_attack_mismatch", "multi-vector_acquisition_trigger_mismatch"}:
        reasons.append("acquisition trigger and reconstructed attack path are not aligned")
    if str(uncertainty.get("case_wide_integrity_status")) == "partial":
        reasons.append("case-wide integrity remains partial")
    return (len(reasons) > 0, reasons)


def compare_executions(execution_ids: list[str], *, campaign_id: str | None = None, delta_wcpr_allowed: float | None = None) -> dict:
    executions = [load_execution(item) for item in execution_ids]
    if not executions or any(item is None for item in executions):
        return {"status": "Insufficient Data", "reason": "one or more execution manifests were not found", "execution_ids": execution_ids}

    profiles = []
    for execution in executions:
        path = _profile_path(execution)
        profile = _json_load(path)
        if not isinstance(profile, dict):
            return {"status": "Insufficient Data", "reason": "one or more forensic comparison profiles are missing", "execution_ids": execution_ids}
        profiles.append((execution, profile, path))

    reference_execution, reference_profile, _ = profiles[0]
    expected_edges = (reference_profile.get("causal_reconstruction") or {}).get("expected_edges")
    if not expected_edges:
        return {"status": "Insufficient Data", "reason": "expected causal edge count is unavailable in the reference execution", "execution_ids": execution_ids}

    try:
        expected_edges = int(expected_edges)
    except Exception:
        return {"status": "Insufficient Data", "reason": "expected causal edge count is invalid", "execution_ids": execution_ids}

    delta_cpr_allowed = 1.0 / abs(expected_edges)
    configured_wcpr = delta_wcpr_allowed
    if configured_wcpr is None and campaign_id:
        cfg = _json_load(campaign_config_path(campaign_id)) or {}
        configured_wcpr = cfg.get("delta_wcpr_allowed")
    delta_wcpr_allowed = float(configured_wcpr if configured_wcpr is not None else DEFAULT_DELTA_WCPR_ALLOWED)

    reference_causal = reference_profile.get("causal_reconstruction") or {}
    reference_hypothesis = reference_profile.get("hypothesis_support") or {}
    comparison_rows = []
    hard_failures: list[str] = []
    degradation_reasons: list[str] = []
    for execution, profile, _path in profiles:
        causal = profile.get("causal_reconstruction") or {}
        hypothesis = profile.get("hypothesis_support") or {}
        cpr = causal.get("cpr")
        wcpr = causal.get("weighted_cpr")
        if cpr is None or wcpr is None:
            return {"status": "Insufficient Data", "reason": "one or more executions are missing CPR or Weighted CPR", "execution_ids": execution_ids}
        cpr_diff = abs(float(cpr) - float(reference_causal.get("cpr") or 0.0))
        wcpr_diff = abs(float(wcpr) - float(reference_causal.get("weighted_cpr") or 0.0))
        support_shift = abs(_support_rank(hypothesis.get("global_support_level")) - _support_rank(reference_hypothesis.get("global_support_level")))
        if cpr_diff > delta_cpr_allowed:
            hard_failures.append(f"{execution['execution_id']}: CPR delta {cpr_diff:.4f} exceeds allowed {delta_cpr_allowed:.4f}")
        if wcpr_diff > delta_wcpr_allowed:
            hard_failures.append(f"{execution['execution_id']}: Weighted CPR delta {wcpr_diff:.4f} exceeds allowed {delta_wcpr_allowed:.4f}")
        if support_shift > 1:
            hard_failures.append(f"{execution['execution_id']}: hypothesis support level changed too strongly between executions")
        degraded, degraded_reasons = _has_degradation(profile)
        degradation_reasons.extend(f"{execution['execution_id']}: {reason}" for reason in degraded_reasons)
        comparison_rows.append(
            {
                "execution_id": execution["execution_id"],
                "campaign_id": execution["campaign_id"],
                "cpr": cpr,
                "weighted_cpr": wcpr,
                "recovered_edges": causal.get("recovered_edges"),
                "degraded_edges": causal.get("degraded_edges"),
                "ambiguous_edges": causal.get("ambiguous_edges"),
                "missing_edges": causal.get("missing_edges"),
                "global_support_level": hypothesis.get("global_support_level"),
                "temporal_confidence": (profile.get("uncertainty") or {}).get("temporal_confidence"),
                "baseline_noise_status": (profile.get("baseline_noise") or {}).get("baseline_noise_status"),
                "trigger_attack_alignment": (profile.get("detection_trigger") or {}).get("trigger_attack_alignment"),
                "cpr_delta_vs_reference": cpr_diff,
                "weighted_cpr_delta_vs_reference": wcpr_diff,
                "support_rank_shift_vs_reference": support_shift,
            }
        )

    if hard_failures:
        status = "Not Comparable"
    elif degradation_reasons:
        status = "Comparable With Degradation"
    else:
        status = "Comparable"
    assert status in COMPARABILITY_STATES

    comparison_id = f"comparison-{uuid.uuid4().hex[:12]}"
    target_root = campaign_dir(campaign_id) / "comparisons" if campaign_id else campaign_dir("_cross_campaign") / "comparisons"
    result_dir = target_root / comparison_id
    result_dir.mkdir(parents=True, exist_ok=True)
    matrix = {
        "comparison_id": comparison_id,
        "generated_at": utc_now(),
        "reference_execution_id": reference_execution["execution_id"],
        "delta_cpr_allowed": delta_cpr_allowed,
        "delta_wcpr_allowed": delta_wcpr_allowed,
        "rows": comparison_rows,
    }
    result = {
        "comparison_id": comparison_id,
        "generated_at": utc_now(),
        "status": status,
        "execution_ids": execution_ids,
        "reference_execution_id": reference_execution["execution_id"],
        "delta_cpr_allowed": delta_cpr_allowed,
        "delta_wcpr_allowed": delta_wcpr_allowed,
        "hard_failures": hard_failures,
        "degradation_reasons": degradation_reasons,
        "summary": {
            "max_abs_cpr_difference": max((row["cpr_delta_vs_reference"] for row in comparison_rows), default=0.0),
            "max_abs_weighted_cpr_difference": max((row["weighted_cpr_delta_vs_reference"] for row in comparison_rows), default=0.0),
            "max_support_rank_shift": max((row["support_rank_shift_vs_reference"] for row in comparison_rows), default=0),
        },
    }
    report = [
        f"# Forensic Reconstruction Comparability Report",
        "",
        f"- Comparison ID: `{comparison_id}`",
        f"- Status: **{status}**",
        f"- Reference execution: `{reference_execution['execution_id']}`",
        f"- Delta CPR allowed: `{delta_cpr_allowed:.4f}`",
        f"- Delta Weighted CPR allowed: `{delta_wcpr_allowed:.4f}`",
        "",
        "## Execution rows",
    ]
    for row in comparison_rows:
        report.extend(
            [
                f"- `{row['execution_id']}`: CPR `{row['cpr']}`, Weighted CPR `{row['weighted_cpr']}`, support `{row['global_support_level']}`, temporal `{row['temporal_confidence']}`",
            ]
        )
    if hard_failures:
        report.extend(["", "## Hard failures"] + [f"- {item}" for item in hard_failures])
    if degradation_reasons:
        report.extend(["", "## Degradation reasons"] + [f"- {item}" for item in degradation_reasons])

    _write_json(result_dir / "comparison_matrix.json", matrix)
    _write_json(result_dir / "comparability_result.json", result)
    _write_text(result_dir / "comparability_report.md", "\n".join(report) + "\n")
    result["artifacts"] = {
        "comparison_matrix": rel(result_dir / "comparison_matrix.json"),
        "comparability_result": rel(result_dir / "comparability_result.json"),
        "comparability_report": rel(result_dir / "comparability_report.md"),
    }
    return result


def load_comparison_result(comparison_id: str) -> dict | None:
    roots = [campaign_dir("_cross_campaign") / "comparisons"]
    from .campaign_service import list_campaigns

    for item in list_campaigns().get("campaigns", []):
        roots.append(campaign_dir(item["campaign_id"]) / "comparisons")
    for root in roots:
        path = root / comparison_id / "comparability_result.json"
        payload = _json_load(path)
        if payload:
            return payload
    return None


def load_execution_profile(execution_id: str) -> dict | None:
    execution = load_execution(execution_id)
    if not execution:
        return None
    return _json_load(_profile_path(execution))
