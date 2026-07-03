from __future__ import annotations

import json
import statistics
import time
import zipfile
from pathlib import Path

from app_core.infrastructure.foc_causal_reconstruction.service import (
    causal_metrics_payload,
    causal_status_payload,
    causal_uncertainty_payload,
)
from app_core.infrastructure.foc_experimentation.campaign_service import create_campaign
from app_core.infrastructure.foc_experimentation.comparability_service import compare_executions
from app_core.infrastructure.foc_experimentation.execution_service import load_execution
from app_core.infrastructure.foc_experimentation.job_runner import (
    JobCancelled,
    get_job,
    job_cancel_requested,
    new_job,
    raise_if_cancelled,
    request_cancel,
    start_job,
    update_job,
)
from app_core.infrastructure.foc_experimentation.level_a_scientific_report_service import (
    start_level_a_scientific_report_job,
)
from app_core.infrastructure.foc_reconstruction.evidence_lifecycle_dashboard import (
    load_evidence_lifecycle_dashboard,
)
from app_core.infrastructure.foc_reconstruction.evidence_support.service import (
    load_claimability_report,
    load_counter_evidence_report,
    load_forensic_storyline,
    load_hypothesis_support_report,
)
from app_core.infrastructure.foc_reconstruction.foc_case_analysis import (
    _case_dir_from_entry,
    get_case_entry,
    load_analysis_status,
)
from app_core.infrastructure.foc_reconstruction.foc_paths import relative_path
from app_core.infrastructure.foc_reconstruction.foc_sources import utc_now

from .audit import build_capability_audit
from .config import PAPER_EVIDENCE_ROOT
from .tables import build_paper_table_registry

TERMINAL_JOB_STATUSES = {
    "completed",
    "completed_with_degradation",
    "completed_with_failures",
    "failed",
    "cancelled",
    "stopped",
}


def _level_b_repetition_api():
    from app_core.infrastructure.foc_experimentation.level_b_repetition_runner import (
        get_level_b_repetition_report,
        preview_level_b_repetitions,
        start_level_b_repetitions_job,
    )

    return {
        "get_level_b_repetition_report": get_level_b_repetition_report,
        "preview_level_b_repetitions": preview_level_b_repetitions,
        "start_level_b_repetitions_job": start_level_b_repetitions_job,
    }


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
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def _upsert_phase_status(job_payload: dict | None, *, phase_key: str, phase_label: str, status: str, detail: str, progress_percent: float) -> list[dict]:
    phases = list((job_payload or {}).get("phase_statuses") or [])
    updated = False
    for item in phases:
        if str(item.get("phase_key") or "") == phase_key:
            item["phase_label"] = phase_label
            item["status"] = status
            item["detail"] = detail
            item["progress_percent"] = progress_percent
            item["updated_at"] = utc_now()
            updated = True
            break
    if not updated:
        phases.append(
            {
                "phase_key": phase_key,
                "phase_label": phase_label,
                "status": status,
                "detail": detail,
                "updated_at": utc_now(),
                "progress_percent": progress_percent,
            }
        )
    return phases


def _progress_slice(start: float, end: float, child_progress: float | int | None) -> float:
    try:
        ratio = max(0.0, min(100.0, float(child_progress or 0.0))) / 100.0
    except Exception:
        ratio = 0.0
    return round(start + ((end - start) * ratio), 2)


def _safe_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in (value or "value"))


def _report_id(level: str, case_id: str | None = None, scenario_id: str | None = None) -> str:
    ts = utc_now().replace(":", "").replace("+", "_")
    if case_id:
        return f"paper-{level.lower()}-{_safe_slug(case_id)}-{_safe_slug(ts)}"
    if scenario_id:
        return f"paper-{level.lower()}-{_safe_slug(scenario_id)}-{_safe_slug(ts)}"
    return f"paper-{level.lower()}-{_safe_slug(ts)}"


def _report_dir(report_id: str) -> Path:
    return PAPER_EVIDENCE_ROOT / report_id


def _path_from_rel(rel_path: str | None) -> Path | None:
    if not rel_path:
        return None
    path = Path(rel_path)
    if path.is_absolute():
        return path
    return Path.cwd() / path


def _to_float(value):
    try:
        if value in {None, "", "not_available"}:
            return None
        return float(value)
    except Exception:
        return None


def _support_rank(value: str | None) -> int | None:
    mapping = {
        "unsupported": 0,
        "very_low_support": 1,
        "low_support": 1,
        "limited_support": 1,
        "weak_support": 1,
        "partial_support": 2,
        "moderate_support": 3,
        "strong_support": 4,
    }
    raw = str(value or "").strip().lower()
    return mapping.get(raw)


def _mean_std(values: list[float]) -> dict:
    clean = [float(item) for item in values if item is not None]
    if not clean:
        return {"mean": "not_available", "std": "not_available"}
    if len(clean) == 1:
        return {"mean": round(clean[0], 6), "std": 0.0}
    return {"mean": round(statistics.mean(clean), 6), "std": round(statistics.pstdev(clean), 6)}


def _status_bucket(value: str | None) -> str:
    raw = str(value or "").lower()
    if raw in {"completed", "valid", "ready", "available", "comparable"}:
        return "supported"
    if raw in {"completed_with_degradation", "partial", "limited", "blocked", "comparable with degradation"}:
        return "partial"
    if raw in {"failed", "missing", "unsupported", "not_available", "not_generated", "insufficient data"}:
        return "unsupported"
    return "partial"


def _collect_level_a_execution_metrics(execution_id: str, campaign_id: str) -> dict:
    execution = load_execution(execution_id, campaign_id=campaign_id) or {}
    execution_dir = Path(str(execution.get("execution_abs_path") or ""))
    repeatability = _json_load(execution_dir / "analysis_repeatability_profile.json") or {}
    comparison_profile = _json_load(execution_dir / "forensic_comparison_profile.json") or {}
    result_card = _json_load(execution_dir / "forensic_result_card.json") or {}
    causal = comparison_profile.get("causal_reconstruction") or {}
    uncertainty = comparison_profile.get("uncertainty") or {}
    hypothesis = comparison_profile.get("hypothesis_support") or {}
    final_conclusion = comparison_profile.get("final_conclusion") or {}
    return {
        "execution_id": execution_id,
        "status": execution.get("status") or "not_available",
        "comparison_family_id": execution.get("comparison_family_id") or result_card.get("comparison_family_id") or "not_available",
        "CPR": repeatability.get("CPR", result_card.get("CPR", causal.get("cpr"))),
        "Weighted_CPR": repeatability.get("Weighted_CPR", result_card.get("Weighted_CPR", causal.get("weighted_cpr"))),
        "recovered_relations": result_card.get("recovered_edges", causal.get("recovered_edges")),
        "degraded_relations": result_card.get("degraded_edges", causal.get("degraded_edges")),
        "ambiguous_relations": causal.get("ambiguous_edges"),
        "missing_relations": result_card.get("missing_edges", causal.get("missing_edges")),
        "timestamp_availability": uncertainty.get("timestamp_availability", "not_available"),
        "timestamp_resolvability": uncertainty.get("timestamp_resolvability", "not_available"),
        "causal_temporal_ordering_confidence": uncertainty.get("temporal_confidence", repeatability.get("uncertainty_class")),
        "hypothesis_support_level": repeatability.get("hypothesis_support", result_card.get("hypothesis_support", hypothesis.get("global_support_level"))),
        "claimability_class": repeatability.get("final_conclusion_class", result_card.get("final_conclusion_class", final_conclusion.get("conclusion_class"))),
        "scientific_limitations": list(repeatability.get("scientific_limitations") or result_card.get("scientific_limitations") or []),
        "artifacts": execution.get("artifacts") or {},
    }


def _placeholder_level_report(level: str, reason: str) -> dict:
    return {
        "level": level,
        "status": "unsupported",
        "reason": reason,
        "reviewer_facing_interpretation": {
            "what_this_level_proves": "not_available",
            "what_this_level_does_not_prove": "not_available",
            "reviewer_concerns_addressed": [],
        },
    }


def _build_latex_tables(level_a_report: dict, table_registry: dict) -> dict[str, str]:
    aggregate = level_a_report.get("aggregate_repeatability") or {}
    lines_summary = [
        "\\begin{tabular}{ll}",
        "\\hline",
        "Metric & Value \\\\",
        "\\hline",
        f"Repetitions & {level_a_report.get('number_of_level_a_repetitions', 'not\\_available')} \\\\",
        f"Mean CPR & {aggregate.get('cpr_mean', 'not\\_available')} \\\\",
        f"Mean Weighted CPR & {aggregate.get('weighted_cpr_mean', 'not\\_available')} \\\\",
        f"Max $|\\Delta CPR|$ & {aggregate.get('delta_cpr', 'not\\_available')} \\\\",
        f"Max $|\\Delta WCPR|$ & {aggregate.get('delta_weighted_cpr', 'not\\_available')} \\\\",
        f"Conclusion stability & {level_a_report.get('conclusion_class_stability', 'not\\_available')} \\\\",
        "\\hline",
        "\\end{tabular}",
        "",
    ]
    lines_registry = [
        "\\begin{tabular}{p{0.22\\linewidth}p{0.22\\linewidth}p{0.16\\linewidth}p{0.16\\linewidth}}",
        "\\hline",
        "Label & Purpose & Level & Support \\\\",
        "\\hline",
    ]
    for row in table_registry.get("rows") or []:
        lines_registry.append(
            f"{row.get('table_label', 'not\\_available')} & {str(row.get('scientific_purpose', 'not_available')).replace('_', '\\_')} & {row.get('required_repetition_level', 'not_available')} & {row.get('current_support_status', 'not_available')} \\\\"
        )
    lines_registry.extend(["\\hline", "\\end{tabular}", ""])
    return {
        "level_a_metrics_table.tex": "\n".join(lines_summary),
        "paper_table_registry.tex": "\n".join(lines_registry),
    }


def _relation_support_summary(relations: list[dict]) -> dict:
    counts = {"recovered": 0, "degraded": 0, "ambiguous": 0, "missing": 0, "other": 0}
    for item in relations:
        key = str(item.get("recovered_status") or "other").lower()
        if key not in counts:
            key = "other"
        counts[key] += 1
    return counts


def _reviewer_concern_analysis(level_a_report: dict) -> dict:
    causal = level_a_report.get("causal_reconstruction") or {}
    weighted = level_a_report.get("weighted_cpr_methodology") or {}
    final_position = {
        "supports_complete_causality": False,
        "supports_partial_causality": str(causal.get("status") or "").lower() in {"completed_with_degradation", "completed", "blocked", "partial"},
        "supports_moderate_support": str((level_a_report.get("hypothesis_support") or {}).get("global_support_level") or "") in {"moderate_support", "strong_support"},
        "supports_only_technical_completion": False,
    }


def _build_level_a_scientific_comparison_report(level_a_report: dict) -> tuple[dict, str]:
    source_case = level_a_report.get("source_case") or {}
    per_repetition = list(level_a_report.get("per_repetition_metrics") or [])
    comparison = level_a_report.get("repeatability_comparison") or {}
    aggregate = level_a_report.get("aggregate_repeatability") or {}
    relation_counts = []
    stable_profiles = {
        "cpr": len({item.get("CPR") for item in per_repetition}) <= 1 if per_repetition else False,
        "weighted_cpr": len({item.get("Weighted_CPR") for item in per_repetition}) <= 1 if per_repetition else False,
        "claimability_class": len({item.get("claimability_class") for item in per_repetition}) <= 1 if per_repetition else False,
        "hypothesis_support_level": len({item.get("hypothesis_support_level") for item in per_repetition}) <= 1 if per_repetition else False,
    }
    for item in per_repetition:
        relation_counts.append(
            {
                "execution_id": item.get("execution_id"),
                "recovered_relations": item.get("recovered_relations", "not_available"),
                "degraded_relations": item.get("degraded_relations", "not_available"),
                "ambiguous_relations": item.get("ambiguous_relations", "not_available"),
                "missing_relations": item.get("missing_relations", "not_available"),
            }
        )
    scientific_position = {
        "comparison_type": comparison.get("comparison_type", "not_available"),
        "comparison_status": comparison.get("status", "not_available"),
        "is_direct_level_a_repeatability_evidence": str(comparison.get("comparison_type") or "").startswith("direct_level_a_repeatability"),
        "drift_detected": bool(level_a_report.get("drifted_metrics")),
        "stable_degradation_detected": comparison.get("status") == "Comparable With Degradation" and not level_a_report.get("drifted_metrics"),
        "what_is_stable": [
            key for key, value in stable_profiles.items() if value
        ],
        "what_remains_degraded": list(level_a_report.get("stable_limitations") or []),
        "what_is_not_proven": [
            "attack repeatability",
            "acquisition repeatability",
            "trigger repeatability",
            "scenario redeployment reproducibility",
            "complete causality",
        ],
    }
    report = {
        "report_type": "level_a_scientific_comparison_report",
        "definition": "Scientific comparison of repeated read-only Level A executions over the same preserved case.",
        "source_case_id": source_case.get("case_id", "not_available"),
        "source_campaign_id": source_case.get("campaign_id", "not_available"),
        "scenario_id": source_case.get("scenario_id", "not_available"),
        "number_of_repetitions": len(per_repetition),
        "execution_ids": [item.get("execution_id") for item in per_repetition],
        "comparison_status": comparison.get("status", "not_available"),
        "comparison_type": comparison.get("comparison_type", "not_available"),
        "summary_metrics": {
            "mean_cpr": aggregate.get("cpr_mean", "not_available"),
            "std_cpr": aggregate.get("cpr_std", "not_available"),
            "mean_weighted_cpr": aggregate.get("weighted_cpr_mean", "not_available"),
            "std_weighted_cpr": aggregate.get("weighted_cpr_std", "not_available"),
            "max_delta_cpr": aggregate.get("delta_cpr", "not_available"),
            "max_delta_weighted_cpr": aggregate.get("delta_weighted_cpr", "not_available"),
            "max_support_rank_shift": aggregate.get("support_rank_shift", "not_available"),
        },
        "per_repetition_metric_table": [
            {
                "execution_id": item.get("execution_id"),
                "status": item.get("status", "not_available"),
                "CPR": item.get("CPR", "not_available"),
                "Weighted_CPR": item.get("Weighted_CPR", "not_available"),
                "hypothesis_support_level": item.get("hypothesis_support_level", "not_available"),
                "claimability_class": item.get("claimability_class", "not_available"),
                "timestamp_availability": item.get("timestamp_availability", "not_available"),
                "timestamp_resolvability": item.get("timestamp_resolvability", "not_available"),
            }
            for item in per_repetition
        ],
        "per_repetition_relation_table": relation_counts,
        "stable_profiles": stable_profiles,
        "degradation_reasons": list(comparison.get("degradation_reasons") or []),
        "hard_failures": list(comparison.get("hard_failures") or []),
        "stable_limitations": list(level_a_report.get("stable_limitations") or []),
        "drifted_metrics": list(level_a_report.get("drifted_metrics") or []),
        "scientific_position": scientific_position,
        "source_artifacts": {
            "comparability_result": ((comparison.get("artifacts") or {}).get("comparability_result")) or "not_available",
            "comparison_matrix": ((comparison.get("artifacts") or {}).get("comparison_matrix")) or "not_available",
            "comparability_report": ((comparison.get("artifacts") or {}).get("comparability_report")) or "not_available",
            "level_a_report": "level_a_report.json",
        },
    }
    lines = [
        "# Level A Scientific Comparison Report",
        "",
        "## Executive summary",
        "",
        f"- Source case: `{report['source_case_id']}`",
        f"- Campaign: `{report['source_campaign_id']}`",
        f"- Scenario: `{report['scenario_id']}`",
        f"- Repetitions compared: `{report['number_of_repetitions']}`",
        f"- Comparison type: `{report['comparison_type']}`",
        f"- Comparison status: `{report['comparison_status']}`",
        f"- Mean CPR: `{report['summary_metrics']['mean_cpr']}`",
        f"- Mean Weighted CPR: `{report['summary_metrics']['mean_weighted_cpr']}`",
        f"- Max |ΔCPR|: `{report['summary_metrics']['max_delta_cpr']}`",
        f"- Max |ΔWCPR|: `{report['summary_metrics']['max_delta_weighted_cpr']}`",
        "",
        "## Scientific interpretation",
        "",
        "- This report compares repeated Level A executions over the same sealed case, so it addresses analytical repeatability only.",
        "- Stable equality of CPR and Weighted CPR indicates stable analytical recovery over fixed evidence, not complete causality.",
        "- A status of `Comparable With Degradation` means the runs remained comparable while preserving the same degradation profile.",
        "",
        "## Per-repetition metric table",
        "",
        "| Execution | Status | CPR | Weighted CPR | Hypothesis support | Claimability |",
        "| --- | --- | ---: | ---: | --- | --- |",
    ]
    for item in report["per_repetition_metric_table"]:
        lines.append(
            f"| `{item['execution_id']}` | `{item['status']}` | `{item['CPR']}` | `{item['Weighted_CPR']}` | `{item['hypothesis_support_level']}` | `{item['claimability_class']}` |"
        )
    lines.extend(
        [
            "",
            "## Relation-state stability",
            "",
            "| Execution | Recovered | Degraded | Ambiguous | Missing |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for item in relation_counts:
        lines.append(
            f"| `{item['execution_id']}` | `{item['recovered_relations']}` | `{item['degraded_relations']}` | `{item['ambiguous_relations']}` | `{item['missing_relations']}` |"
        )
    lines.extend(
        [
            "",
            "## Stable versus drifted elements",
            "",
            f"- Stable profiles: `{', '.join(report['scientific_position']['what_is_stable']) or 'none'}`",
            f"- Drifted metrics: `{', '.join(report['drifted_metrics']) or 'none'}`",
            "",
            "## Persistent degradation",
            "",
        ]
    )
    if report["stable_limitations"]:
        for item in report["stable_limitations"]:
            lines.append(f"- {item}")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Reviewer-facing conclusion",
            "",
            "The repeated Level A executions are scientifically comparable at the analytical level because they preserve the same CPR/WCPR profile and the same conclusion class over the same preserved evidence. However, the comparison also shows that the same causal limitations persist across runs. This is evidence of stable degradation, not evidence of complete incident reconstruction.",
            "",
        ]
    )
    return report, "\n".join(lines) + "\n"


def _build_level_b_outputs(
    *,
    report_id: str,
    report_dir: Path,
    child_job_payload: dict,
    generate_latex: bool,
    generate_zip: bool,
) -> dict:
    level_b_api = _level_b_repetition_api()
    child_job_id = str(child_job_payload.get("job_id") or "")
    child_report_payload = level_b_api["get_level_b_repetition_report"](child_job_id) or {}
    level_b_report = dict(child_report_payload.get("report_json") or {})
    if not level_b_report:
        raise RuntimeError("level_b_report_not_ready")
    cleanup_manifest = dict(child_report_payload.get("cleanup_manifest") or {})
    requested_repetitions = int(level_b_report.get("requested_repetitions") or 0)
    completed = int(level_b_report.get("completed_repetitions") or 0)
    partial = int(level_b_report.get("partial_repetitions") or 0)
    failed = int(level_b_report.get("failed_repetitions") or 0)
    source_case_ids = [item.get("case_id") for item in (level_b_report.get("per_repetition_results") or []) if item.get("case_id")]
    nested_runs = [dict(item.get("nested_level_a") or {}) for item in (level_b_report.get("per_repetition_results") or [])]
    nested_completed = [item for item in nested_runs if str(item.get("status") or "").lower() in {"completed", "completed_with_degradation"}]
    table_registry = build_paper_table_registry(
        level="B",
        level_a_available=bool(nested_completed),
        level_a_report_path=relative_path(report_dir / "level_a_report.json"),
        level_b_available=True,
        level_b_report_path=relative_path(report_dir / "level_b_report.json"),
    )
    audit = build_capability_audit()
    paper_metrics_summary = {
        "artifact_availability": {
            "cases_created": len(source_case_ids),
            "cleanup_old_cases_before_run": cleanup_manifest.get("cleanup_status", "not_available"),
            "nested_level_a_reports_completed": len(nested_completed),
        },
        "analysis_usefulness": {
            "completed_repetitions": completed,
            "partial_repetitions": partial,
            "failed_repetitions": failed,
        },
        "trigger_and_acquisition_latency": dict(level_b_report.get("aggregate_timing_metrics") or {}),
        "cross_case_comparability": dict(level_b_report.get("higher_level_comparison") or {}),
        "nested_level_a_repeatability": dict(level_b_report.get("nested_level_a_aggregate") or {}),
        "aggregate_reconstruction_metrics": dict(level_b_report.get("aggregate_reconstruction_metrics") or {}),
    }
    paper_limitations_report = {
        "observed_degradation_states": [
            {
                "state": "higher_level_comparison_degradation",
                "type": "observed_degradation",
                "reason": "Cross-case comparison remained comparable only with degradation.",
            }
        ] if str(((level_b_report.get("higher_level_comparison") or {}).get("status") or "")).lower() == "comparable with degradation" else [],
        "warnings": list(level_b_report.get("warnings") or []),
        "blockers": list(level_b_report.get("blockers") or []),
        "cleanup_manifest": cleanup_manifest,
        "notes": [
            "Level B creates new cases and new preserved evidence, so this package addresses incident-to-case repeatability rather than read-only reanalysis.",
            "Each Level B repetition launches nested Level A repetitions over the fresh case after preservation and analysis complete.",
            "Heavy prior cases may be cleaned before the batch, and heavy case artifacts may also be cleaned after preservation-dependent reporting if the underlying Level B workflow performs that cleanup.",
        ],
    }
    manifest = {
        "report_id": report_id,
        "generated_at": utc_now(),
        "requested_level": "B",
        "status": child_job_payload.get("status") or level_b_report.get("status") or "not_available",
        "source_campaign_id": child_job_payload.get("meta", {}).get("campaign_id") or "not_available",
        "source_case_id": source_case_ids[0] if source_case_ids else "not_available",
        "child_level_b_job_id": child_job_id,
        "child_level_b_report_dir": child_report_payload.get("report_dir"),
        "capability_audit_path": relative_path(report_dir / "paper_capability_audit.json"),
        "paper_table_registry_path": relative_path(report_dir / "paper_table_registry.json"),
        "level_a_report_path": relative_path(report_dir / "level_a_report.json"),
        "level_b_report_path": relative_path(report_dir / "level_b_report.json"),
        "level_c_report_path": relative_path(report_dir / "level_c_report.json"),
        "paper_metrics_summary_path": relative_path(report_dir / "paper_metrics_summary.json"),
        "paper_limitations_report_path": relative_path(report_dir / "paper_limitations_report.json"),
        "paper_reviewer_defense_report_path": relative_path(report_dir / "paper_reviewer_defense_report.md"),
    }
    reviewer_lines = [
        "# Paper Evidence Package",
        "",
        "## Executive summary",
        "",
        f"- Report ID: `{report_id}`",
        f"- Level requested: `B`",
        f"- Generated at: `{manifest['generated_at']}`",
        f"- Source campaign: `{manifest['source_campaign_id']}`",
        f"- Requested repetitions: `{requested_repetitions}`",
        f"- Completed / partial / failed: `{completed}` / `{partial}` / `{failed}`",
        f"- Higher-level comparison status: `{((level_b_report.get('higher_level_comparison') or {}).get('status') or 'not_available')}`",
        f"- Nested Level A completed reports: `{len(nested_completed)}`",
        "",
        "## Reviewer-facing interpretation",
        "",
        "### What does this level prove?",
        "",
        "- Level B proves whether repeated execution of the same controlled incident in the same deployed scenario produces comparable new forensic cases and comparable reconstruction outputs.",
        "- Level B also exposes trigger quality, alert-to-acquisition latency, preservation ordering, and cross-case comparability.",
        "",
        "### What does this level not prove?",
        "",
        "- Level B does not prove full redeployment reproducibility. That belongs to Level C.",
        "",
        "### Cross-case scientific comparison",
        "",
        f"- Comparison type: `{((level_b_report.get('higher_level_comparison') or {}).get('comparison_type') or 'not_available')}`",
        f"- Comparison status: `{((level_b_report.get('higher_level_comparison') or {}).get('status') or 'not_available')}`",
        f"- Compared executions: `{', '.join(((level_b_report.get('higher_level_comparison') or {}).get('execution_ids') or [])) or 'not_available'}`",
        "",
        "### Operational latency and acquisition",
        "",
        f"- Alert -> memory start mean/std: `{(level_b_report.get('aggregate_timing_metrics') or {}).get('alert_to_memory_start_mean_seconds')}` / `{(level_b_report.get('aggregate_timing_metrics') or {}).get('alert_to_memory_start_std_seconds')}`",
        f"- Alert -> case sealed mean/std: `{(level_b_report.get('aggregate_timing_metrics') or {}).get('alert_to_case_sealed_mean_seconds')}` / `{(level_b_report.get('aggregate_timing_metrics') or {}).get('alert_to_case_sealed_std_seconds')}`",
        "",
        "### Nested Level A inside each Level B case",
        "",
        "- Each Level B repetition generated a new case and then launched a nested Level A repeatability audit over that preserved case.",
        f"- Nested comparison statuses: `{', '.join((level_b_report.get('nested_level_a_aggregate') or {}).get('comparison_statuses') or []) or 'not_available'}`",
        "",
        "### Which paper tables are supported by this output?",
        "",
    ]
    for row in table_registry.get("rows") or []:
        reviewer_lines.append(f"- `{row.get('table_label')}`: support=`{row.get('current_support_status')}` | concern=`{row.get('reviewer_concern_addressed')}`")
    reviewer_lines.extend(
        [
            "",
            "### Limitations and degradation",
            "",
        ]
    )
    if paper_limitations_report["warnings"] or paper_limitations_report["blockers"]:
        for item in paper_limitations_report["warnings"]:
            reviewer_lines.append(f"- warning: {item}")
        for item in paper_limitations_report["blockers"]:
            reviewer_lines.append(f"- blocker: {item}")
    else:
        reviewer_lines.append("- No additional warnings or blockers were recorded beyond the child Level B report.")
    reviewer_markdown = "\n".join(reviewer_lines) + "\n"

    _write_json(report_dir / "paper_evidence_manifest.json", manifest)
    _write_json(report_dir / "paper_capability_audit.json", audit)
    _write_json(report_dir / "paper_table_registry.json", table_registry)
    _write_json(report_dir / "level_a_report.json", _placeholder_level_report("A", "This package was not requested to run top-level Level A. Nested Level A outputs are embedded in the Level B report."))
    _write_json(report_dir / "level_b_report.json", level_b_report)
    _write_json(report_dir / "level_c_report.json", _placeholder_level_report("C", "Requires full scenario redeployment followed by repeated Level B execution."))
    _write_json(report_dir / "paper_metrics_summary.json", paper_metrics_summary)
    _write_json(report_dir / "paper_limitations_report.json", paper_limitations_report)
    _write_text(report_dir / "paper_reviewer_defense_report.md", reviewer_markdown)
    if generate_latex:
        _write_text(report_dir / "paper_table_registry.tex", _build_latex_tables(_placeholder_level_report("A", "not_requested"), table_registry)["paper_table_registry.tex"])
    zip_path = _zip_report_dir(report_dir) if generate_zip else None
    if zip_path:
        manifest["zip_path"] = relative_path(zip_path)
        _write_json(report_dir / "paper_evidence_manifest.json", manifest)
    return {
        "manifest": manifest,
        "level_b_report": level_b_report,
        "table_registry": table_registry,
        "paper_metrics_summary": paper_metrics_summary,
        "paper_limitations_report": paper_limitations_report,
        "paper_reviewer_defense_report": reviewer_markdown,
        "zip_path": relative_path(zip_path) if zip_path else None,
    }
    return {
        "lack_of_situational_context": {
            "status": "addressed",
            "response": "The package now includes a relation-state matrix with source event, target event, required evidence, recovered status, degradation reason, and temporal resolvability for every expected causal relation.",
            "supporting_sections": ["situational_relation_matrix", "observed_degradation_states"],
        },
        "weighted_cpr_arbitrariness": {
            "status": "partially_addressed",
            "response": "The package explicitly distinguishes the raw Weighted CPR ratio from reconstruction-confidence penalties and exposes the per-edge weights used by the current ground-truth model. The report still warns that these weights are scenario-defined methodological inputs, not objective natural constants.",
            "supporting_sections": ["weighted_cpr_methodology"],
            "weight_source": "scenario_ground_truth.json expected_edges[*].weight",
            "current_total_edge_weight": weighted.get("total_edge_weight", "not_available"),
        },
        "100_percent_operational_vs_partial_causality": {
            "status": "addressed",
            "response": "The package explicitly separates artifact availability, multilayer analysis completion, causal reconstruction strength, temporal confidence, integrity coverage, hypothesis support, and claimability. High structural or analytical completion is not reported as full causal success.",
            "supporting_sections": ["diagnostic_indicator_separation", "reviewer_facing_interpretation"],
            "scientific_position": final_position,
        },
    }


def _zip_report_dir(report_dir: Path) -> Path:
    zip_path = report_dir.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(report_dir.rglob("*")):
            if path.is_file():
                zf.write(path, arcname=path.relative_to(report_dir.parent))
    return zip_path


def _render_reviewer_markdown(
    *,
    manifest: dict,
    level_a_report: dict,
    limitations: dict,
    table_registry: dict,
) -> str:
    aggregate = level_a_report.get("aggregate_repeatability") or {}
    stable_limitations = level_a_report.get("stable_limitations") or []
    drifted_metrics = level_a_report.get("drifted_metrics") or []
    weighted = level_a_report.get("weighted_cpr_methodology") or {}
    relations = level_a_report.get("situational_relation_matrix") or []
    trigger = level_a_report.get("trigger_and_intervention_context") or {}
    relation_summary = _relation_support_summary(relations)
    reviewer_concerns = level_a_report.get("reviewer_concern_analysis") or {}
    lines = [
        "# Paper Evidence Package",
        "",
        "## Executive summary",
        "",
        f"- Report ID: `{manifest.get('report_id')}`",
        f"- Level requested: `{manifest.get('requested_level')}`",
        f"- Generated at: `{manifest.get('generated_at')}`",
        f"- Source case: `{(level_a_report.get('source_case') or {}).get('case_id', 'not_available')}`",
        f"- Level A repetitions: `{level_a_report.get('number_of_level_a_repetitions', 'not_available')}`",
        f"- Mean CPR: `{aggregate.get('cpr_mean', 'not_available')}`",
        f"- Mean Weighted CPR: `{aggregate.get('weighted_cpr_mean', 'not_available')}`",
        f"- Max |ΔCPR|: `{aggregate.get('delta_cpr', 'not_available')}`",
        f"- Max |ΔWCPR|: `{aggregate.get('delta_weighted_cpr', 'not_available')}`",
        f"- Repeatability status: `{level_a_report.get('repeatability_status', 'not_available')}`",
        "",
        "## Reviewer-facing interpretation",
        "",
        "### What does this level prove?",
        "",
        "- Level A proves analytical repeatability over the same preserved evidence set when the pipeline is rerun in read-only mode.",
        "- Level A supports stability claims for CPR, Weighted CPR, conclusion class, and limitation profile only when those values remain stable across the repeated executions.",
        "",
        "### What does this level not prove?",
        "",
        "- Level A does not prove attack repeatability, acquisition repeatability, trigger repeatability, or scenario redeployment reproducibility.",
        "- Level A does not convert a degraded preserved case into a complete causal reconstruction. Stable degradation must still be reported as degradation.",
        "",
        "### Why a partial causal result is not hidden behind a scalar",
        "",
        f"- Recovered relations: `{relation_summary.get('recovered', 0)}`",
        f"- Degraded relations: `{relation_summary.get('degraded', 0)}`",
        f"- Ambiguous relations: `{relation_summary.get('ambiguous', 0)}`",
        f"- Missing relations: `{relation_summary.get('missing', 0)}`",
        "- Every expected causal relation is reported with its source event, target event, expected evidence source, current support status, degradation reason, and temporal resolvability.",
        "",
        "### Situational meaning of degraded or missing relations",
        "",
    ]
    for item in relations:
        if str(item.get("recovered_status") or "").lower() in {"degraded", "ambiguous", "missing"}:
            lines.append(
                f"- `{item.get('edge_id')}`: {item.get('source_event')} -> {item.get('target_event')} | status=`{item.get('recovered_status')}` | expected evidence=`{item.get('expected_evidence_source')}` | temporal=`{item.get('temporal_resolvability')}` | reason={item.get('degradation_reason')}"
            )
    lines.extend(
        [
            "",
            "### Weighted CPR methodological note",
            "",
            f"- Weighted CPR formula: `{weighted.get('weighted_cpr_formula', 'not_available')}`",
            f"- Total edge weight: `{weighted.get('total_edge_weight', 'not_available')}`",
            f"- Recovered edge weight: `{weighted.get('recovered_edge_weight', 'not_available')}`",
            f"- Final Weighted CPR: `{weighted.get('final_weighted_score', 'not_available')}`",
            f"- Method note: {weighted.get('weighted_cpr_explanation', 'not_available')}",
            "- The decimal precision is computational reproducibility, not epistemic certainty. The report must not imply that a four-decimal score makes the causal model objective.",
            "- The current weight model comes from the scenario-defined expected causal edges. If the manuscript uses this score, the methodology section must justify the edge weights explicitly.",
            "",
            "### Operational completion versus causal evidence",
            "",
            f"- Analysis status: `{(level_a_report.get('analysis_context') or {}).get('analysis_status', 'not_available')}`",
            f"- Useful layers: `{((level_a_report.get('analysis_context') or {}).get('layers_with_useful_output', 'not_available'))}` / `{((level_a_report.get('analysis_context') or {}).get('layers_expected', 'not_available'))}`",
            f"- Trigger selected: `{trigger.get('trigger', 'not_available')}`",
            f"- Trigger selection method: `{trigger.get('trigger_selection_method', 'not_available')}`",
            f"- Stronger trigger available: `{trigger.get('stronger_trigger_available', 'not_available')}`",
            "- Completed analysis or alert-trigger selection is not treated as full causal proof. The package keeps trigger quality and alert-to-causal-path mismatch explicit.",
            "",
            "### Which paper tables are supported by this output?",
            "",
        ]
    )
    for row in table_registry.get("rows") or []:
        lines.append(
            f"- `{row.get('table_label')}`: support=`{row.get('current_support_status')}` | concern=`{row.get('reviewer_concern_addressed')}`"
        )
    lines.extend(
        [
            "",
            "### Which values are degraded, partial, missing, or not available?",
            "",
        ]
    )
    for item in limitations.get("observed_degradation_states") or []:
        lines.append(f"- `{item.get('state')}`: {item.get('reason')}")
    lines.extend(
        [
            "",
            "### Are any 100% values only operational preconditions rather than reconstruction evidence?",
            "",
            "- Yes. Structural readiness and completed analysis coverage are not equivalent to full causal reconstruction. Completed analysis can coexist with degraded or missing causal edges.",
            "- If a manuscript sentence claims 100% operational success, the report constrains that interpretation to preconditions such as scenario deployment, artifact indexing, or analysis completion. It does not let that sentence imply 100% causal recoverability.",
            "",
            "### Does the result support complete causality, partial causality, moderate support, or only technical completion?",
            "",
            f"- Current scientific conclusion class: `{level_a_report.get('scientific_conclusion_class', 'not_available')}`",
            f"- Hypothesis support stability: `{level_a_report.get('hypothesis_support_stability', 'not_available')}`",
            "",
            "## Stable limitations",
            "",
        ]
    )
    if stable_limitations:
        lines.extend([f"- {item}" for item in stable_limitations])
    else:
        lines.append("- not_available")
    lines.extend(
        [
            "",
            "## Drifted metrics",
            "",
        ]
    )
    if drifted_metrics:
        lines.extend([f"- {item}" for item in drifted_metrics])
    else:
        lines.append("- No drift was observed in the supported repeatability metrics.")
    lines.extend(
        [
            "",
            "## Reviewer concern matrix",
            "",
        ]
    )
    for key, item in reviewer_concerns.items():
        lines.append(f"- `{key}`: status=`{item.get('status')}` | {item.get('response')}")
    return "\n".join(lines) + "\n"


def _build_level_a_outputs(
    *,
    report_id: str,
    report_dir: Path,
    child_job_payload: dict,
    generate_latex: bool,
    generate_zip: bool,
) -> dict:
    level_a_meta = (child_job_payload.get("level_a_report") or {}).copy()
    metadata_path = _path_from_rel(level_a_meta.get("report_metadata_path"))
    metadata_file = _json_load(metadata_path) or {}
    if metadata_file:
        level_a_meta.update(metadata_file)
    case_id = str(level_a_meta.get("case_id") or "not_available")
    campaign_id = str(level_a_meta.get("campaign_id") or "not_available")
    generated_execution_ids = list(level_a_meta.get("generated_execution_ids") or [])

    source_index = _json_load(_path_from_rel(level_a_meta.get("source_files_index_path"))) or {}
    claim_map = _json_load(_path_from_rel(level_a_meta.get("evidence_to_claim_map_path"))) or {}
    report_summary = _json_load(_path_from_rel(level_a_meta.get("report_summary_path"))) or {}
    report_markdown_path = _path_from_rel(level_a_meta.get("report_markdown_path"))
    report_markdown = report_markdown_path.read_text(encoding="utf-8") if report_markdown_path and report_markdown_path.is_file() else ""

    case_entry = get_case_entry(case_id)
    case_dir = _case_dir_from_entry(case_entry) if case_entry else None
    dashboard = load_evidence_lifecycle_dashboard(case_id) if case_entry else {}
    summary = (dashboard or {}).get("summary") or {}
    causal_summary = summary.get("causal_summary") or {}
    final_conclusion = summary.get("final_forensic_conclusion") or {}
    execution_summary = summary.get("execution_summary") or {}
    trigger_summary = summary.get("trigger_summary") or {}
    analysis_status = load_analysis_status(case_id) if case_entry else {}
    causal_status = causal_status_payload(case_id, case_dir) if case_dir else {}
    causal_metrics = causal_metrics_payload(case_id, case_dir) if case_dir else {}
    uncertainty = causal_uncertainty_payload(case_id, case_dir) if case_dir else {}
    hypothesis = load_hypothesis_support_report(case_id) if case_entry else {}
    claimability = load_claimability_report(case_id) if case_entry else {}
    counter_evidence = load_counter_evidence_report(case_id) if case_entry else {}
    storyline = load_forensic_storyline(case_id) if case_entry else {}

    per_repetition = [_collect_level_a_execution_metrics(execution_id, campaign_id) for execution_id in generated_execution_ids]
    cprs = [_to_float(item.get("CPR")) for item in per_repetition]
    wcprs = [_to_float(item.get("Weighted_CPR")) for item in per_repetition]
    support_ranks = [_support_rank(item.get("hypothesis_support_level")) for item in per_repetition]
    claimability_classes = [str(item.get("claimability_class") or "not_available") for item in per_repetition]
    limitation_sets = [set(item.get("scientific_limitations") or []) for item in per_repetition]
    stable_limitations = sorted(set.intersection(*limitation_sets)) if limitation_sets else []
    union_limitations = sorted(set().union(*limitation_sets)) if limitation_sets else []
    drifted_metrics: list[str] = []
    delta_cpr = round(max(cprs) - min(cprs), 6) if len([x for x in cprs if x is not None]) >= 2 else "not_available"
    delta_wcpr = round(max(wcprs) - min(wcprs), 6) if len([x for x in wcprs if x is not None]) >= 2 else "not_available"
    support_shift = max(support_ranks) - min(support_ranks) if len([x for x in support_ranks if x is not None]) >= 2 else "not_available"
    if isinstance(delta_cpr, float) and delta_cpr > 0:
        drifted_metrics.append(f"CPR drift observed: {delta_cpr}")
    if isinstance(delta_wcpr, float) and delta_wcpr > 0:
        drifted_metrics.append(f"Weighted CPR drift observed: {delta_wcpr}")
    if isinstance(support_shift, int) and support_shift > 0:
        drifted_metrics.append(f"Hypothesis support rank shift observed: {support_shift}")
    if len(set(claimability_classes)) > 1:
        drifted_metrics.append("Conclusion-class stability is not perfect across the Level A repetitions.")

    comparison = compare_executions(generated_execution_ids, campaign_id=campaign_id) if len(generated_execution_ids) >= 2 else {"status": "Insufficient Data"}
    level_a_report = {
        "level": "A",
        "status": level_a_meta.get("status") or child_job_payload.get("status") or "not_available",
        "definition": "Reanalysis repeatability over the same preserved case and the same preserved evidence set in read-only mode.",
        "source_case": {
            "case_id": case_id,
            "case_path": relative_path(case_dir) if case_dir else "not_available",
            "scenario_id": summary.get("scenario_id") or "not_available",
            "scenario_name": summary.get("scenario_name") or "not_available",
            "campaign_id": campaign_id,
        },
        "analysis_run_ids": generated_execution_ids,
        "number_of_level_a_repetitions": len(generated_execution_ids),
        "repeatability_status": comparison.get("status", "not_available"),
        "per_repetition_metrics": per_repetition,
        "evidence_completeness_ratio": ((summary.get("integrity_summary") or {}).get("case_wide_integrity_ratio")) or "not_available",
        "analysis_context": {
            "analysis_status": analysis_status.get("status") or execution_summary.get("multilayer_analysis_status") or "not_available",
            "layers_with_useful_output": ((summary.get("multilayer_analysis_summary") or {}).get("layers_with_useful_output")) or "not_available",
            "layers_expected": ((summary.get("multilayer_analysis_summary") or {}).get("layers_expected")) or "not_available",
            "evidence_processing_interpretation": execution_summary.get("evidence_processing_interpretation") or "not_available",
        },
        "integrity_custody_coverage": {
            "integrity_status": ((summary.get("integrity_summary") or {}).get("integrity_status")) or "not_available",
            "integrity_ratio": ((summary.get("integrity_summary") or {}).get("case_wide_integrity_ratio")) or "not_available",
            "custody_status": ((summary.get("integrity_summary") or {}).get("custody_status")) or "not_available",
        },
        "timestamp_context": {
            "timestamp_availability": uncertainty.get("timestamp_availability", "not_available"),
            "timestamp_resolvability": uncertainty.get("timestamp_resolvability", "not_available"),
            "causal_temporal_ordering_confidence": uncertainty.get("temporal_confidence", "not_available"),
        },
        "causal_reconstruction": {
            "status": causal_status.get("status", "not_available"),
            "expected_relations": causal_metrics.get("expected_edges", "not_available"),
            "recovered_relations": causal_metrics.get("recovered_edges", "not_available"),
            "degraded_relations": causal_metrics.get("degraded_edges", "not_available"),
            "ambiguous_relations": causal_metrics.get("ambiguous_edges", "not_available"),
            "missing_relations": causal_metrics.get("missing_edges", "not_available"),
            "CPR": causal_metrics.get("cpr", "not_available"),
            "Weighted_CPR": causal_metrics.get("weighted_cpr", "not_available"),
            "reconstruction_confidence": causal_metrics.get("reconstruction_confidence", "not_available"),
        },
        "situational_relation_matrix": list((causal_summary.get("why_expected_relations") or {}).get("relations") or []),
        "weighted_cpr_methodology": causal_summary.get("weighted_cpr_details") or {},
        "modbus_specificity": causal_summary.get("modbus_specificity") or {},
        "trigger_and_intervention_context": {
            "trigger": trigger_summary.get("trigger", "not_available"),
            "trigger_type": trigger_summary.get("trigger_type", "not_available"),
            "triggering_alert_id": trigger_summary.get("triggering_alert_id", "not_available"),
            "triggering_alert_rule_id": trigger_summary.get("triggering_alert_rule_id", "not_available"),
            "triggering_alert_name": trigger_summary.get("triggering_alert_name", "not_available"),
            "trigger_selection_method": trigger_summary.get("trigger_selection_method", "not_available"),
            "stronger_trigger_available": trigger_summary.get("stronger_trigger_available", "not_available"),
            "intervention_status": trigger_summary.get("intervention_status", "not_available"),
        },
        "hypothesis_support": {
            "global_support_level": hypothesis.get("global_support_level", "not_available"),
            "final_claimability_status": hypothesis.get("final_claimability_status", "not_available"),
            "claimability_class": claimability.get("claimability_class") or hypothesis.get("final_claimability_status") or "not_available",
        },
        "repeatability_comparison": comparison,
        "aggregate_repeatability": {
            "cpr_mean": _mean_std([item for item in cprs if item is not None]).get("mean"),
            "cpr_std": _mean_std([item for item in cprs if item is not None]).get("std"),
            "weighted_cpr_mean": _mean_std([item for item in wcprs if item is not None]).get("mean"),
            "weighted_cpr_std": _mean_std([item for item in wcprs if item is not None]).get("std"),
            "delta_cpr": delta_cpr,
            "delta_weighted_cpr": delta_wcpr,
            "support_rank_shift": support_shift,
        },
        "conclusion_class_stability": "stable" if len(set(claimability_classes)) <= 1 else "drifted",
        "hypothesis_support_stability": "stable" if (support_shift in {0, "not_available"}) else "drifted",
        "scientific_conclusion_class": claimability.get("claimability_class") or hypothesis.get("final_claimability_status") or report_summary.get("hypothesis_support") or "not_available",
        "stable_limitations": stable_limitations,
        "all_observed_limitations": union_limitations,
        "drifted_metrics": drifted_metrics,
        "reviewer_concern_analysis": {},
        "supports": [
            "analytical repeatability",
            "stability of CPR/WCPR over fixed evidence",
            "stability of conclusion class",
            "stability of limitation profile",
        ],
        "does_not_support": [
            "attack repeatability",
            "acquisition repeatability",
            "trigger repeatability",
            "scenario redeployment reproducibility",
        ],
        "embedded_source_artifacts": {
            "level_a_report_markdown": level_a_meta.get("report_markdown_path"),
            "level_a_source_files_index": level_a_meta.get("source_files_index_path"),
            "level_a_evidence_to_claim_map": level_a_meta.get("evidence_to_claim_map_path"),
        },
        "manuscript_claim_guardrails": {
            "operational_completion_is_not_full_causal_success": True,
            "stable_degradation_must_be_reported_as_degradation": True,
            "weighted_cpr_precision_is_not_epistemic_certainty": True,
            "if_named_invariants_exist_they_require_explicit_runtime_mapping": True,
        },
        "executive_scientific_position": final_conclusion.get("summary_text") or "not_available",
    }
    level_a_report["reviewer_concern_analysis"] = _reviewer_concern_analysis(level_a_report)

    paper_metrics_summary = {
        "artifact_availability": {
            "summary_available": bool(summary),
            "source_index_files": len((source_index or {}).get("files") or []),
            "analysis_status": analysis_status.get("status") or "not_available",
        },
        "analysis_usefulness": {
            "useful_layers": ((summary.get("multilayer_analysis_summary") or {}).get("layers_with_useful_output")) or "not_available",
            "expected_layers": ((summary.get("multilayer_analysis_summary") or {}).get("layers_expected")) or "not_available",
        },
        "observation_recovery": {
            "timeline_entries": ((summary.get("multilayer_analysis_summary") or {}).get("timeline_entries")) or "not_available",
            "cross_layer_findings": ((summary.get("multilayer_analysis_summary") or {}).get("cross_layer_findings")) or "not_available",
        },
        "causal_reconstruction_strength": level_a_report["causal_reconstruction"],
        "temporal_confidence": level_a_report["timestamp_context"],
        "integrity_custody_coverage": level_a_report["integrity_custody_coverage"],
        "hypothesis_support": level_a_report["hypothesis_support"],
        "claimability_class": level_a_report["scientific_conclusion_class"],
        "repetition_stability": level_a_report["aggregate_repeatability"],
        "diagnostic_indicator_separation": {
            "artifact_availability": "separate",
            "analysis_usefulness": "separate",
            "observation_recovery": "separate",
            "causal_reconstruction_strength": "separate",
            "temporal_confidence": "separate",
            "integrity_custody_coverage": "separate",
            "hypothesis_support": "separate",
            "claimability_class": "separate",
            "repetition_stability": "separate",
        },
    }

    paper_limitations_report = {
        "observed_degradation_states": [
            {
                "state": item,
                "type": "observed_degradation",
                "reason": "Observed in real derived outputs reused by the Level A paper evidence package.",
            }
            for item in union_limitations
        ],
        "relation_state_matrix": level_a_report.get("situational_relation_matrix") or [],
        "weighted_cpr_methodology": level_a_report.get("weighted_cpr_methodology") or {},
        "modbus_specificity": level_a_report.get("modbus_specificity") or {},
        "trigger_and_intervention_context": level_a_report.get("trigger_and_intervention_context") or {},
        "counter_evidence": counter_evidence,
        "storyline": storyline,
        "stale_or_missing_outputs": [
            {"artifact": "hypothesis_support_report.json", "status": hypothesis.get("error", "available") if isinstance(hypothesis, dict) else "not_available"},
            {"artifact": "claimability_report.json", "status": claimability.get("error", "available") if isinstance(claimability, dict) else "not_available"},
        ],
        "notes": [
            "This package reflects observed degradation in real outputs. It does not claim a controlled fault-injection campaign unless such artifacts already exist.",
            "Completed analysis is kept separate from complete causal reconstruction.",
            "Weighted CPR is reported as a deterministic computation over scenario-defined edge weights, not as objective epistemic certainty.",
            "If the manuscript uses named invariants such as C1-C5, they must be mapped explicitly to runtime artifacts and metrics; otherwise the package will only support a requirements-to-metrics mapping, not a validated invariant table.",
        ],
    }

    table_registry = build_paper_table_registry(
        level="A",
        level_a_available=True,
        level_a_report_path=relative_path(report_dir / "level_a_report.json"),
    )
    level_a_comparison_report, level_a_comparison_markdown = _build_level_a_scientific_comparison_report(level_a_report)
    audit = build_capability_audit()
    manifest = {
        "report_id": report_id,
        "generated_at": utc_now(),
        "requested_level": "A",
        "status": level_a_report.get("status") or "not_available",
        "source_case_id": case_id,
        "source_campaign_id": campaign_id,
        "child_level_a_job_id": child_job_payload.get("job_id"),
        "child_level_a_report_path": level_a_meta.get("report_markdown_path"),
        "capability_audit_path": relative_path(report_dir / "paper_capability_audit.json"),
        "paper_table_registry_path": relative_path(report_dir / "paper_table_registry.json"),
        "level_a_report_path": relative_path(report_dir / "level_a_report.json"),
        "level_b_report_path": relative_path(report_dir / "level_b_report.json"),
        "level_c_report_path": relative_path(report_dir / "level_c_report.json"),
        "level_a_scientific_comparison_report_path": relative_path(report_dir / "level_a_scientific_comparison_report.json"),
        "level_a_scientific_comparison_markdown_path": relative_path(report_dir / "LEVEL_A_SCIENTIFIC_COMPARISON_REPORT.md"),
        "paper_metrics_summary_path": relative_path(report_dir / "paper_metrics_summary.json"),
        "paper_limitations_report_path": relative_path(report_dir / "paper_limitations_report.json"),
        "paper_reviewer_defense_report_path": relative_path(report_dir / "paper_reviewer_defense_report.md"),
        "report_markdown_source_path": level_a_meta.get("report_markdown_path"),
        "source_files_index_source_path": level_a_meta.get("source_files_index_path"),
        "evidence_to_claim_map_source_path": level_a_meta.get("evidence_to_claim_map_path"),
    }
    reviewer_markdown = _render_reviewer_markdown(
        manifest=manifest,
        level_a_report=level_a_report,
        limitations=paper_limitations_report,
        table_registry=table_registry,
    )

    _write_json(report_dir / "paper_evidence_manifest.json", manifest)
    _write_json(report_dir / "paper_capability_audit.json", audit)
    _write_json(report_dir / "paper_table_registry.json", table_registry)
    _write_json(report_dir / "level_a_report.json", level_a_report)
    _write_json(report_dir / "level_b_report.json", _placeholder_level_report("B", "Requires real Level B repeated incident executions."))
    _write_json(report_dir / "level_c_report.json", _placeholder_level_report("C", "Requires full scenario redeployment followed by repeated Level B execution."))
    _write_json(report_dir / "level_a_scientific_comparison_report.json", level_a_comparison_report)
    _write_json(report_dir / "paper_metrics_summary.json", paper_metrics_summary)
    _write_json(report_dir / "paper_limitations_report.json", paper_limitations_report)
    _write_text(report_dir / "paper_reviewer_defense_report.md", reviewer_markdown)
    _write_text(report_dir / "LEVEL_A_SCIENTIFIC_COMPARISON_REPORT.md", level_a_comparison_markdown)
    _write_text(report_dir / "embedded_level_a_scientific_report.md", report_markdown)
    _write_json(report_dir / "embedded_level_a_source_files_index.json", source_index)
    _write_json(report_dir / "embedded_level_a_evidence_to_claim_map.json", claim_map)
    if generate_latex:
        for filename, content in _build_latex_tables(level_a_report, table_registry).items():
            _write_text(report_dir / filename, content)
    zip_path = _zip_report_dir(report_dir) if generate_zip else None
    if zip_path:
        manifest["zip_path"] = relative_path(zip_path)
        _write_json(report_dir / "paper_evidence_manifest.json", manifest)
    return {
        "manifest": manifest,
        "level_a_report": level_a_report,
        "table_registry": table_registry,
        "level_a_scientific_comparison_report": level_a_comparison_report,
        "level_a_scientific_comparison_markdown": level_a_comparison_markdown,
        "paper_metrics_summary": paper_metrics_summary,
        "paper_limitations_report": paper_limitations_report,
        "paper_reviewer_defense_report": reviewer_markdown,
        "zip_path": relative_path(zip_path) if zip_path else None,
    }


def _wait_for_child_job(parent_job_id: str, parent_job_path: Path, child_job_id: str, *, phase_label: str) -> dict:
    while True:
        raise_if_cancelled(
            parent_job_id,
            parent_job_path,
            phase_key="level_a_runtime",
            phase_label=phase_label,
            detail="Paper evidence generation was cancelled while waiting for the nested Level A scientific report workflow.",
        )
        child = get_job(child_job_id)
        if not child:
            raise RuntimeError(f"child_job_not_found:{child_job_id}")
        parent_progress = _progress_slice(15.0, 85.0, child.get("progress_percent"))
        parent_payload = get_job(parent_job_id) or {}
        update_job(
            parent_job_id,
            parent_job_path,
            current_child_job_id=child_job_id,
            current_phase="level_a_runtime",
            current_phase_label=phase_label,
            current_phase_detail=str(child.get("current_phase_detail") or f"Waiting for nested job {child_job_id}."),
            progress_percent=parent_progress,
            phase_statuses=_upsert_phase_status(
                parent_payload,
                phase_key="level_a_runtime",
                phase_label=phase_label,
                status=str(child.get("status") or "running"),
                detail=str(child.get("current_phase_detail") or f"Waiting for nested job {child_job_id}."),
                progress_percent=parent_progress,
            ),
            nested_phase_statuses=list(child.get("phase_statuses") or []),
            nested_current_phase_label=child.get("current_phase_label") or child.get("current_phase") or "not_available",
            nested_current_phase_detail=child.get("current_phase_detail") or "not_available",
            nested_progress_percent=child.get("progress_percent"),
        )
        if str(child.get("status") or "").lower() in TERMINAL_JOB_STATUSES:
            return child
        time.sleep(2.5)


def _run_level_a_paper_evidence_job(job_id: str, job_path: Path, body: dict) -> None:
    case_id = str(body.get("case_id") or "").strip()
    if not case_id:
        raise ValueError("case_id_required_for_level_a_paper_evidence")
    entry = get_case_entry(case_id)
    if not entry:
        raise FileNotFoundError(f"case_not_found:{case_id}")
    n_repetitions = max(int(body.get("n_repetitions") or 6), 1)
    generate_latex = bool(body.get("generate_latex"))
    generate_zip = bool(body.get("generate_zip"))
    report_id = str(body.get("report_id") or _report_id("A", case_id=case_id))
    report_dir = _report_dir(report_id)
    update_job(
        job_id,
        job_path,
        current_case_id=case_id,
        current_phase="audit_existing_capabilities",
        current_phase_label="Audit existing scientific capabilities",
        current_phase_detail="Recording what the existing FOC views, endpoints, artifacts, and metrics already support before the paper-evidence run starts.",
        progress_percent=5.0,
        report_id=report_id,
        report_output_path=relative_path(report_dir),
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="audit_existing_capabilities",
            phase_label="Audit existing scientific capabilities",
            status="running",
            detail="Recording what the existing FOC views, endpoints, artifacts, and metrics already support before the paper-evidence run starts.",
            progress_percent=5.0,
        ),
    )
    report_dir.mkdir(parents=True, exist_ok=True)
    _write_json(report_dir / "paper_capability_audit.json", build_capability_audit())
    raise_if_cancelled(job_id, job_path)

    case_dir = _case_dir_from_entry(entry)
    manifest = _json_load(case_dir / "manifest.json") or {}
    scenario_id = str(manifest.get("scenario_id") or body.get("scenario_id") or "not_available")
    update_job(
        job_id,
        job_path,
        current_phase="prepare_level_a_campaign",
        current_phase_label="Prepare Level A campaign",
        current_phase_detail=f"Creating an isolated Level A campaign for paper evidence generation over preserved case {case_id}.",
        progress_percent=10.0,
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="prepare_level_a_campaign",
            phase_label="Prepare Level A campaign",
            status="running",
            detail=f"Creating an isolated Level A campaign for paper evidence generation over preserved case {case_id}.",
            progress_percent=10.0,
        ),
    )
    campaign_payload = create_campaign(
        {
            "level": "A",
            "name": f"Paper Evidence Level A — {case_id}",
            "description": "Reviewer-facing Level A paper evidence package generated from the preserved case in read-only mode.",
            "base_case_id": case_id,
            "base_case_path": str(case_dir),
            "scenario_id": None if scenario_id == "not_available" else scenario_id,
            "repetitions": n_repetitions,
            "analysis_profile_id": body.get("analysis_profile_id") or "default_multilayer_analysis_v1",
            "foc_profile_id": body.get("foc_profile_id") or "default_foc_causal_reconstruction_v1",
            "acquisition_profile_id": body.get("acquisition_profile_id") or "default_kolla_lime_tshark_v1",
            "trigger_policy_id": body.get("trigger_policy_id") or "highest_severity_alert_v1",
            "notes": "Created automatically by foc_paper_evidence Level A runner.",
        }
    )
    campaign_id = str((campaign_payload.get("campaign") or {}).get("campaign_id"))
    update_job(
        job_id,
        job_path,
        current_phase="run_nested_level_a_workflow",
        current_phase_label="Run nested Level A scientific workflow",
        current_phase_detail=f"Launching the existing consolidated Level A scientific report workflow with {n_repetitions} repetitions.",
        progress_percent=15.0,
        created_campaign_id=campaign_id,
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="run_nested_level_a_workflow",
            phase_label="Run nested Level A scientific workflow",
            status="running",
            detail=f"Launching the existing consolidated Level A scientific report workflow with {n_repetitions} repetitions.",
            progress_percent=15.0,
        ),
    )
    child_job = start_level_a_scientific_report_job(campaign_id)
    child_payload = _wait_for_child_job(job_id, job_path, str(child_job.get("job_id")), phase_label="Run nested Level A scientific workflow")
    if str(child_payload.get("status") or "").lower() in {"failed", "cancelled", "stopped"}:
        raise RuntimeError(f"nested_level_a_workflow_{str(child_payload.get('status') or 'failed')}")
    update_job(
        job_id,
        job_path,
        current_phase="assemble_paper_package",
        current_phase_label="Assemble paper evidence package",
        current_phase_detail="Collecting the nested Level A outputs, capability audit, table registry, metrics summary, and reviewer-facing interpretation.",
        progress_percent=88.0,
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="assemble_paper_package",
            phase_label="Assemble paper evidence package",
            status="running",
            detail="Collecting the nested Level A outputs, capability audit, table registry, metrics summary, and reviewer-facing interpretation.",
            progress_percent=88.0,
        ),
    )
    outputs = _build_level_a_outputs(
        report_id=report_id,
        report_dir=report_dir,
        child_job_payload=child_payload,
        generate_latex=generate_latex,
        generate_zip=generate_zip,
    )
    update_job(
        job_id,
        job_path,
        status=outputs["manifest"].get("status") or "completed",
        finished_at=utc_now(),
        current_phase="completed",
        current_phase_label="Completed",
        current_phase_detail=f"Paper evidence package written to {relative_path(report_dir)}.",
        progress_percent=100.0,
        report_output_path=relative_path(report_dir),
        paper_evidence_manifest_path=outputs["manifest"]["paper_metrics_summary_path"] if False else relative_path(report_dir / "paper_evidence_manifest.json"),
        report_id=report_id,
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="completed",
            phase_label="Completed",
            status=outputs["manifest"].get("status") or "completed",
            detail=f"Paper evidence package written to {relative_path(report_dir)}.",
            progress_percent=100.0,
        ),
        allow_post_stop_update=True,
    )


def _run_level_b_paper_evidence_job(job_id: str, job_path: Path, body: dict) -> None:
    level_b_api = _level_b_repetition_api()
    campaign_id = str(body.get("campaign_id") or "").strip()
    if not campaign_id:
        raise ValueError("campaign_id_required_for_level_b_paper_evidence")
    requested_repetitions = max(int(body.get("n_repetitions") or body.get("requested_repetitions") or 6), 1)
    nested_level_a_repetitions = max(int(body.get("nested_level_a_repetitions") or requested_repetitions), 1)
    generate_latex = bool(body.get("generate_latex"))
    generate_zip = bool(body.get("generate_zip"))
    cleanup_old_cases = bool(body.get("cleanup_old_cases", True))
    report_id = str(body.get("report_id") or _report_id("B", scenario_id=campaign_id))
    report_dir = _report_dir(report_id)
    update_job(
        job_id,
        job_path,
        current_phase="audit_existing_capabilities",
        current_phase_label="Audit existing scientific capabilities",
        current_phase_detail="Recording what the existing FOC views, endpoints, artifacts, and metrics already support before the paper-evidence run starts.",
        progress_percent=5.0,
        report_id=report_id,
        report_output_path=relative_path(report_dir),
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="audit_existing_capabilities",
            phase_label="Audit existing scientific capabilities",
            status="running",
            detail="Recording what the existing FOC views, endpoints, artifacts, and metrics already support before the paper-evidence run starts.",
            progress_percent=5.0,
        ),
    )
    report_dir.mkdir(parents=True, exist_ok=True)
    _write_json(report_dir / "paper_capability_audit.json", build_capability_audit())
    raise_if_cancelled(job_id, job_path)
    preview = level_b_api["preview_level_b_repetitions"](
        campaign_id,
        requested_repetitions=requested_repetitions,
        requested_nested_level_a_repetitions=nested_level_a_repetitions,
    )
    if not preview.get("ready"):
        raise ValueError(str(preview.get("error") or "level_b_preview_not_ready"))
    update_job(
        job_id,
        job_path,
        current_phase="prepare_level_b_batch",
        current_phase_label="Prepare Level B batch",
        current_phase_detail=f"Launching the existing Level B repetition workflow for campaign {campaign_id} with {requested_repetitions} requested repetitions and {preview.get('nested_level_a_repetitions')} nested Level A repetitions per case.",
        progress_percent=10.0,
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="prepare_level_b_batch",
            phase_label="Prepare Level B batch",
            status="running",
            detail=f"Launching the existing Level B repetition workflow for campaign {campaign_id} with {requested_repetitions} requested repetitions and {preview.get('nested_level_a_repetitions')} nested Level A repetitions per case.",
            progress_percent=10.0,
        ),
    )
    child_job = level_b_api["start_level_b_repetitions_job"](
        campaign_id,
        confirmation="OK",
        requested_repetitions=requested_repetitions,
        requested_nested_level_a_repetitions=nested_level_a_repetitions,
        cleanup_old_cases=cleanup_old_cases,
        detection_timeout_seconds=body.get("detection_timeout_seconds"),
        dfir_mode_before=str(body.get("dfir_mode_before") or "unknown"),
        dfir_mode_after=str(body.get("dfir_mode_after") or "on"),
    )
    child_payload = _wait_for_child_job(job_id, job_path, str(child_job.get("job_id")), phase_label="Run nested Level B scientific workflow")
    if str(child_payload.get("status") or "").lower() in {"failed", "cancelled", "stopped"}:
        raise RuntimeError(f"nested_level_b_workflow_{str(child_payload.get('status') or 'failed')}")
    update_job(
        job_id,
        job_path,
        current_phase="assemble_paper_package",
        current_phase_label="Assemble paper evidence package",
        current_phase_detail="Collecting the nested Level B outputs, capability audit, table registry, metrics summary, and reviewer-facing interpretation.",
        progress_percent=88.0,
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="assemble_paper_package",
            phase_label="Assemble paper evidence package",
            status="running",
            detail="Collecting the nested Level B outputs, capability audit, table registry, metrics summary, and reviewer-facing interpretation.",
            progress_percent=88.0,
        ),
    )
    outputs = _build_level_b_outputs(
        report_id=report_id,
        report_dir=report_dir,
        child_job_payload=child_payload,
        generate_latex=generate_latex,
        generate_zip=generate_zip,
    )
    update_job(
        job_id,
        job_path,
        status=outputs["manifest"].get("status") or "completed",
        finished_at=utc_now(),
        current_phase="completed",
        current_phase_label="Completed",
        current_phase_detail=f"Paper evidence package written to {relative_path(report_dir)}.",
        progress_percent=100.0,
        report_output_path=relative_path(report_dir),
        paper_evidence_manifest_path=relative_path(report_dir / "paper_evidence_manifest.json"),
        report_id=report_id,
        phase_statuses=_upsert_phase_status(
            get_job(job_id) or {},
            phase_key="completed",
            phase_label="Completed",
            status=outputs["manifest"].get("status") or "completed",
            detail=f"Paper evidence package written to {relative_path(report_dir)}.",
            progress_percent=100.0,
        ),
        allow_post_stop_update=True,
    )


def _run_placeholder_level_job(job_id: str, job_path: Path, *, level: str, body: dict) -> None:
    report_id = str(body.get("report_id") or _report_id(level, case_id=str(body.get("case_id") or "") or None, scenario_id=str(body.get("scenario_id") or "") or None))
    report_dir = _report_dir(report_id)
    report_dir.mkdir(parents=True, exist_ok=True)
    update_job(
        job_id,
        job_path,
        current_phase="prepare_placeholder_package",
        current_phase_label=f"Prepare Level {level} placeholder package",
        current_phase_detail=f"Recording the current support boundaries for Level {level}. Runtime paper evidence for this level is not fully implemented in this iteration.",
        progress_percent=50.0,
        report_output_path=relative_path(report_dir),
        report_id=report_id,
    )
    table_registry = build_paper_table_registry(level=level, level_a_available=False)
    manifest = {
        "report_id": report_id,
        "generated_at": utc_now(),
        "requested_level": level,
        "status": "unsupported",
        "reason": f"Level {level} paper evidence is not fully implemented in this iteration.",
        "paper_table_registry_path": relative_path(report_dir / "paper_table_registry.json"),
    }
    _write_json(report_dir / "paper_evidence_manifest.json", manifest)
    _write_json(report_dir / "paper_capability_audit.json", build_capability_audit())
    _write_json(report_dir / "paper_table_registry.json", table_registry)
    _write_json(report_dir / "level_a_report.json", _placeholder_level_report("A", "This package was not requested to run Level A."))
    _write_json(report_dir / "level_b_report.json", _placeholder_level_report("B", "Requires real repeated incident execution."))
    _write_json(report_dir / "level_c_report.json", _placeholder_level_report("C", "Requires full redeployment plus Level B execution."))
    _write_json(report_dir / "paper_metrics_summary.json", {"status": "unsupported"})
    _write_json(report_dir / "paper_limitations_report.json", {"status": "unsupported", "reason": manifest["reason"]})
    _write_text(report_dir / "paper_reviewer_defense_report.md", f"# Level {level} Paper Evidence Package\n\nThis level is not yet fully implemented.\n")
    update_job(
        job_id,
        job_path,
        status="completed_with_degradation",
        finished_at=utc_now(),
        current_phase="completed",
        current_phase_label="Completed with degradation",
        current_phase_detail=f"Placeholder Level {level} paper evidence package written to {relative_path(report_dir)}.",
        progress_percent=100.0,
        report_output_path=relative_path(report_dir),
        report_id=report_id,
    )


def _start_job(level: str, title: str, body: dict, runner) -> dict:
    report_id = str(body.get("report_id") or _report_id(level, case_id=str(body.get("case_id") or "") or None, scenario_id=str(body.get("scenario_id") or "") or None))
    job_root = _report_dir(report_id)
    job_root.mkdir(parents=True, exist_ok=True)
    job = new_job(
        job_type=f"paper_evidence_level_{level.lower()}",
        title=title,
        job_path=job_root / f"{job_root.name}-job.json",
        meta={
            "report_id": report_id,
            "level": level,
            "case_id": str(body.get("case_id") or "") or None,
            "scenario_id": str(body.get("scenario_id") or "") or None,
            "n_repetitions": int(body.get("n_repetitions") or 6),
            "workflow": "paper_evidence",
        },
    )
    return start_job(job, lambda job_id, job_path: runner(job_id, job_path, body))


def start_level_a_paper_evidence_job(body: dict) -> dict:
    return _start_job("A", "Generate Level A Paper Evidence Report", body, _run_level_a_paper_evidence_job)


def start_level_b_paper_evidence_job(body: dict) -> dict:
    return _start_job("B", "Generate Level B Paper Evidence Report", body, _run_level_b_paper_evidence_job)


def start_level_c_paper_evidence_job(body: dict) -> dict:
    return _start_job("C", "Prepare Level C Paper Evidence Report", body, lambda job_id, job_path, inner: _run_placeholder_level_job(job_id, job_path, level="C", body=inner))


def start_paper_evidence_binder_job(body: dict) -> dict:
    level = str(body.get("level") or "A").strip().upper()
    if level == "A":
        return start_level_a_paper_evidence_job(body)
    if level == "B":
        return start_level_b_paper_evidence_job(body)
    if level == "C":
        return start_level_c_paper_evidence_job(body)
    if level == "ALL":
        return start_level_a_paper_evidence_job(body)
    raise ValueError("invalid_paper_evidence_level")


def get_paper_evidence_report(report_id: str) -> dict | None:
    report_dir = _report_dir(report_id)
    manifest = _json_load(report_dir / "paper_evidence_manifest.json")
    if not isinstance(manifest, dict):
        return None
    level_a_report = _json_load(report_dir / "level_a_report.json") or {}
    comparison_json_path = report_dir / "level_a_scientific_comparison_report.json"
    comparison_md_path = report_dir / "LEVEL_A_SCIENTIFIC_COMPARISON_REPORT.md"
    comparison_report = _json_load(comparison_json_path) or {}
    if not comparison_report and level_a_report:
        comparison_report, comparison_markdown = _build_level_a_scientific_comparison_report(level_a_report)
        _write_json(comparison_json_path, comparison_report)
        _write_text(comparison_md_path, comparison_markdown)
        if not manifest.get("level_a_scientific_comparison_report_path"):
            manifest["level_a_scientific_comparison_report_path"] = relative_path(comparison_json_path)
            manifest["level_a_scientific_comparison_markdown_path"] = relative_path(comparison_md_path)
            _write_json(report_dir / "paper_evidence_manifest.json", manifest)
    reviewer_md_path = report_dir / "paper_reviewer_defense_report.md"
    return {
        "report_id": report_id,
        "manifest": manifest,
        "paper_table_registry": _json_load(report_dir / "paper_table_registry.json") or {},
        "level_a_report": level_a_report,
        "level_a_scientific_comparison_report": comparison_report,
        "level_b_report": _json_load(report_dir / "level_b_report.json") or {},
        "level_c_report": _json_load(report_dir / "level_c_report.json") or {},
        "paper_metrics_summary": _json_load(report_dir / "paper_metrics_summary.json") or {},
        "paper_limitations_report": _json_load(report_dir / "paper_limitations_report.json") or {},
        "paper_reviewer_defense_report": reviewer_md_path.read_text(encoding="utf-8") if reviewer_md_path.is_file() else "",
        "level_a_scientific_comparison_markdown": comparison_md_path.read_text(encoding="utf-8") if comparison_md_path.is_file() else "",
    }


def list_paper_evidence_reports(*, level: str | None = None, case_id: str | None = None) -> dict:
    rows: list[dict] = []
    for manifest_path in sorted(PAPER_EVIDENCE_ROOT.glob("paper-*/paper_evidence_manifest.json"), reverse=True):
        payload = _json_load(manifest_path)
        if not isinstance(payload, dict):
            continue
        requested_level = str(payload.get("requested_level") or "").upper()
        source_case_id = str(payload.get("source_case_id") or "")
        if level and requested_level != str(level).upper():
            continue
        if case_id and source_case_id != str(case_id):
            continue
        rows.append(
            {
                "report_id": payload.get("report_id") or manifest_path.parent.name,
                "requested_level": requested_level or "not_available",
                "status": payload.get("status") or "not_available",
                "generated_at": payload.get("generated_at") or "not_available",
                "source_case_id": source_case_id or "not_available",
                "source_campaign_id": payload.get("source_campaign_id") or "not_available",
                "report_dir": relative_path(manifest_path.parent),
                "manifest_path": relative_path(manifest_path),
                "paper_reviewer_defense_report_path": payload.get("paper_reviewer_defense_report_path") or relative_path(manifest_path.parent / "paper_reviewer_defense_report.md"),
                "zip_path": payload.get("zip_path"),
            }
        )
    return {
        "generated_at": utc_now(),
        "root": relative_path(PAPER_EVIDENCE_ROOT),
        "reports": rows,
    }


def get_paper_evidence_table_registry(report_id: str) -> dict | None:
    return _json_load(_report_dir(report_id) / "paper_table_registry.json")


def get_paper_evidence_zip_path(report_id: str) -> Path | None:
    report_dir = _report_dir(report_id)
    manifest = _json_load(report_dir / "paper_evidence_manifest.json") or {}
    zip_path = _path_from_rel(manifest.get("zip_path"))
    if zip_path and zip_path.is_file():
        return zip_path
    if not report_dir.is_dir():
        return None
    created = _zip_report_dir(report_dir)
    manifest["zip_path"] = relative_path(created)
    _write_json(report_dir / "paper_evidence_manifest.json", manifest)
    return created
