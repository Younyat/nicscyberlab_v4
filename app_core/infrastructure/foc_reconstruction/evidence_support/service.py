from __future__ import annotations

import threading
from pathlib import Path

from ..evidence_lifecycle_dashboard import (
    _JOB_LOCK,
    _JOBS,
    _RUNNING_JOB_THREADS,
    _artifact_paths,
    _build_causal_summary,
    _case_dir_from_entry,
    _json_load,
    _mtime,
    _new_job,
    _pick_attack,
    _pick_intervention,
    _resolve_real_ground_truth,
    _set_job,
    _source_bundle,
    _update_phase,
    _write_json,
    get_case_entry,
    relative_path,
)
from ..foc_sources import utc_now
from ...foc_causal_reconstruction.service import (
    causal_graph_payload,
    causal_metrics_payload,
    causal_status_payload,
    causal_uncertainty_payload,
)
from . import triage
from .atoms import read_atoms_jsonl, write_atoms_jsonl
from .correlation import (
    build_claimability_report,
    build_counter_evidence_report,
    build_cross_layer_matrix,
    build_forensic_storyline,
    build_hypothesis_support_report,
    compute_global_support_level,
)

_STALENESS_SOURCE_KEYS = [
    "forensic_analysis_report",
    "network_findings",
    "memory_findings",
    "disk_findings",
    "ot_findings",
    "alert_findings",
    "unified_forensic_timeline",
    "causal_graph",
    "reconstruction_metrics",
    "uncertainty_report",
    "causal_status",
]

JOB_TYPE = "evidence_support_generation"


def evidence_support_dir(case_dir: Path) -> Path:
    return case_dir / "derived" / "evidence_support"


def _atoms_path(case_dir: Path) -> Path:
    return evidence_support_dir(case_dir) / "evidence_atoms.jsonl"


def _triage_report_path(case_dir: Path) -> Path:
    return evidence_support_dir(case_dir) / "evidence_triage_report.json"


def _matrix_path(case_dir: Path) -> Path:
    return evidence_support_dir(case_dir) / "cross_layer_support_matrix.json"


def _hypothesis_path(case_dir: Path) -> Path:
    return evidence_support_dir(case_dir) / "hypothesis_support_report.json"


def _storyline_path(case_dir: Path) -> Path:
    return evidence_support_dir(case_dir) / "forensic_storyline.json"


def _claimability_path(case_dir: Path) -> Path:
    return evidence_support_dir(case_dir) / "claimability_report.json"


def _counter_evidence_path(case_dir: Path) -> Path:
    return evidence_support_dir(case_dir) / "counter_evidence_report.json"


def evidence_support_staleness(case_dir: Path) -> dict:
    atoms_path = _atoms_path(case_dir)
    if not atoms_path.is_file():
        return {
            "status": "not_generated",
            "is_stale": True,
            "reason": "Evidence-based hypothesis support has not been generated for this case yet.",
            "required_action": "generate evidence-based hypothesis support.",
            "generated_at_mtime": None,
        }
    atoms_mtime = _mtime(atoms_path)
    paths = _artifact_paths(case_dir)
    newer_sources = [key for key in _STALENESS_SOURCE_KEYS if paths.get(key) and _mtime(paths[key]) > atoms_mtime]
    if newer_sources:
        return {
            "status": "stale",
            "is_stale": True,
            "reason": "One or more source artifacts changed after the evidence support extract was generated.",
            "required_action": "regenerate evidence support extract.",
            "newer_sources": newer_sources,
            "generated_at_mtime": atoms_mtime,
        }
    return {
        "status": "current",
        "is_stale": False,
        "reason": None,
        "required_action": None,
        "generated_at_mtime": atoms_mtime,
    }


def build_evidence_support(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        raise FileNotFoundError(f"Case {case_id} was not found.")
    case_dir = _case_dir_from_entry(entry)

    bundle = _source_bundle()
    causal_status = causal_status_payload(case_id, case_dir)
    metrics = causal_metrics_payload(case_id, case_dir) or {}
    uncertainty = causal_uncertainty_payload(case_id, case_dir) or {}
    intervention = _pick_intervention(case_id, bundle)
    causal_graph = causal_graph_payload(case_id, case_dir) or {}
    causal_summary = _build_causal_summary(case_id, case_dir, bundle, causal_status, metrics, uncertainty, intervention)
    ground_truth = _resolve_real_ground_truth(causal_status, bundle.get("scenario_ground_truth") or {})
    attack = _pick_attack(bundle, ground_truth)

    atoms: list[dict] = []
    atoms += triage.triage_memory(case_dir, case_id)
    atoms += triage.triage_network(case_dir, case_id)
    atoms += triage.triage_disk(case_dir, case_id)
    atoms += triage.triage_ot(case_dir, case_id)
    atoms += triage.triage_alerts(case_dir, case_id, causal_summary)
    atoms += triage.triage_timeline(case_dir, case_id)
    atoms += triage.triage_custody(case_dir, case_id, uncertainty)
    atoms += triage.triage_causal_graph(case_dir, case_id, causal_graph)

    matrix = build_cross_layer_matrix(causal_graph, atoms)
    global_support_level = compute_global_support_level(matrix, atoms)
    hypothesis_report = build_hypothesis_support_report(case_id, ground_truth, attack, matrix, atoms, global_support_level)
    # Carried into the report so the dashboard's single fetch can render the
    # Layer Contribution Matrix card without a second request.
    hypothesis_report["layer_contribution_matrix"] = matrix.get("layer_contribution_matrix")
    hypothesis_report["relations"] = matrix.get("relations")
    claimability_report = build_claimability_report(matrix, atoms)
    counter_evidence_report = build_counter_evidence_report(atoms)
    storyline = build_forensic_storyline(case_id, atoms, global_support_level)

    layer_counts: dict[str, int] = {}
    for atom in atoms:
        layer_counts[atom["evidence_layer"]] = layer_counts.get(atom["evidence_layer"], 0) + 1
    triage_report = {
        "case_id": case_id,
        "generated_at": utc_now(),
        "total_atoms": len(atoms),
        "atom_counts_by_layer": layer_counts,
    }

    write_atoms_jsonl(_atoms_path(case_dir), atoms)
    _write_json(_triage_report_path(case_dir), triage_report)
    _write_json(_matrix_path(case_dir), matrix)
    _write_json(_hypothesis_path(case_dir), hypothesis_report)
    _write_json(_storyline_path(case_dir), storyline)
    _write_json(_claimability_path(case_dir), claimability_report)
    _write_json(_counter_evidence_path(case_dir), counter_evidence_report)

    return {
        "case_id": case_id,
        "global_support_level": global_support_level,
        "total_atoms": len(atoms),
        "atoms_path": relative_path(_atoms_path(case_dir)),
        "evidence_triage_report_path": relative_path(_triage_report_path(case_dir)),
        "cross_layer_support_matrix_path": relative_path(_matrix_path(case_dir)),
        "hypothesis_support_report_path": relative_path(_hypothesis_path(case_dir)),
        "forensic_storyline_path": relative_path(_storyline_path(case_dir)),
        "claimability_report_path": relative_path(_claimability_path(case_dir)),
        "counter_evidence_report_path": relative_path(_counter_evidence_path(case_dir)),
    }


def _evidence_support_worker(job: dict, case_dir: Path) -> None:
    try:
        _set_job(job, case_dir, status="running", started_at=utc_now(), current_phase="triage_and_correlate", progress_percent=10)
        _update_phase(job, case_dir, "triage_and_correlate", "running", started_at=utc_now())
        result = build_evidence_support(job["case_id"])
        _update_phase(
            job,
            case_dir,
            "triage_and_correlate",
            "completed",
            finished_at=utc_now(),
            artifact_path=result.get("hypothesis_support_report_path"),
        )
        generated = [
            result.get(key)
            for key in (
                "atoms_path",
                "evidence_triage_report_path",
                "cross_layer_support_matrix_path",
                "hypothesis_support_report_path",
                "forensic_storyline_path",
                "claimability_report_path",
                "counter_evidence_report_path",
            )
            if result.get(key)
        ]
        _set_job(
            job,
            case_dir,
            status="completed",
            finished_at=utc_now(),
            current_phase="completed",
            progress_percent=100,
            generated_artifacts=generated,
            result_summary={"global_support_level": result.get("global_support_level"), "total_atoms": result.get("total_atoms")},
        )
    except Exception as exc:
        _update_phase(job, case_dir, "triage_and_correlate", "failed", finished_at=utc_now(), error_message=str(exc))
        _set_job(job, case_dir, status="failed", finished_at=utc_now(), current_phase="failed", progress_percent=100, errors=[str(exc)])
    finally:
        with _JOB_LOCK:
            _RUNNING_JOB_THREADS.pop(job["job_id"], None)


def start_evidence_support_job(case_id: str, force: bool = False) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)

    with _JOB_LOCK:
        for job_id, thread in list(_RUNNING_JOB_THREADS.items()):
            existing = _JOBS.get(job_id)
            if existing and existing.get("case_id") == case_id and existing.get("job_type") == JOB_TYPE and thread.is_alive():
                return {"error": "evidence_support_already_running", "job_id": job_id}

    if not force:
        staleness = evidence_support_staleness(case_dir)
        if staleness["status"] == "current":
            return {"case_id": case_id, **staleness, "status": "already_current"}

    job = _new_job(case_id, case_dir, JOB_TYPE, "Generate Evidence-Based Hypothesis Support")
    worker = threading.Thread(target=_evidence_support_worker, args=(job, case_dir), daemon=True, name=f"evidence-support-{case_id}")
    with _JOB_LOCK:
        _RUNNING_JOB_THREADS[job["job_id"]] = worker
    worker.start()
    return job


def load_evidence_support_status(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    staleness = evidence_support_staleness(case_dir)
    return {"case_id": case_id, **staleness}


def load_hypothesis_support_report(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    payload = _json_load(_hypothesis_path(case_dir))
    if not isinstance(payload, dict):
        return {"error": "not_generated", "case_id": case_id}
    payload["is_stale"] = evidence_support_staleness(case_dir)["is_stale"]
    return payload


def load_forensic_storyline(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    payload = _json_load(_storyline_path(case_dir))
    if not isinstance(payload, dict):
        return {"error": "not_generated", "case_id": case_id}
    return payload


def load_claimability_report(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    payload = _json_load(_claimability_path(case_dir))
    if not isinstance(payload, dict):
        return {"error": "not_generated", "case_id": case_id}
    return payload


def load_counter_evidence_report(case_id: str) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    payload = _json_load(_counter_evidence_path(case_dir))
    if not isinstance(payload, dict):
        return {"error": "not_generated", "case_id": case_id}
    return payload


def load_evidence_atoms(case_id: str, limit: int | None = None) -> dict:
    entry = get_case_entry(case_id)
    if not entry:
        return {"error": "case_not_found", "case_id": case_id}
    case_dir = _case_dir_from_entry(entry)
    atoms_path = _atoms_path(case_dir)
    if not atoms_path.is_file():
        return {"error": "not_generated", "case_id": case_id}
    all_atoms = read_atoms_jsonl(atoms_path)
    atoms = all_atoms[:limit] if limit is not None else all_atoms
    return {"case_id": case_id, "total": len(all_atoms), "returned": len(atoms), "atoms": atoms}


def evidence_support_extract_stub(case_id: str, case_dir: Path) -> dict:
    """Cheap, read-only summary for the executive payload - never generates."""
    report = _json_load(_hypothesis_path(case_dir))
    if not isinstance(report, dict):
        return {"status": "not_available", "path": relative_path(_hypothesis_path(case_dir))}
    staleness = evidence_support_staleness(case_dir)
    limitation_candidates = list(report.get("causal_limitations") or []) + list(report.get("temporal_limitations") or [])
    return {
        "status": "stale" if staleness["is_stale"] else "available",
        "report_available": True,
        "markup_status": "generated",
        "path": relative_path(_hypothesis_path(case_dir)),
        "hypothesis_id": report.get("hypothesis_id") or "not_available",
        "claim_evaluated": report.get("hypothesis_text") or "not_available",
        "global_support_level": report.get("global_support_level"),
        "hypothesis_count": 1,
        "supporting_findings": len(report.get("supporting_evidence_atoms") or []),
        "degraded_or_ambiguous_findings": len(report.get("partially_supporting_evidence_atoms") or []),
        "missing_or_not_evaluable_findings": len(report.get("missing_required_evidence") or []),
        "contradictions": len(report.get("contradictory_evidence_atoms") or []),
        "evidence_layers_contributing": [
            layer for layer, row in (report.get("layer_contribution_matrix") or {}).items()
            if (row.get("supports") or 0) or (row.get("partially_supports") or 0) or (row.get("contradicts") or 0)
        ],
        "main_supporting_evidence": list(report.get("supporting_evidence_atoms") or [])[:5],
        "main_contradicting_evidence": list(report.get("contradictory_evidence_atoms") or [])[:5],
        "final_interpretation": report.get("final_claimability_status") or "not_available",
        "main_limitation": limitation_candidates[0] if limitation_candidates else "not_available",
    }
