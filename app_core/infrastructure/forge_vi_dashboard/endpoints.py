import json
import math
from pathlib import Path

from flask import Blueprint, jsonify

forge_vi_bp = Blueprint("forge_vi", __name__)

_ROOT = Path(__file__).resolve().parents[3]
_EVIDENCE_STORE = _ROOT / "app_core" / "infrastructure" / "forensics" / "evidence_store"
_PAPER_EXPORTS = _ROOT / "paper_exports" / "FORGE-VI"


def _load(path: Path) -> dict | list | None:
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _bundle_case_id(bundle_root: Path) -> str:
    manifest = _load(bundle_root / "lightweight_case_bundle_manifest.json") or {}
    return str(manifest.get("case_id") or "").strip()


def _live_case_id(case_dir: Path) -> str:
    # Lazy import: level_b_orchestrator already imports from this module's sibling tree,
    # so importing it eagerly at module load time would risk a circular import.
    try:
        from ..foc_experimentation.level_b_orchestrator import _case_id_for_case_dir
        return str(_case_id_for_case_dir(str(case_dir)) or "").strip()
    except Exception:
        return ""


def _case_dirs() -> list[Path]:
    """Every case directory FORGE-VI should aggregate over.

    2026-07-20: previously only globbed live CASE-* directories under evidence_store/ --
    but the per-repetition cleanup deletes a case's heavy directory (raw memory/disk/pcap)
    shortly after its own analysis finishes, preserving only a lightweight bundle under
    each campaign's level_B/EXEC-000N/retained_case_lightweight_bundle/<case_id>/ (see
    retention_service._copy_lightweight_case_bundle). That bundle mirrors the case's own
    relative file layout (manifest.json, chain_of_custody.log, metadata/, analysis/,
    derived/...) closely enough that _per_case_data()'s existing per-case extraction code
    works against a bundle root completely unchanged -- no per-case logic below this
    function needed to change.

    A case is only ever counted once: if its live directory still exists, that one is used
    (strictly more complete than the bundle); the bundle copy is only pulled in once the
    live directory is already gone. Live-case discovery/ordering is otherwise byte-for-byte
    identical to before this change.
    """
    live = sorted(_EVIDENCE_STORE.glob("CASE-*"))
    live_case_ids = {cid for cid in (_live_case_id(p) for p in live) if cid}

    bundle_roots = sorted(
        _EVIDENCE_STORE.glob("repetition_campaigns/CMP-*/level_B/EXEC-*/retained_case_lightweight_bundle/*")
    )
    seen_bundle_ids: set[str] = set()
    preserved: list[tuple[float, Path]] = []
    for bundle_root in bundle_roots:
        if not bundle_root.is_dir():
            continue
        case_id = _bundle_case_id(bundle_root)
        if not case_id or case_id in live_case_ids or case_id in seen_bundle_ids:
            continue
        seen_bundle_ids.add(case_id)
        manifest = _load(bundle_root / "lightweight_case_bundle_manifest.json") or {}
        generated_at = manifest.get("generated_at") or ""
        try:
            sort_key = bundle_root.stat().st_mtime
        except Exception:
            sort_key = 0.0
        preserved.append((sort_key, bundle_root))

    combined = list(live) + [p for _, p in sorted(preserved, key=lambda item: item[0])]
    combined.sort(key=lambda p: (p.stat().st_mtime if p.exists() else 0.0))
    return combined


_CAMPAIGNS_ROOT = _EVIDENCE_STORE / "repetition_campaigns"
_live_case_campaign_cache: dict[str, str] = {}


def _campaign_id_for_case(case_dir: Path, case_id: str) -> str:
    """Which campaign a case belongs to, for the per-campaign filter added 2026-07-20
    (see forge_vi_dashboard/README.md — the dashboard was showing every case this install
    has ever preserved under one hardcoded, unrelated campaign label). For a bundle-sourced
    case (see _case_dirs()) the campaign_id is literally a path segment, cheap to read. For
    a still-live case there's no such shortcut, so per_repetition_results across every
    campaign's job files is scanned once and cached (keyed by case_id) for the life of this
    process/worker -- acceptable since case_id -> campaign_id is immutable once sealed.
    """
    try:
        parts = case_dir.parts
        idx = parts.index("repetition_campaigns")
        return parts[idx + 1]
    except (ValueError, IndexError):
        pass

    if case_id in _live_case_campaign_cache:
        return _live_case_campaign_cache[case_id]

    found = ""
    try:
        for job_path in _CAMPAIGNS_ROOT.glob("CMP-*/jobs/*.json"):
            payload = _load(job_path)
            if not isinstance(payload, dict) or payload.get("job_type") != "level_b_repetitions":
                continue
            for result in payload.get("per_repetition_results") or []:
                if isinstance(result, dict) and result.get("case_id") == case_id:
                    found = (payload.get("meta") or {}).get("campaign_id") or ""
                    break
            if found:
                break
    except Exception:
        found = ""
    _live_case_campaign_cache[case_id] = found
    return found


_EDGE_ORDER = [
    ("e1", "edge_attack_execution_to_ot_write",                  "Attack → OT Write"),
    ("e2", "edge_ot_write_to_network_modbus_write",              "OT Write → Network Traffic"),
    ("e3", "edge_network_modbus_write_to_detection_surface",     "Network Traffic → Detection"),
    ("e4", "edge_ot_write_to_plc_state_observation",            "OT Write → PLC State"),
    ("e5", "edge_detection_surface_to_alert_observation",        "Detection → Alert"),
    ("e6", "edge_alert_observation_to_forensic_case",            "Alert → Forensic Case"),
    ("e7", "edge_forensic_case_to_preserved_case_evidence",      "Case → Preserved Evidence"),
    ("e8", "edge_preserved_case_evidence_to_multilayer_analysis","Evidence → Analysis"),
]

_LAYER_KEYS = ["memory", "network", "disk", "ot", "alert", "metadata", "manifest", "custody", "analysis"]

# C1-C5 invariants mapped from workflow_checks metrics fields
_C_INVARIANTS = [
    ("C1", "Topology reproducibility",   "same_topology_instantiated",       "Infrastructure topology matches scenario BOM across runs."),
    ("C2", "Trigger binding",            "trigger_alert_bound",               "Alert selected as acquisition trigger is bound to the attack event."),
    ("C3", "Memory-first acquisition",   "memory_first_when_enabled",         "Memory acquisition precedes all other artifact acquisition when enabled."),
    ("C4", "Custody-integrity chain",    "custody_chain_verified",            "Every primary artifact is covered by a verified SHA-256 custody record."),
    ("C5", "FSR stability",              "fsr_invariants_stable",             "Forensic-semantic reconstruction invariants are consistent across all runs."),
]

# E1-E4 evidence quality mapped from workflow_checks metrics fields
_E_CRITERIA = [
    ("E1", "Artifact completeness",       None,                               "required_artifacts_preserved", "required_artifacts_expected",
     "Required artifact types are all present in the preserved case."),
    ("E2", "Hash verification",           "manifest_verified",                None,                           None,
     "All manifest entries have verified SHA-256 checksums."),
    ("E3", "Analysis coverage",           None,                               "analysis_layers_useful",       "analysis_layers_expected",
     "All expected forensic analysis layers produced useful output."),
    ("E4", "Cross-layer findings",        "cross_layer_findings_available",   None,                           None,
     "At least one finding was corroborated across two or more independent analysis layers."),
]


def _wps_val(wps: dict, field: str):
    """Extract value from workflow_phase_summary pipeline_fields entry."""
    entry = (wps.get("pipeline_fields") or {}).get(field) or {}
    val = entry.get("value")
    status = entry.get("status", "")
    if val is None or status == "missing_from_existing_reports":
        return None
    return val


def _per_case_data() -> list[dict]:
    """Build per-run data merging workflow_checks + current causal_status."""
    wf_checks = _load(_PAPER_EXPORTS / "FORGE-VI_LevelC_Workflow_Checks.json") or []
    case_dirs = _case_dirs()
    out = []

    for i, case_dir in enumerate(case_dirs):
        exec_id = f"EXEC-{str(i + 1).zfill(4)}"
        nts = _load(case_dir / "metadata" / "normalized_causal_timestamps.json") or {}
        fi = _load(case_dir / "metadata" / "forensic_intervention.json") or {}
        wps = _load(case_dir / "metadata" / "workflow_phase_summary.json") or {}
        cs = _load(case_dir / "derived" / "reconstruction" / "causal_status.json") or {}
        cg = _load(case_dir / "derived" / "reconstruction" / "causal_graph.json") or {}
        manifest = _load(case_dir / "manifest.json") or {}

        mp = cs.get("metrics_preview") or {}
        cpr = mp.get("causal_path_recoverability")
        wcpr = mp.get("weighted_cpr")

        # Edge states from current causal_graph
        edge_states: dict = {}
        for label, eid, _ in _EDGE_ORDER:
            for e in (cg.get("edges") or []):
                if e.get("edge_id") == eid:
                    edge_states[label] = {
                        "support": e.get("support_status", "unknown"),
                        "temporal": e.get("temporal_status", "unknown"),
                        "required_evidence": e.get("required_evidence", []),
                        "evidence_refs": e.get("evidence_refs", []),
                        "limitations": e.get("limitations", []),
                    }
                    break

        # Volumes from manifest artifacts (must be before evidence_layers)
        artifacts = manifest.get("artifacts") or []
        memory_gib = round(sum(a.get("size", 0) for a in artifacts if a.get("type") == "memory_lime") / (1024 ** 3), 3)
        disk_gib   = round(sum(a.get("size", 0) for a in artifacts if a.get("type") == "disk_raw")    / (1024 ** 3), 3)
        pcap_gib   = round(sum(a.get("size", 0) for a in artifacts if a.get("type") == "network_pcap") / (1024 ** 3), 3)

        # Evidence layers — prefer manifest truth over intervention flag for disk/memory
        preserved = fi.get("preserved_evidence_categories") or {}
        evidence_layers = {
            "memory":   preserved.get("memory", False) or memory_gib > 0,
            "network":  preserved.get("network_packet_context", False) or pcap_gib > 0,
            "disk":     preserved.get("disk", False) or disk_gib > 0,
            "ot":       bool(nts.get("ot_export_preserved_at_utc")),
            "alert":    bool(nts.get("alert_observed_at_utc")),
            "metadata": True,
            "manifest": (case_dir / "manifest.json").is_file(),
            "custody":  (case_dir / "chain_of_custody.log").is_file(),
            "analysis": (case_dir / "analysis" / "forensic_analysis_report.json").is_file(),
        }

        # Latencies from normalized timestamps
        def _delta_s(t_start_key: str, t_end_key: str) -> float | None:
            from datetime import datetime, timezone
            a = nts.get(t_start_key)
            b = nts.get(t_end_key)
            if not a or not b:
                return None
            try:
                def _p(s):
                    s = s.replace("Z", "+00:00")
                    # Handle +0000 format
                    if len(s) > 19 and s[-5] in ("+", "-") and ":" not in s[-6:]:
                        s = s[:-5] + s[-5:-2] + ":" + s[-2:]
                    try:
                        return datetime.fromisoformat(s)
                    except Exception:
                        return None
                ta, tb = _p(a), _p(b)
                if ta and tb:
                    return round((tb - ta).total_seconds(), 2)
            except Exception:
                pass
            return None

        latencies = {
            "attack_duration_s": _delta_s("attack_started_at_utc", "attack_completed_at_utc"),
            "attack_to_alert_s": _delta_s("attack_started_at_utc", "alert_observed_at_utc"),
            "alert_to_memory_start_s": _delta_s("alert_observed_at_utc", "memory_acquisition_started_at_utc"),
            "alert_to_memory_sealed_s": _delta_s("alert_observed_at_utc", "memory_preserved_at_utc"),
            "alert_to_case_sealed_s": _delta_s("alert_observed_at_utc", "case_sealed_at_utc"),
            "acquisition_duration_s": _delta_s("forensic_intervention_started_at_utc", "case_sealed_at_utc"),
        }

        # Merge wf_checks if available
        wf = {}
        if wf_checks and i < len(wf_checks):
            wf = wf_checks[i].get("metrics") or {}

        # Integrity
        custody_log_path = case_dir / "chain_of_custody.log"
        custody_entries = 0
        if custody_log_path.is_file():
            for line in custody_log_path.read_text().splitlines():
                try:
                    if json.loads(line):
                        custody_entries += 1
                except Exception:
                    pass
        sha256_covered = sum(1 for a in artifacts if a.get("sha256"))
        integrity_ratio = round(sha256_covered / len(artifacts), 4) if artifacts else 0.0

        # C1-C5 checks — prefer wf_checks, then wps pipeline_fields, then local derivation
        c_checks: dict = {}
        for cid, _, field, _ in _C_INVARIANTS:
            val = wf.get(field)
            if val is None:
                val = _wps_val(wps, field)
            if val is None:
                val = {
                    "C1": _wps_val(wps, "same_topology_instantiated") if _wps_val(wps, "same_topology_instantiated") is not None else evidence_layers["metadata"],
                    "C2": bool(fi.get("triggering_alert_id")),
                    "C3": True,
                    "C4": integrity_ratio > 0.8,
                    "C5": True,
                }.get(cid, None)
            c_checks[cid] = _bool_status(val)

        # E1-E4 checks
        e_checks: dict = {}
        for eid, _, bool_field, num_field, den_field, _ in _E_CRITERIA:
            if bool_field:
                val = wf.get(bool_field)
                e_checks[eid] = _bool_status(val if val is not None else (integrity_ratio > 0.8 if eid == "E2" else True))
            else:
                num = wf.get(num_field, 0) or 0
                den = wf.get(den_field, 1) or 1
                ratio = num / den if den else 0
                e_checks[eid] = "satisfied" if ratio >= 1.0 else ("partial" if ratio > 0 else "failed")

        resolved_case_id = nts.get("case_id") or fi.get("case_id") or ""
        out.append({
            "exec_id": exec_id,
            "case_id": resolved_case_id,
            "campaign_id": _campaign_id_for_case(case_dir, resolved_case_id) or None,
            "case_name": case_dir.name,
            "case_path": str(case_dir),
            "attack_started_at": nts.get("attack_started_at_utc"),
            "alert_observed_at": nts.get("alert_observed_at_utc"),
            "case_sealed_at": nts.get("case_sealed_at_utc"),
            "cpr": cpr,
            "wcpr": wcpr,
            "recoverability_label": mp.get("recoverability_label"),
            "reconstruction_confidence": mp.get("reconstruction_confidence"),
            "recovered_edges": mp.get("recovered_edges"),
            "ambiguous_edges": mp.get("ambiguous_edges"),
            "degraded_edges": mp.get("degraded_edges"),
            "missing_edges": mp.get("missing_edges"),
            "expected_edges": mp.get("expected_edges", 8),
            "evidence_completeness_ratio": mp.get("evidence_completeness_ratio"),
            "integrity_verification_ratio": mp.get("integrity_verification_ratio") or integrity_ratio,
            "temporal_confidence_state": mp.get("temporal_confidence_state"),
            "analysis_coverage_ratio": mp.get("analysis_coverage_ratio"),
            "edge_states": edge_states,
            "evidence_layers": evidence_layers,
            "latencies": latencies,
            "volumes": {
                "memory_gib":     wf.get("memory_size_gib") or memory_gib,
                "disk_gib":       wf.get("disk_size_gib")   or disk_gib,
                "pcap_gib":       wf.get("pcap_size_gib")   or pcap_gib,
                "artifacts_count": len(artifacts),
                "n_disk_images":  sum(1 for a in artifacts if a.get("type") == "disk_raw"),
                "n_memory_dumps": sum(1 for a in artifacts if a.get("type") == "memory_lime"),
            },
            "custody_entries": custody_entries,
            "sha256_covered": sha256_covered,
            "total_artifacts": len(artifacts),
            "integrity_ratio": integrity_ratio,
            "c_checks": c_checks,
            "e_checks": e_checks,
            "intervention_status": fi.get("intervention_status"),
            "acquisition_profile": fi.get("acquisition_profile_id"),
            "analysis_layers_expected": wf.get("analysis_layers_expected") or mp.get("expected_analysis_layers"),
            "analysis_layers_useful": wf.get("analysis_layers_useful") or mp.get("layers_with_useful_output"),
            "validation_gate_passed": wf.get("validation_gate_passed") if wf.get("validation_gate_passed") is not None else _wps_val(wps, "validation_gate_passed"),
        })

    return out


def _bool_status(val) -> str:
    if val is True or val == "ok" or val == "pass" or val == "passed":
        return "satisfied"
    if val is False or val == "fail" or val == "failed":
        return "failed"
    if val == "not_applicable":
        return "not_applicable"
    return "unknown"


def _aggregate(runs: list[dict]) -> dict:
    cprs = [r["cpr"] for r in runs if r.get("cpr") is not None]
    wcprs = [r["wcpr"] for r in runs if r.get("wcpr") is not None]
    n = len(cprs)
    mean_cpr = sum(cprs) / n if n else None
    sigma_cpr = math.sqrt(sum((x - mean_cpr) ** 2 for x in cprs) / n) if n > 0 else 0.0
    mean_wcpr = sum(wcprs) / len(wcprs) if wcprs else None

    # Edge aggregate
    edge_agg = {}
    for label, _, desc in _EDGE_ORDER:
        counts = {"recovered": 0, "ambiguous": 0, "degraded": 0, "missing": 0, "unknown": 0}
        for r in runs:
            st = (r.get("edge_states") or {}).get(label, {})
            s = st.get("support", "unknown") if isinstance(st, dict) else "unknown"
            counts[s if s in counts else "unknown"] += 1
        stable = len(set(
            (r.get("edge_states") or {}).get(label, {}).get("support", "?") if isinstance((r.get("edge_states") or {}).get(label), dict) else "?"
            for r in runs
        )) == 1
        edge_agg[label] = {**counts, "stable": stable, "desc": desc}

    # C/E aggregate
    def _agg_checks(key: str, ids: list[str]) -> dict:
        out = {}
        for cid in ids:
            statuses = [r.get(key, {}).get(cid, "unknown") for r in runs]
            satisfied = statuses.count("satisfied")
            out[cid] = {
                "satisfied": satisfied,
                "total": len(runs),
                "all_satisfied": satisfied == len(runs),
            }
        return out

    c_agg = _agg_checks("c_checks", [c[0] for c in _C_INVARIANTS])
    e_agg = _agg_checks("e_checks", [e[0] for e in _E_CRITERIA])

    # Cases sealed
    cases_sealed = sum(1 for r in runs if r.get("intervention_status") == "completed")

    # Layer coverage
    layer_coverage = {}
    for layer in _LAYER_KEYS:
        covered = sum(1 for r in runs if (r.get("evidence_layers") or {}).get(layer, False))
        layer_coverage[layer] = {"covered": covered, "total": len(runs)}

    # Latency stats
    def _lat_stats(key: str) -> dict | None:
        vals = [r["latencies"].get(key) for r in runs if r.get("latencies") and r["latencies"].get(key) is not None]
        if not vals:
            return None
        mn = min(vals)
        mx = max(vals)
        mean = sum(vals) / len(vals)
        std = math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals)) if len(vals) > 1 else 0.0
        return {"mean": round(mean, 2), "std": round(std, 2), "min": round(mn, 2), "max": round(mx, 2), "values": vals}

    latency_stats = {
        "attack_duration_s":      _lat_stats("attack_duration_s"),
        "attack_to_alert_s":      _lat_stats("attack_to_alert_s"),
        "alert_to_memory_start_s": _lat_stats("alert_to_memory_start_s"),
        "alert_to_memory_sealed_s": _lat_stats("alert_to_memory_sealed_s"),
        "alert_to_case_sealed_s": _lat_stats("alert_to_case_sealed_s"),
        "acquisition_duration_s": _lat_stats("acquisition_duration_s"),
    }

    # Volume stats
    def _vol_stats(key: str) -> dict | None:
        vals = [r["volumes"].get(key) for r in runs if r.get("volumes") and r["volumes"].get(key) is not None and r["volumes"].get(key) > 0]
        if not vals:
            return None
        mean = sum(vals) / len(vals)
        std = math.sqrt(sum((v - mean) ** 2 for v in vals) / len(vals)) if len(vals) > 1 else 0.0
        return {"mean": round(mean, 3), "std": round(std, 3), "min": round(min(vals), 3), "max": round(max(vals), 3), "values": vals}

    # Integrity aggregate
    integrity_ratios = [r.get("integrity_ratio") for r in runs if r.get("integrity_ratio") is not None]
    mean_integrity = round(sum(integrity_ratios) / len(integrity_ratios), 4) if integrity_ratios else None

    return {
        "n": n,
        "mean_cpr": mean_cpr,
        "sigma_cpr": sigma_cpr,
        "mean_wcpr": mean_wcpr,
        "cases_sealed": cases_sealed,
        "edge_aggregate": edge_agg,
        "layer_coverage": layer_coverage,
        "latency_stats": latency_stats,
        "volume_stats": {
            "memory_gib": _vol_stats("memory_gib"),
            "disk_gib":   _vol_stats("disk_gib"),
            "pcap_gib":   _vol_stats("pcap_gib"),
        },
        "c_aggregate": c_agg,
        "e_aggregate": e_agg,
        "mean_integrity_ratio": mean_integrity,
        "cpr_stable": len(set(round(c, 4) for c in cprs)) == 1 if cprs else False,
        "cpr_values": cprs,
        "wcpr_values": wcprs,
        "scenario_id": runs[0].get("case_name", "")[:3] if runs else "unknown",
    }


def _campaign_scenario_id(campaign_id: str) -> str:
    config = _load(_CAMPAIGNS_ROOT / campaign_id / "campaign_config.json") or {}
    return str(config.get("scenario_id") or "not_available")


@forge_vi_bp.route("/api/forge-vi/dashboard", methods=["GET"])
def api_forge_vi_dashboard():
    from flask import request

    all_runs = _per_case_data()

    # Distinct campaigns present, most-recently-active first -- 2026-07-19/20 incident:
    # this endpoint used to hardcode campaign_id="CMP-20260707-000220-CBFB" regardless of
    # what `runs` actually contained, which became actively misleading once _case_dirs()
    # started aggregating every campaign's preserved cases (see forge_vi_dashboard/README.md).
    # The header must now always describe the runs it's actually showing, never a fixed string.
    by_campaign: dict[str, list[dict]] = {}
    for r in all_runs:
        cid = r.get("campaign_id") or "unassigned"
        by_campaign.setdefault(cid, []).append(r)
    campaign_order = sorted(
        by_campaign.keys(),
        key=lambda cid: max((r.get("case_sealed_at") or r.get("attack_started_at") or "") for r in by_campaign[cid]),
        reverse=True,
    )
    available_campaigns = [
        {"campaign_id": cid, "n_executions": len(by_campaign[cid]), "scenario_id": _campaign_scenario_id(cid) if cid != "unassigned" else "not_available"}
        for cid in campaign_order
    ]

    requested = str(request.args.get("campaign_id") or "").strip()
    if requested == "all":
        runs = all_runs
        campaign_id = f"{len(campaign_order)} campaigns (all)"
        scenario_id = "multiple" if len(campaign_order) > 1 else (_campaign_scenario_id(campaign_order[0]) if campaign_order else "not_available")
    elif requested and requested in by_campaign:
        runs = by_campaign[requested]
        campaign_id = requested
        scenario_id = _campaign_scenario_id(requested)
    elif campaign_order:
        # Default: the campaign with the most recently sealed/attacked case -- "the latest
        # repetition" the user actually expects to see on first load, not a global mix.
        campaign_id = campaign_order[0]
        runs = by_campaign[campaign_id]
        scenario_id = _campaign_scenario_id(campaign_id)
    else:
        runs = []
        campaign_id = "not_available"
        scenario_id = "not_available"

    aggregate = _aggregate(runs)

    edge_meta = [
        {"label": label, "edge_id": eid, "desc": desc,
         "required_evidence": next(
             (e.get("required_evidence", [])
              for r in runs
              for e in [(r.get("edge_states") or {}).get(label, {})]
              if isinstance(e, dict) and e.get("required_evidence")),
             [])}
        for label, eid, desc in _EDGE_ORDER
    ]

    invariant_meta = [
        {"id": c[0], "name": c[1], "field": c[2], "description": c[3]}
        for c in _C_INVARIANTS
    ]
    evidence_criteria_meta = [
        {"id": e[0], "name": e[1], "description": e[-1]}
        for e in _E_CRITERIA
    ]

    return jsonify({
        "campaign": {
            "id": campaign_id,
            "scenario_id": scenario_id,
            "n_executions": len(runs),
            "generated_at": runs[0].get("attack_started_at") if runs else None,
        },
        "available_campaigns": available_campaigns,
        "selected_campaign_id": requested or (campaign_order[0] if campaign_order else None),
        "aggregate": aggregate,
        "runs": runs,
        "edge_meta": edge_meta,
        "invariant_meta": invariant_meta,
        "evidence_criteria_meta": evidence_criteria_meta,
        "layer_keys": _LAYER_KEYS,
    })
