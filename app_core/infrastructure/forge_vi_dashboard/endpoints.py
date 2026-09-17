import json
import math
from pathlib import Path

from flask import Blueprint, jsonify

from ..forensics.fsr_verdict import compute_fsr_verdict

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
    # 2026-07-24: only cache a REAL resolution, never the empty/"unassigned"
    # result. A case looked up while its Level B job hasn't finished writing
    # per_repetition_results yet (i.e. still mid-repetition) genuinely has no
    # campaign_id YET -- that's a temporary state, not the permanent one the
    # docstring above assumed ("immutable once sealed" is true of the real
    # answer, but caching a not-yet-known answer as if it were final is not
    # the same thing). Caching "" here meant a case that got looked up too
    # early stayed stuck showing "unassigned" in this worker process forever,
    # even minutes later once the real campaign_id was written -- confirmed
    # live: a fresh process resolved every one of 53 cases correctly, while
    # the already-running gunicorn worker (which had looked at least one of
    # them up while its repetition was still finishing) kept it cached empty.
    if found:
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

# M1 — the 6 named pre-run infrastructure-reproducibility preconditions,
# exactly as reported in the paper (Table 11).
_IR_GATE = [
    ("topology",       "Same intended topology instantiated",       "IT zone, OT zone, and conduits match the declared scenario."),
    ("target_roles",   "Expected forensic target roles present",     "Victim host, PLC, and SCADA/HMI roles are present in the effective inventory."),
    ("segmentation",   "Segmentation enforcement verified",          "Zone isolation and allowed conduits are confirmed from observed traffic."),
    ("monitoring",     "Monitoring liveness verified",               "IDS and alert export are available and observed to fire."),
    ("time_reference", "Time reference coherent",                    "Node clocks are synchronized within the declared threshold."),
    ("service_health", "Baseline service health",                    "PLC and SCADA/HMI are reachable before incident execution."),
]

# C1-C5 forensic-semantic reproducibility invariants, defined exactly as in
# the paper (Section 6.3 / Table 12) -- each is a case-recoverable statement
# about the preserved evidence, not a workflow-mechanism check.
_C_INVARIANTS = [
    ("C1", "Network invariant",     None,
     "The case preserves the network evidence required by the active acquisition profile around the incident window, "
     "temporally anchored to support network-layer correlation and packet-level observations."),
    ("C2", "Alert invariant",       None,
     "The case preserves the triggering alert in normalized form and preserves the corresponding original detector output for audit."),
    ("C3", "Industrial invariant",  None,
     "The case preserves a protocol-aware OT export that captures control-observable state required to interpret the incident at the industrial layer."),
    ("C4", "Host invariant",        None,
     "The case preserves the host artifacts (volatile memory and persistent disk state) enabled by the active acquisition profile, "
     "with timestamps and provenance sufficient for cross-layer correlation within the incident window."),
    ("C5", "Preservation invariant", None,
     "The case passes verifiable preservation controls: manifest verification succeeds and the custody record is hash-chained and consistent with the manifest."),
]

# E1-E4 evidence-quality criteria, defined exactly as in the paper
# (Section 6.6 / Table 16).
_E_CRITERIA = [
    ("E1", "Profile-conditioned completeness", None, None, None,
     "Presence of the primary artifacts required by the active profile for the network, volatile-memory, persistent-host, and industrial layers."),
    ("E2", "Temporal coherence",               None, None, None,
     "Ability to correlate alerts, network traces, and host/industrial artifacts under a common UTC reference, within the measured clock-offset budget."),
    ("E3", "Verifiable integrity",             None, None, None,
     "Successful verification of cryptographic digests and consistency with the tamper-evident custody trace."),
    ("E4", "Primary/derived separation",       None, None, None,
     "Derived artifacts are produced only after primary evidence is sealed, generated from copies, and remain distinct from primary evidence, with traceable tools, versions, and parameters."),
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
    # 2026-09-07: user asked why C5 ("FSR stability") and E3 ("Analysis
    # coverage") showed 0/10 for a real campaign whose own data looked fine
    # everywhere else -- traced to a real bug, not a real result. wf_checks
    # is a static, one-time paper export (FORGE-VI_LevelC_Workflow_Checks.json,
    # 103 entries, all from OLD runs of this scenario -- case_ids like
    # case-f9b84046, none of which belong to any current/future campaign)
    # and it was being merged into THIS campaign's per-case rows by raw list
    # POSITION (`wf_checks[i]`), not by case identity. Every C1-C5/E1-E4
    # check backed by a `wf` field was therefore reading an unrelated
    # historical case's value, not this campaign's own -- C1-C4/E1/E2/E4
    # happened to look right only because those specific fields are
    # constant `True`/full-ratio across all 103 stale entries; C5
    # (constant `False` in the stale file) and E3 (constant 12/14 ratio,
    # never reaching 1.0) were the only two whose constant stale value
    # exposed the mismatch. Fixed by keying the lookup on case_id instead of
    # position, so a real match only happens when the case is genuinely the
    # same one the export was built from (never true for a new campaign) --
    # and added real per-case fallbacks (already computed elsewhere in this
    # function for display purposes, just not wired into the actual
    # pass/fail computation) for the two ratio-based checks so an unmatched
    # case still gets evaluated from its own real data, not a bare 0/0 default.
    wf_checks_raw = _load(_PAPER_EXPORTS / "FORGE-VI_LevelC_Workflow_Checks.json") or []
    wf_checks_by_case = {
        entry.get("case_id"): (entry.get("metrics") or {})
        for entry in wf_checks_raw
        if entry.get("case_id")
    }

    # Per-case trigger_attempts_total, for the real M4 "recoverable trigger
    # retry/failure events" metric (paper Table 18) -- only ever recorded in
    # a Level B job's per_repetition_results, not copied into the lightweight
    # case bundle, so it is read once here by scanning campaign job files.
    trigger_attempts_by_case: dict[str, int] = {}
    try:
        for job_path in _CAMPAIGNS_ROOT.glob("CMP-*/jobs/level-b-repetitions-*.json"):
            payload = _load(job_path)
            if not isinstance(payload, dict):
                continue
            for result in payload.get("per_repetition_results") or []:
                if isinstance(result, dict) and result.get("case_id"):
                    trigger_attempts_by_case[result["case_id"]] = result.get("trigger_attempts_total") or 1
    except Exception:
        pass

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
        time_sync = _load(case_dir / "metadata" / "time_sync.json") or {}

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
                        # The specific, real sentence edge_evaluator._build_status_reason()
                        # already computes and persists per edge (e.g. "Required evidence
                        # was found, but the temporal order could not be resolved from
                        # preserved timestamps.") -- already used in the standalone
                        # narrative/forensic report, but this dashboard was dropping it
                        # and showing only the bare recovered/ambiguous/degraded/missing
                        # label with no investigated cause behind it.
                        "status_reason": e.get("status_reason"),
                    }
                    break

        # Volumes from manifest artifacts (must be before evidence_layers)
        artifacts = manifest.get("artifacts") or []
        memory_gib = round(sum(a.get("size", 0) for a in artifacts if a.get("type") == "memory_lime") / (1024 ** 3), 3)
        disk_gib   = round(sum(a.get("size", 0) for a in artifacts if a.get("type") == "disk_raw")    / (1024 ** 3), 3)
        pcap_gib   = round(sum(a.get("size", 0) for a in artifacts if a.get("type") == "network_pcap") / (1024 ** 3), 3)

        # Manifest sizes are recorded at acquisition time and kept for hash/provenance
        # verification even after retention policy purges the heavy binary (see
        # _case_dirs() docstring above: only a lightweight bundle survives per
        # repetition). Distinguish "recorded" from "bytes physically present here" so
        # the dashboard never implies GiB are retained in this case when only the
        # manifest + hash record is.
        def _bytes_retained(atype: str) -> bool:
            for a in artifacts:
                if a.get("type") == atype:
                    rel = a.get("rel_path")
                    if rel and (case_dir / rel).is_file():
                        return True
            return False

        memory_bytes_retained = _bytes_retained("memory_lime")
        disk_bytes_retained = _bytes_retained("disk_raw")
        pcap_bytes_retained = _bytes_retained("network_pcap")

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
            ta, tb = _parse_ts(nts.get(t_start_key)), _parse_ts(nts.get(t_end_key))
            if ta and tb:
                return round((tb - ta).total_seconds(), 2)
            return None

        latencies = {
            "attack_duration_s": _delta_s("attack_started_at_utc", "attack_completed_at_utc"),
            "attack_to_alert_s": _delta_s("attack_started_at_utc", "alert_observed_at_utc"),
            "alert_to_memory_start_s": _delta_s("alert_observed_at_utc", "memory_acquisition_started_at_utc"),
            "alert_to_memory_sealed_s": _delta_s("alert_observed_at_utc", "memory_preserved_at_utc"),
            "alert_to_case_sealed_s": _delta_s("alert_observed_at_utc", "case_sealed_at_utc"),
            "acquisition_duration_s": _delta_s("forensic_intervention_started_at_utc", "case_sealed_at_utc"),
        }

        # Merge wf_checks if available -- matched by case_id, never by list
        # position (see this function's 2026-09-07 note above for why).
        resolved_case_id = nts.get("case_id") or fi.get("case_id") or ""
        wf = wf_checks_by_case.get(resolved_case_id) or {}

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

        # C1-C5 / E1-E4 / IR-gate: computed by the single shared module also
        # used to persist metadata/fsr/fsr_eval_<run_id>.json at case-sealing
        # time (app_core/infrastructure/forensics/fsr_verdict.py), so the
        # live dashboard and the durable per-case record can never drift apart.
        verdict = compute_fsr_verdict(case_dir)
        c_checks = {cid: _bool_status(entry["satisfied"]) for cid, entry in verdict["c_invariants"].items()}
        e_checks = {eid: _bool_status(entry["satisfied"]) for eid, entry in verdict["e_criteria"].items()}
        ir_gate = {key: entry["satisfied"] for key, entry in verdict["ir_gate"].items()}
        trigger_attempts_total = trigger_attempts_by_case.get(resolved_case_id) or 1
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
                "memory_sizes_gib": sorted(
                    (round(a.get("size", 0) / (1024 ** 3), 3) for a in artifacts if a.get("type") == "memory_lime"),
                    reverse=True,
                ),
                "disk_sizes_gib": sorted(
                    (round(a.get("size", 0) / (1024 ** 3), 3) for a in artifacts if a.get("type") == "disk_raw"),
                    reverse=True,
                ),
                "memory_bytes_retained": memory_bytes_retained,
                "disk_bytes_retained": disk_bytes_retained,
                "pcap_bytes_retained": pcap_bytes_retained,
            },
            "custody_entries": custody_entries,
            "sha256_covered": sha256_covered,
            "total_artifacts": len(artifacts),
            "integrity_ratio": integrity_ratio,
            "c_checks": c_checks,
            "e_checks": e_checks,
            "intervention_status": fi.get("intervention_status"),
            "acquisition_profile": fi.get("acquisition_profile_id"),
            # 2026-09-07: prefer mp (causal_status.json's curated, real
            # analysis-domain list) over wf (the static export's inflated
            # count including two pipeline-bookkeeping "layers" -- see the
            # E3 note above) for the same reason.
            "analysis_layers_expected": mp.get("expected_analysis_layers") or wf.get("analysis_layers_expected"),
            "analysis_layers_useful": mp.get("layers_with_useful_output") or wf.get("analysis_layers_useful"),
            "validation_gate_passed": wf.get("validation_gate_passed") if wf.get("validation_gate_passed") is not None else _wps_val(wps, "validation_gate_passed"),
            # Paper Table 11: the 6 named pre-run IR preconditions (M1).
            "ir_gate": ir_gate,
            # Paper Table 18: recoverable trigger retry/failure events (M4).
            "trigger_attempts_total": trigger_attempts_total,
            "max_clock_offset_ms": time_sync.get("max_clock_offset_ms"),
        })

    return out


def _parse_ts(s: str | None):
    from datetime import datetime
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    if len(s) > 19 and s[-5] in ("+", "-") and ":" not in s[-6:]:
        s = s[:-5] + s[-5:-2] + ":" + s[-2:]
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _bool_status(val) -> str:
    if val is True or val == "ok" or val == "pass" or val == "passed":
        return "satisfied"
    if val is False or val == "fail" or val == "failed":
        return "failed"
    if val == "not_applicable":
        return "not_applicable"
    return "unknown"


def _sample_std(vals: list[float], mean: float) -> float:
    """Sample standard deviation (n-1 denominator) -- matches the convention
    used throughout the paper's own reported statistics (e.g. Table 14's
    CPR s=0.0395), so dashboard and paper numbers are directly comparable."""
    n = len(vals)
    if n < 2:
        return 0.0
    return math.sqrt(sum((v - mean) ** 2 for v in vals) / (n - 1))


def _aggregate(runs: list[dict]) -> dict:
    cprs = [r["cpr"] for r in runs if r.get("cpr") is not None]
    wcprs = [r["wcpr"] for r in runs if r.get("wcpr") is not None]
    n = len(cprs)
    mean_cpr = sum(cprs) / n if n else None
    sigma_cpr = _sample_std(cprs, mean_cpr) if n > 0 else 0.0
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
        std = _sample_std(vals, mean)
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
        std = _sample_std(vals, mean)
        return {"mean": round(mean, 3), "std": round(std, 3), "min": round(min(vals), 3), "max": round(max(vals), 3), "values": vals}

    # Integrity aggregate
    integrity_ratios = [r.get("integrity_ratio") for r in runs if r.get("integrity_ratio") is not None]
    mean_integrity = round(sum(integrity_ratios) / len(integrity_ratios), 4) if integrity_ratios else None

    # E2 clock-offset stats (paper Table 16: reported as a continuous
    # measurement, not a satisfied-count -- surfaced here the same way).
    offset_vals = [r.get("max_clock_offset_ms") for r in runs if r.get("max_clock_offset_ms") is not None]
    clock_offset_stats = None
    if offset_vals:
        mean_offset_s = (sum(offset_vals) / len(offset_vals)) / 1000.0
        std_offset_s = _sample_std(offset_vals, sum(offset_vals) / len(offset_vals)) / 1000.0
        clock_offset_stats = {"mean_s": round(mean_offset_s, 3), "std_s": round(std_offset_s, 3), "n": len(offset_vals)}

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
        "clock_offset_stats": clock_offset_stats,
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
        # 2026-07-23: "unassigned" is not a real campaign -- it's cases whose Level B job
        # hasn't finished storing per_repetition_results yet (see _campaign_id_for_case()),
        # which happens for every still-running repetition's just-sealed case. Left
        # unfiltered, a live 10-rep Level C run's freshly-sealed rep 9 case would outrank
        # the real campaign as "most recent" purely because its campaign lookup hasn't
        # resolved yet -- confirmed live (campaign showed "unassigned", n_executions: 1,
        # while the real campaign had 9). Same "skip the noisy synthetic bucket when
        # picking a default, but keep it selectable" principle already applied to Level A
        # nested campaigns in the Comparability View.
        default_campaign_id = next((cid for cid in campaign_order if cid != "unassigned"), campaign_order[0])
        campaign_id = default_campaign_id
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
    ir_gate_meta = [
        {"key": key, "name": name, "description": desc}
        for key, name, desc in _IR_GATE
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
        "ir_gate_meta": ir_gate_meta,
        "layer_keys": _LAYER_KEYS,
    })
