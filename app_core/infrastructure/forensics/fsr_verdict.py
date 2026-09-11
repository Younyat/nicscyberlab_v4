"""Computes the paper-faithful FSR/IR verdict for a single sealed case.

This is the single source of truth for the C1-C5 forensic-semantic
reproducibility invariants (paper Section 6.3 / Table 12), the E1-E4
evidence-quality criteria (Section 6.6 / Table 16), and the M1 infrastructure
reproducibility precondition gate (Table 11) -- shared between the live
dashboard (app_core/infrastructure/forge_vi_dashboard/endpoints.py) and the
durable per-case snapshot written at case-sealing time
(metadata/fsr/fsr_eval_<run_id>.json), so the two can never drift apart.

2026-09-09: written after finding metadata/fsr/ was reserved by
ensure_case_layout() (forensics_api.py) as a first-class case directory,
symmetric with metadata/ir/, but nothing ever wrote the verdict file into it
-- the sibling metadata/ir/ir_snapshot.json IS written automatically (from
_get_or_set_alert_ts), but the paired _save_fsr_eval_to_case() call was only
ever wired into the manual case-creation endpoint, never into the automated
Level B/C pipeline. This module is the fix: a shared, paper-faithful verdict
computed once real evidence exists, called from the automated pipeline right
after reconstruction attaches (see level_b_repetition_runner.py) and from the
live dashboard.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

SCHEMA = "nics_fsr_verdict_v1"

IR_GATE = [
    ("topology",       "Same intended topology instantiated",       "IT zone, OT zone, and conduits match the declared scenario."),
    ("target_roles",   "Expected forensic target roles present",     "Victim host, PLC, and SCADA/HMI roles are present in the effective inventory."),
    ("segmentation",   "Segmentation enforcement verified",          "Zone isolation and allowed conduits are confirmed from observed traffic."),
    ("monitoring",     "Monitoring liveness verified",               "IDS and alert export are available and observed to fire."),
    ("time_reference", "Time reference coherent",                    "Node clocks are synchronized within the declared threshold."),
    ("service_health", "Baseline service health",                    "PLC and SCADA/HMI are reachable before incident execution."),
]

C_INVARIANTS = [
    ("C1", "Network invariant",
     "The case preserves the network evidence required by the active acquisition profile around the incident window."),
    ("C2", "Alert invariant",
     "The case preserves the triggering alert in normalized form together with the original raw detector output."),
    ("C3", "Industrial invariant",
     "The case preserves a protocol-aware OT export capturing control-observable state."),
    ("C4", "Host invariant",
     "The case preserves host-origin artifacts (volatile memory and persistent disk state)."),
    ("C5", "Preservation invariant",
     "Manifest verification succeeds and the custody record is hash-chained and consistent with the manifest."),
]

E_CRITERIA = [
    ("E1", "Profile-conditioned completeness",
     "Primary artifacts required by the active profile are present for the network, memory, disk, and industrial layers."),
    ("E2", "Temporal coherence",
     "Node clocks are synchronized within the declared threshold, supporting UTC-based cross-source correlation."),
    ("E3", "Verifiable integrity",
     "Cryptographic digests verify and are consistent with the tamper-evident custody trace."),
    ("E4", "Primary/derived separation",
     "Derived analysis output is distinct from primary evidence and was generated only after the case was sealed."),
]


def _load(path: Path) -> dict | list | None:
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return None


def _parse_ts(s: str | None):
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    if len(s) > 19 and s[-5] in ("+", "-") and ":" not in s[-6:]:
        s = s[:-5] + s[-5:-2] + ":" + s[-2:]
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _wps_val(wps: dict, field: str):
    entry = (wps.get("pipeline_fields") or {}).get(field) or {}
    val = entry.get("value")
    status = entry.get("status", "")
    if val is None or status == "missing_from_existing_reports":
        return None
    return val


def compute_fsr_verdict(case_dir: Path) -> dict:
    """Real, evidence-derived verdict for one sealed case. Safe to call at
    any point in a case's life -- criteria whose supporting evidence does not
    exist yet (e.g. E4 before analysis has run) simply read as unsatisfied,
    not as an error; this function never raises for missing files."""
    case_dir = Path(case_dir)
    nts = _load(case_dir / "metadata" / "normalized_causal_timestamps.json") or {}
    fi = _load(case_dir / "metadata" / "forensic_intervention.json") or {}
    wps = _load(case_dir / "metadata" / "workflow_phase_summary.json") or {}
    manifest = _load(case_dir / "manifest.json") or {}
    trigger_binding = _load(case_dir / "metadata" / "trigger_alert_binding.json") or {}
    time_sync = _load(case_dir / "metadata" / "time_sync.json") or {}
    analysis_report = _load(case_dir / "analysis" / "forensic_analysis_report.json") or {}

    artifacts = manifest.get("artifacts") or []
    memory_gib = sum(a.get("size", 0) for a in artifacts if a.get("type") == "memory_lime") / (1024 ** 3)
    disk_gib = sum(a.get("size", 0) for a in artifacts if a.get("type") == "disk_raw") / (1024 ** 3)
    pcap_gib = sum(a.get("size", 0) for a in artifacts if a.get("type") == "network_pcap") / (1024 ** 3)
    preserved = fi.get("preserved_evidence_categories") or {}

    evidence_layers = {
        "memory":   preserved.get("memory", False) or memory_gib > 0,
        "network":  preserved.get("network_packet_context", False) or pcap_gib > 0,
        "disk":     preserved.get("disk", False) or disk_gib > 0,
        "ot":       bool(nts.get("ot_export_preserved_at_utc")),
        "manifest": (case_dir / "manifest.json").is_file(),
        "custody":  (case_dir / "chain_of_custody.log").is_file(),
        "analysis": (case_dir / "analysis" / "forensic_analysis_report.json").is_file(),
    }

    sha256_covered = sum(1 for a in artifacts if a.get("sha256"))
    integrity_ratio = round(sha256_covered / len(artifacts), 4) if artifacts else 0.0
    preservation_verified = evidence_layers["manifest"] and evidence_layers["custody"] and integrity_ratio >= 0.95

    c_checks = {
        "C1": evidence_layers["network"],
        "C2": bool(trigger_binding.get("trigger_alert_id")) and bool(trigger_binding.get("raw_json")),
        "C3": evidence_layers["ot"],
        "C4": evidence_layers["memory"] and evidence_layers["disk"],
        "C5": preservation_verified,
    }

    sealed_ts = _parse_ts(nts.get("case_sealed_at_utc"))
    generated_ts = _parse_ts(analysis_report.get("generated_at"))
    e_checks = {
        "E1": evidence_layers["network"] and evidence_layers["memory"] and evidence_layers["disk"] and evidence_layers["ot"],
        "E2": bool(time_sync.get("synchronized")),
        "E3": preservation_verified,
        "E4": evidence_layers["analysis"] and (sealed_ts is None or generated_ts is None or generated_ts > sealed_ts),
    }

    ir_gate = {
        "topology":       bool(_wps_val(wps, "same_topology_instantiated")),
        "target_roles":   bool(_wps_val(wps, "effective_inventory_recorded")),
        "segmentation":   bool(_wps_val(wps, "segmentation_verified")),
        "monitoring":     bool(_wps_val(wps, "sensor_liveness_verified")),
        "time_reference": bool(time_sync.get("synchronized")),
        "service_health": bool(_wps_val(wps, "plc_scada_reachable")),
    }

    return {
        "schema": SCHEMA,
        "generated_at_utc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "case_id": nts.get("case_id") or fi.get("case_id"),
        "c_invariants": {
            cid: {"name": name, "description": desc, "satisfied": bool(c_checks.get(cid))}
            for cid, name, desc in C_INVARIANTS
        },
        "e_criteria": {
            eid: {"name": name, "description": desc, "satisfied": bool(e_checks.get(eid))}
            for eid, name, desc in E_CRITERIA
        },
        "ir_gate": {
            key: {"name": name, "description": desc, "satisfied": bool(ir_gate.get(key))}
            for key, name, desc in IR_GATE
        },
        "evidence_layers": evidence_layers,
        "integrity_verification_ratio": integrity_ratio,
        "max_clock_offset_ms": time_sync.get("max_clock_offset_ms"),
    }


def write_fsr_verdict(case_dir: Path, run_id: str = "R1") -> Path | None:
    """Persists compute_fsr_verdict() into metadata/fsr/fsr_eval_<run_id>.json,
    mirroring the sibling metadata/ir/ir_snapshot.json write pattern. Returns
    the written path, or None on any failure (never raises -- this must not
    be able to break the automated acquisition/preservation pipeline that
    calls it)."""
    try:
        case_dir = Path(case_dir)
        verdict = compute_fsr_verdict(case_dir)
        out_dir = case_dir / "metadata" / "fsr"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"fsr_eval_{run_id}.json"
        tmp_path = out_path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
        tmp_path.replace(out_path)
        return out_path
    except Exception:
        return None
