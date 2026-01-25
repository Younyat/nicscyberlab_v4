#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
from pathlib import Path
from datetime import datetime, timezone

from analyzers.network_pcap_analyzer import analyze_pcap
from analyzers.system_snapshot_analyzer import analyze_system_snapshot
from analyzers.modbus_analyzer import analyze_modbus_snapshot


EVIDENCE_ROOT = (
    Path(__file__).resolve()
    .parent.parent
    / "collection_layer"
    / "evidence_store"
)


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def main(case_id: str):
    case_dir = EVIDENCE_ROOT / case_id
    if not case_dir.exists():
        print(f"[ERROR] Case not found: {case_dir}")
        sys.exit(1)

    metadata_dir = case_dir / "metadata"
    metadata_dir.mkdir(exist_ok=True)

    analysis_results = {
        "case_id": case_id,
        "analysis_started_utc": utc_now_iso(),
        "modules": {}
    }

    # -------- NETWORK ANALYSIS --------
    network_dir = case_dir / "network"
    if network_dir.exists():
        analysis_results["modules"]["network"] = analyze_pcap(
            network_dir, metadata_dir
        )

    # -------- SYSTEM ANALYSIS --------
    system_dir = case_dir / "system"
    if system_dir.exists():
        analysis_results["modules"]["system"] = analyze_system_snapshot(
            system_dir, metadata_dir
        )

    # -------- INDUSTRIAL ANALYSIS --------
    industrial_dir = case_dir / "industrial"
    if industrial_dir.exists():
        analysis_results["modules"]["industrial"] = analyze_modbus_snapshot(
            industrial_dir, metadata_dir
        )

    analysis_results["analysis_finished_utc"] = utc_now_iso()

    summary_path = metadata_dir / "analysis_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(analysis_results, f, indent=2)

    print("[OK] Forensic analysis completed")
    print(f"[OK] Summary written to {summary_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: forensic_analyzer.py CASE-ID")
        sys.exit(1)

    main(sys.argv[1])
