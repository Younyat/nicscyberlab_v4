# -*- coding: utf-8 -*-

import subprocess
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List


TSHARK_BIN = "/usr/bin/tshark"


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def run_cmd(cmd: List[str], timeout: int = 60):
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 999, "", str(e)


def analyze_single_pcap(pcap: Path) -> Dict[str, Any]:
    stats = {
        "pcap_file": pcap.name,
        "size_bytes": pcap.stat().st_size,
        "analysis_utc": utc_now_iso(),
    }

    # Packet count
    rc, out, _ = run_cmd(
        [TSHARK_BIN, "-r", str(pcap), "-q", "-z", "io,stat,0"]
    )
    stats["packet_statistics"] = out.strip() if rc == 0 else "unavailable"

    # Protocol hierarchy
    rc, out, _ = run_cmd(
        [TSHARK_BIN, "-r", str(pcap), "-q", "-z", "io,phs"]
    )
    stats["protocol_hierarchy"] = out.strip() if rc == 0 else "unavailable"

    # Modbus detection
    rc, out, _ = run_cmd(
        [TSHARK_BIN, "-r", str(pcap), "-Y", "modbus", "-T", "fields", "-e", "frame.time"]
    )
    stats["modbus_frames_detected"] = len(out.splitlines()) if rc == 0 else 0

    return stats


def analyze_pcap(network_dir: Path, metadata_dir: Path) -> Dict[str, Any]:
    pcaps = sorted(network_dir.glob("*.pcap"))

    results = {
        "pcap_count": len(pcaps),
        "files": [],
        "analysis_utc": utc_now_iso()
    }

    for pcap in pcaps:
        results["files"].append(analyze_single_pcap(pcap))

    out_file = metadata_dir / "network_analysis.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    return {
        "status": "completed",
        "output": str(out_file),
        "pcaps_analyzed": len(pcaps)
    }
