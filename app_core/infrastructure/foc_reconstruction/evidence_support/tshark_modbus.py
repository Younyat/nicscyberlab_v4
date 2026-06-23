from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path

_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "mbtcp.trans_id",
    "mbtcp.unit_id",
    "modbus.func_code",
    "modbus.reference_num",
    "modbus.write_reference_num",
    "modbus.regval_uint16",
]

# Modbus write function codes per the standard table:
# 5=WRITE_SINGLE_COIL, 6=WRITE_SINGLE_REGISTER, 15=WRITE_MULTIPLE_COILS,
# 16=WRITE_MULTIPLE_REGISTERS.
_WRITE_FUNCTION_CODES = {"5", "6", "15", "16"}


def extract_modbus_fields(pcap_path: Path, case_dir: Path, timeout_seconds: int = 30) -> dict:
    """Read-only tshark subprocess wrapper over one already-preserved pcap.

    Never re-runs capture, never modifies the pcap. Never raises on tool
    failure - failures are surfaced via the "error" key so callers can mark
    the corresponding atom as not_evaluable instead of crashing the triage job.
    """
    try:
        resolved_pcap = pcap_path.resolve()
        resolved_case_dir = case_dir.resolve()
        resolved_pcap.relative_to(resolved_case_dir)
    except Exception:
        return {"error": "pcap_path_outside_case_dir", "pcap": str(pcap_path)}

    if not resolved_pcap.is_file():
        return {"error": "pcap_not_found", "pcap": str(pcap_path)}

    argv = ["tshark", "-r", str(resolved_pcap), "-Y", "modbus", "-T", "fields"]
    for field in _FIELDS:
        argv.extend(["-e", field])

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            cwd=str(resolved_case_dir),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "pcap": str(pcap_path)}
    except FileNotFoundError:
        return {"error": "tshark_not_available", "pcap": str(pcap_path)}
    except Exception as exc:
        return {"error": f"tshark_invocation_failed:{exc}", "pcap": str(pcap_path)}

    if result.returncode != 0:
        return {"error": "tshark_nonzero_exit", "pcap": str(pcap_path), "stderr": (result.stderr or "")[:500]}

    function_codes: Counter = Counter()
    write_function_count = 0
    frame_count = 0
    conversations: set[tuple[str, str]] = set()
    first_timestamp: str | None = None
    last_timestamp: str | None = None

    for line in (result.stdout or "").splitlines():
        if not line.strip():
            continue
        cols = line.split("\t")
        cols = cols + [""] * (len(_FIELDS) - len(cols))
        ts, src_ip, dst_ip, _trans_id, _unit_id, func_code, _ref_num, _write_ref_num, _regval = cols[: len(_FIELDS)]
        frame_count += 1
        if ts:
            first_timestamp = first_timestamp or ts
            last_timestamp = ts
        if src_ip and dst_ip:
            conversations.add((src_ip, dst_ip))
        if func_code:
            function_codes[func_code] += 1
            if func_code in _WRITE_FUNCTION_CODES:
                write_function_count += 1

    return {
        "error": None,
        "pcap": str(pcap_path),
        "modbus_frame_count": frame_count,
        "function_codes": dict(function_codes),
        "write_function_count": write_function_count,
        "conversations": [{"src_ip": s, "dst_ip": d} for s, d in sorted(conversations)],
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
    }
