#!/usr/bin/env python3
import subprocess
import pathlib
import json
import re

def extract_modbus_frames(case_path: pathlib.Path) -> list:
    """
    Extracts Modbus/TCP frames from PCAPs using tshark.
    """
    network_dir = case_path / "network"
    frames = []

    if not network_dir.exists():
        return frames

    for pcap in network_dir.glob("*.pcap"):
        cmd = [
            "tshark",
            "-r", str(pcap),
            "-Y", "modbus",
            "-T", "json"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            packets = json.loads(result.stdout)

            for pkt in packets:
                layers = pkt.get("_source", {}).get("layers", {})
                modbus = layers.get("modbus", {})

                frame = {
                    "timestamp": pkt["_source"]["layers"]["frame"]["frame.time_epoch"],
                    "function": int(modbus.get("modbus.func_code", 0)),
                    "unit_id": int(modbus.get("modbus.unit_id", 0)),
                    "source_ip": layers.get("ip", {}).get("ip.src"),
                    "destination_ip": layers.get("ip", {}).get("ip.dst")
                }
                frames.append(frame)

        except Exception:
            continue

    return frames
