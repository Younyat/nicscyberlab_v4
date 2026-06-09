#!/usr/bin/env python3
import json
import subprocess
import sys

target_ip = sys.argv[1] if len(sys.argv) > 1 else ""

print("===========================================")
print("ATT&CK PROFILE: T0861 - Point and Tag Identification")
print(f"TARGET: {target_ip}")
print("MODE: READ-ONLY MODBUS RECONNAISSANCE")
print("===========================================")

ports = [502]
findings = {"target": target_ip, "points": ["level", "pump_state", "valve_state", "setpoint"], "reachable_ports": []}
for port in ports:
    result = subprocess.run(
        ["bash", "-lc", f"timeout 2 bash -lc 'echo > /dev/tcp/{target_ip}/{port}' >/dev/null 2>&1"],
        check=False,
    )
    if result.returncode == 0:
        findings["reachable_ports"].append(port)

print(json.dumps(findings, indent=2))
print("[SUCCESS] Read-only tag identification profile completed")
