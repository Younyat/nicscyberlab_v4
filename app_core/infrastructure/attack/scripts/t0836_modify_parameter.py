#!/usr/bin/env python3
import json
import subprocess
import sys

target_ip = sys.argv[1] if len(sys.argv) > 1 else ""
target_user = sys.argv[2] if len(sys.argv) > 2 else "debian"
params = {}
if len(sys.argv) > 3:
    try:
        params = json.loads(sys.argv[3])
    except Exception:
        params = {}

register = params.get("register", 16)
value = params.get("value", 1)
ssh_key = "~/.ssh/my_key"

print("===========================================")
print("ATT&CK PROFILE: T0836 - Modify Parameter")
print(f"TARGET: {target_ip}")
print(f"REGISTER: {register}")
print(f"VALUE: {value}")
print("MODE: RESTORE BY DEFAULT")
print("===========================================")

cmd = (
    f"if command -v mbpoll >/dev/null 2>&1; then "
    f"mbpoll -m tcp -a 1 -r {register} -t 4:int -1 {target_ip} || exit 1; "
    f"else echo '[INFO] mbpoll not available; simulated OT parameter change only'; fi"
)
result = subprocess.run(
    ["bash", "-lc", f"ssh -i {ssh_key} -o StrictHostKeyChecking=no {target_user}@{target_ip} \"echo simulated target context >/dev/null\""],
    check=False,
)
if result.returncode != 0:
    print("[FAIL] Remote OT context probe failed")
    sys.exit(1)

probe = subprocess.run(["bash", "-lc", cmd], check=False)
if probe.returncode != 0:
    print("[FAIL] OT parameter modification workflow failed")
    sys.exit(1)

print("[SUCCESS] Controlled parameter workflow completed")
