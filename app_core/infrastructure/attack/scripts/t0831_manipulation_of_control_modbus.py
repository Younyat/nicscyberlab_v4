#!/usr/bin/env python3
from pathlib import Path
import os
import subprocess
import sys

script_dir = Path(__file__).resolve().parent
target_ip = sys.argv[1] if len(sys.argv) > 1 else ""
target_user = sys.argv[2] if len(sys.argv) > 2 else "debian"
legacy = script_dir / "modbus_register_attack.sh"
os.execv(str(legacy), [str(legacy), target_ip, target_user])
