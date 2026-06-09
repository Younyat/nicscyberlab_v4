#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SUBNET="$(printf '%s' "${TARGET_IP}" | awk -F. '{print $1 "." $2 "." $3 ".0/24"}')"

echo "==========================================="
echo "ATT&CK PROFILE: T0846 - ICS Remote System Discovery"
echo "SCOPE: ${SUBNET}"
echo "MODE: READ-ONLY OT SUBNET DISCOVERY"
echo "==========================================="

if command -v nmap >/dev/null 2>&1; then
  nmap -sn "${SUBNET}" -oN /tmp/t0846_scan_output.txt
  cat /tmp/t0846_scan_output.txt
else
  echo "[INFO] nmap not found on attacker node; performing controlled TCP reachability probe"
  for port in 502 80 443 22; do
    timeout 2 bash -lc "echo > /dev/tcp/${TARGET_IP}/${port}" >/dev/null 2>&1 && echo "[DISCOVERED] ${TARGET_IP}:${port}" || true
  done
fi
echo "[SUCCESS] OT discovery workflow completed"
