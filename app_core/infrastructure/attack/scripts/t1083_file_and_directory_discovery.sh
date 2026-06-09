#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"
echo "ATT&CK PROFILE: T1083 - File and Directory Discovery"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "mkdir -p '${LAB_ROOT}/sensitive_data'; find '${LAB_ROOT}' -maxdepth 3 -type f -o -type d | sort"
echo "[SUCCESS] Scoped file and directory discovery completed"
