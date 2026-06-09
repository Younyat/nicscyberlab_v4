#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
echo "ATT&CK PROFILE: T1082 - System Information Discovery"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "uname -a; hostnamectl 2>/dev/null || true; uptime"
echo "[SUCCESS] Read-only system information discovery completed"
