#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
echo "ATT&CK PROFILE: T1049 - System Network Connections Discovery"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null || true"
echo "[SUCCESS] Read-only network connection discovery completed"
