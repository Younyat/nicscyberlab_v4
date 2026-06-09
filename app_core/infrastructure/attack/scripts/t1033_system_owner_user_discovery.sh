#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
echo "ATT&CK PROFILE: T1033 - System Owner/User Discovery"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "id; echo '---'; who; echo '---'; groups"
echo "[SUCCESS] Read-only user discovery completed"
