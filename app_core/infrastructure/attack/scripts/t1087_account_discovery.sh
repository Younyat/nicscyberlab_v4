#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
echo "ATT&CK PROFILE: T1087 - Account Discovery"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "cut -d: -f1 /etc/passwd | head -n 50"
echo "[SUCCESS] Read-only account discovery completed"
