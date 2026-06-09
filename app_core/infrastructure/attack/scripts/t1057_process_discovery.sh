#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
echo "ATT&CK PROFILE: T1057 - Process Discovery"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "ps aux --sort=-%mem | head -n 20; echo '---'; systemctl list-units --type=service --state=running 2>/dev/null | head -n 20 || true"
echo "[SUCCESS] Read-only process discovery completed"
