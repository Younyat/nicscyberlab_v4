#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
echo "ATT&CK PROFILE: T1016 - System Network Configuration Discovery"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "ip addr; echo '---'; ip route; echo '---'; cat /etc/resolv.conf"
echo "[SUCCESS] Read-only network configuration discovery completed"
