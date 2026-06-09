#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"

echo "==========================================="
echo "ATT&CK PROFILE: T1078 - Valid Accounts"
echo "TARGET: ${TARGET_USER}@${TARGET_IP}"
echo "MODE: SINGLE CONTROLLED SSH LOGIN"
echo "==========================================="

ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "echo '[REMOTE] valid lab login confirmed'; whoami; hostname"
echo "[SUCCESS] Controlled valid-account login completed"
