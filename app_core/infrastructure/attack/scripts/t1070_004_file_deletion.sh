#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"
echo "ATT&CK PROFILE: T1070.004 - File Deletion"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "\
  mkdir -p '${LAB_ROOT}/sensitive_data' && \
  printf 'to-delete\n' > '${LAB_ROOT}/sensitive_data/delete_me.txt' && \
  sha256sum '${LAB_ROOT}/sensitive_data/delete_me.txt' && \
  rm -f '${LAB_ROOT}/sensitive_data/delete_me.txt' && \
  echo '[OK] Lab file deleted'"
echo "[SUCCESS] Controlled file deletion completed"
