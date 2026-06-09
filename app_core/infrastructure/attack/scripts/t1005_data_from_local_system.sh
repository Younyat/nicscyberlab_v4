#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"
echo "ATT&CK PROFILE: T1005 - Data from Local System"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "\
  mkdir -p '${LAB_ROOT}/sensitive_data' '${LAB_ROOT}/output' && \
  printf 'fake-secret-alpha\n' > '${LAB_ROOT}/sensitive_data/customer_notes.txt' && \
  printf 'fake-secret-beta\n' > '${LAB_ROOT}/sensitive_data/ot_setpoints.txt' && \
  cp '${LAB_ROOT}/sensitive_data/'*.txt '${LAB_ROOT}/output/' && \
  sha256sum '${LAB_ROOT}/output/'*.txt"
echo "[SUCCESS] Controlled local data collection completed"
