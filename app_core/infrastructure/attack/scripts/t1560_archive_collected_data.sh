#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"
echo "ATT&CK PROFILE: T1560 - Archive Collected Data"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "\
  mkdir -p '${LAB_ROOT}/output' '${LAB_ROOT}/sensitive_data' && \
  tar -czf '${LAB_ROOT}/output/collected_data.tar.gz' -C '${LAB_ROOT}/sensitive_data' . && \
  sha256sum '${LAB_ROOT}/output/collected_data.tar.gz' && \
  ls -lh '${LAB_ROOT}/output/collected_data.tar.gz'"
echo "[SUCCESS] Controlled archive creation completed"
