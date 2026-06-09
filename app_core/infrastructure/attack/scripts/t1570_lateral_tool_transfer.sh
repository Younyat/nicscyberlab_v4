#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"

echo "==========================================="
echo "ATT&CK PROFILE: T1570 - Lateral Tool Transfer"
echo "TARGET: ${TARGET_USER}@${TARGET_IP}"
echo "MODE: CONTROLLED INTERNAL MARKER MOVEMENT"
echo "==========================================="

ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "\
  mkdir -p '${LAB_ROOT}/tools' '${LAB_ROOT}/sensitive_data' && \
  printf 'lateral-movement marker\n' > '${LAB_ROOT}/sensitive_data/internal_marker.txt' && \
  cp '${LAB_ROOT}/sensitive_data/internal_marker.txt' '${LAB_ROOT}/tools/lateral_marker.txt' && \
  sha256sum '${LAB_ROOT}/sensitive_data/internal_marker.txt' '${LAB_ROOT}/tools/lateral_marker.txt'" || {
  echo "[FAIL] Internal marker movement failed"
  exit 1
}
echo "[SUCCESS] Controlled internal transfer completed"
