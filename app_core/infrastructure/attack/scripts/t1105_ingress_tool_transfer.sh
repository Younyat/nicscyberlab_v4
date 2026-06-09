#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"
TARGET_DIR="${LAB_ROOT}/tools"
MARKER_FILE="/tmp/nics_ingress_marker.txt"

echo "==========================================="
echo "ATT&CK PROFILE: T1105 - Ingress Tool Transfer"
echo "TARGET: ${TARGET_USER}@${TARGET_IP}"
echo "MODE: CONTROLLED BENIGN MARKER TRANSFER"
echo "==========================================="

printf 'nics-lab benign transfer marker\n' > "${MARKER_FILE}"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "mkdir -p '${TARGET_DIR}'"
scp -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${MARKER_FILE}" "${TARGET_USER}@${TARGET_IP}:${TARGET_DIR}/ingress_marker.txt" >/tmp/nics_t1105_scp.log 2>&1 || {
  cat /tmp/nics_t1105_scp.log
  echo "[FAIL] Marker transfer failed"
  exit 1
}
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "mkdir -p '${TARGET_DIR}' && sha256sum '${TARGET_DIR}/ingress_marker.txt' || true"
echo "[SUCCESS] Benign marker file transferred to monitored lab directory"
