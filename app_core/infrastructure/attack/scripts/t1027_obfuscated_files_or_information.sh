#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"
echo "ATT&CK PROFILE: T1027 - Obfuscated Files or Information"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "\
  mkdir -p '${LAB_ROOT}/encoded' && \
  printf 'benign-lab-marker' | base64 > '${LAB_ROOT}/encoded/encoded_marker.b64' && \
  cat '${LAB_ROOT}/encoded/encoded_marker.b64' && \
  sha256sum '${LAB_ROOT}/encoded/encoded_marker.b64'"
echo "[SUCCESS] Controlled obfuscation marker completed"
