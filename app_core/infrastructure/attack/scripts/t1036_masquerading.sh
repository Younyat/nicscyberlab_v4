#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"
echo "ATT&CK PROFILE: T1036 - Masquerading"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "\
  mkdir -p '${LAB_ROOT}/masquerade' && \
  printf 'benign marker\n' > '${LAB_ROOT}/masquerade/invoice_2026.pdf.txt' && \
  sha256sum '${LAB_ROOT}/masquerade/invoice_2026.pdf.txt' && \
  ls -l '${LAB_ROOT}/masquerade/invoice_2026.pdf.txt'"
echo "[SUCCESS] Controlled masquerading marker completed"
