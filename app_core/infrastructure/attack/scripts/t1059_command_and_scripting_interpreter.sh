#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
echo "ATT&CK PROFILE: T1059 - Command and Scripting Interpreter"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "\
  echo '[BASH] harmless command pipeline'; \
  printf 'nics-cyberlab\n' | tr '[:lower:]' '[:upper:]'; \
  python3 -c \"print('python safe marker execution')\""
echo "[SUCCESS] Controlled command and scripting execution completed"
