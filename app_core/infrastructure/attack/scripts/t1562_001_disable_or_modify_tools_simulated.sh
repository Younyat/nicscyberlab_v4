#!/usr/bin/env bash
set -euo pipefail
TARGET_IP="${1:-}"
TARGET_USER="${2:-debian}"
SSH_KEY="${HOME}/.ssh/my_key"
LAB_ROOT="/tmp/nics_attack_lab"
echo "ATT&CK PROFILE: T1562.001 - Disable or Modify Tools (Simulated)"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${TARGET_USER}@${TARGET_IP}" "\
  mkdir -p '${LAB_ROOT}/tool_control' && \
  printf 'active\n' > '${LAB_ROOT}/tool_control/dummy_monitor.status' && \
  echo '[BEFORE]'; cat '${LAB_ROOT}/tool_control/dummy_monitor.status'; \
  printf 'stopped\n' > '${LAB_ROOT}/tool_control/dummy_monitor.status'; \
  echo '[AFTER]'; cat '${LAB_ROOT}/tool_control/dummy_monitor.status'"
echo "[SUCCESS] Simulated tool disable workflow completed"
