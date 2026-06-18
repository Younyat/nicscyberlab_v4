#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-ubuntu}"
REMOTE_DUMP="${3:-}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/my_key}"

if [[ -z "$TARGET_IP" ]]; then
  echo "ERROR: No target IP provided."
  echo "USAGE: $0 <target_ip> [ssh_user] [remote_dump_path]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_SCRIPT="$SCRIPT_DIR/pre_memory_cleanup_inside_node.sh"

if [[ ! -f "$REMOTE_SCRIPT" ]]; then
  echo "ERROR: Remote cleanup script not found: $REMOTE_SCRIPT"
  exit 1
fi

echo "==========================================="
echo "SAFE REMOTE DISK CLEANUP"
echo "==========================================="
echo "[TARGET] $TARGET_IP"
echo "[SSH USER] $SSH_USER"
echo "[REMOTE_DUMP] ${REMOTE_DUMP:-not_set}"
echo "==========================================="

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_IP" \
  "REMOTE_DUMP='${REMOTE_DUMP}' bash -s" < "$REMOTE_SCRIPT"
