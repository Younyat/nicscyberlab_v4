#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CANONICAL_SCRIPT="${SCRIPT_DIR}/app_core/infrastructure/forensics/scripts/time_sync_preflight.sh"

if [[ ! -f "$CANONICAL_SCRIPT" ]]; then
  echo "[ERROR] Canonical time synchronization script not found: $CANONICAL_SCRIPT" >&2
  exit 1
fi

exec bash "$CANONICAL_SCRIPT" "$@"
