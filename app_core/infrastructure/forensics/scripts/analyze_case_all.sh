#!/usr/bin/env bash
set -euo pipefail

# Uso:
#   analyze_case_all.sh <CASE_DIR> [SYMBOLS_DIR] [VOL_CMD]
#
# Descubre automáticamente:
#   - último disk RAW en <CASE_DIR>/disk/*.raw
#   - último dump LiME en <CASE_DIR>/memory/*.lime
#   - OT exports en <CASE_DIR>/industrial/ot_export_*.json (para timeline)
#
# Escribe outputs en:
#   <CASE_DIR>/analysis/...

CASE_DIR="${1:-}"
SYMBOLS_DIR="${2:-}"
VOL_CMD="${3:-vol}"

[[ -n "$CASE_DIR" ]] || { echo "Uso: $0 <CASE_DIR> [SYMBOLS_DIR] [VOL_CMD]"; exit 1; }
[[ -d "$CASE_DIR" ]] || { echo "No existe CASE_DIR: $CASE_DIR"; exit 1; }

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"

# Find latest artifacts
latest_disk="$(ls -1t "$CASE_DIR"/disk/*.raw 2>/dev/null | head -n1 || true)"
latest_mem="$(ls -1t "$CASE_DIR"/memory/*.lime 2>/dev/null | head -n1 || true)"

mkdir -p "$CASE_DIR/analysis"

echo "[*] CASE=$CASE_DIR"
echo "[*] latest_disk=${latest_disk:-none}"
echo "[*] latest_mem=${latest_mem:-none}"
echo "[*] symbols_dir=${SYMBOLS_DIR:-none}"

# Disk
if [[ -n "${latest_disk:-}" && -f "$latest_disk" ]]; then
  bash "$SCRIPTS_DIR/analyze_disk_tsk.sh" "$CASE_DIR" "$latest_disk"
else
  echo "[WARN] No disk RAW encontrado, omitiendo análisis de disco"
fi

# Memory (requiere symbols_dir)
if [[ -n "${latest_mem:-}" && -f "$latest_mem" ]]; then
  if [[ -n "${SYMBOLS_DIR:-}" && -d "$SYMBOLS_DIR" ]]; then
    bash "$SCRIPTS_DIR/analyze_memory_vol3.sh" "$CASE_DIR" "$latest_mem" "$SYMBOLS_DIR" "$VOL_CMD"
  else
    echo "[WARN] No symbols_dir válido; omitiendo Volatility3"
  fi
else
  echo "[WARN] No dump LiME encontrado, omitiendo análisis de memoria"
fi

# Unified timeline (events + artifacts + OT)
python3 "$SCRIPTS_DIR/build_case_timeline.py" "$CASE_DIR" >/dev/null 2>&1 || true

echo "$CASE_DIR/analysis"
