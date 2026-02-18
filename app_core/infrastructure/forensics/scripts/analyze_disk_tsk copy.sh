#!/usr/bin/env bash
set -euo pipefail

# Uso:
#   analyze_disk_tsk.sh <CASE_DIR> <DISK_RAW_ABS_PATH>
#
# Salidas:
#   <CASE_DIR>/analysis/disk/tsk/...
#
# Requisitos host:
#   - Sleuth Kit (fls, mactime, istat, icat)
#   - (Opcional) bulk_extractor, yara, etc.

if [[ $# -lt 2 ]]; then
  echo "Uso: $0 <CASE_DIR> <DISK_RAW_ABS_PATH>"
  exit 1
fi

CASE_DIR="$1"
DISK="$2"

[[ -d "$CASE_DIR" ]] || { echo "No existe CASE_DIR: $CASE_DIR"; exit 1; }
[[ -f "$DISK" ]] || { echo "No existe DISK: $DISK"; exit 1; }

OUT="$CASE_DIR/analysis/disk/tsk"
mkdir -p "$OUT"

echo "[*] TSK analysis => $OUT"
echo "[*] disk=$DISK"

# 1) Identificar particiones
mmls "$DISK" > "$OUT/mmls.txt" 2> "$OUT/mmls.err" || true

# Intento simple: coger el primer "Linux" / "EFI" / "NTFS" con offset.
# Si no se detecta, se hace fls sin offset.
OFFSET=""
if grep -qE "^\s*[0-9]+:\s" "$OUT/mmls.txt"; then
  # Busca primera línea con "Linux" o "NTFS" o "EFI System" y extrae Start
  start="$(awk '
    $0 ~ /^[[:space:]]*[0-9]+:/ {
      if ($0 ~ /(Linux|NTFS|EFI System|FAT|ext4|ext3|ext2)/) {
        print $3; exit
      }
    }' "$OUT/mmls.txt" 2>/dev/null || true)"
  if [[ -n "${start:-}" ]]; then
    OFFSET="$start"
  fi
fi

echo "[*] Using OFFSET(sectors)=${OFFSET:-none}"

# 2) Bodyfile + mactime (timeline FS)
if [[ -n "${OFFSET:-}" ]]; then
  fls -r -m / -o "$OFFSET" "$DISK" > "$OUT/fls_recursive.txt" 2> "$OUT/fls_recursive.err" || true
  fls -r -m / -o "$OFFSET" -b "$OUT/bodyfile.txt" "$DISK" >/dev/null 2>&1 || true
else
  fls -r -m / "$DISK" > "$OUT/fls_recursive.txt" 2> "$OUT/fls_recursive.err" || true
  fls -r -m / -b "$OUT/bodyfile.txt" "$DISK" >/dev/null 2>&1 || true
fi

if [[ -f "$OUT/bodyfile.txt" ]]; then
  mactime -b "$OUT/bodyfile.txt" -d > "$OUT/mactime.csv" 2> "$OUT/mactime.err" || true
fi

# 3) Extra: strings rápidas (best-effort)
strings -a -n 8 "$DISK" | head -n 20000 > "$OUT/strings_head.txt" 2>/dev/null || true

echo "$OUT"
