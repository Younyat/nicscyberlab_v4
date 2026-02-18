#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Script: analyze_disk_tsk.sh
# ==============================================================================

if [[ $# -lt 2 ]]; then
    echo "Uso: $0 <CASE_DIR> <DISK_RAW_ABS_PATH>"
    exit 1
fi

CASE_DIR="$1"
DISK="$2"

[[ -d "$CASE_DIR" ]] || { echo "ERROR: No existe CASE_DIR"; exit 1; }
[[ -f "$DISK" ]] || { echo "ERROR: No existe DISK"; exit 1; }

OUT="$CASE_DIR/analysis/disk/tsk"
mkdir -p "$OUT"

echo "[*] TSK Analysis Started"

# 1) mmls
mmls "$DISK" > "$OUT/mmls.txt" 2> "$OUT/mmls.err" || true

# 2) Detección de Offset
CANDIDATES=$(awk '$0 ~ /^[[:space:]]*[0-9]+:/ { s=$3; if (s ~ /^[0-9]+$/) print s }' "$OUT/mmls.txt" | sed 's/^0*//' | sort -n | uniq)

OFFSET=""
for off in $CANDIDATES; do
    [[ -z "$off" ]] && off=0
    if fsstat -o "$off" "$DISK" 2>/dev/null | grep -q "File System Type:"; then
        OFFSET="$off"
        FS_TYPE=$(fsstat -o "$off" "$DISK" 2>/dev/null | grep "File System Type:" | cut -d: -f2 | xargs)
        echo "[+] Detectado $FS_TYPE en offset: $OFFSET"
        break
    fi
done

# 3) Extracción de metadatos (FLS)
# EXPLICACIÓN DEL FIX:
# Para generar un bodyfile que mactime entienda, NO se usa "-b" (que es para sector size).
# Se usa "-m <punto_de_montaje>".
# Si usas "-m /", fls imprimirá el formato bodyfile por stdout.

echo "[*] Extracting file system metadata..."

if [[ -n "$OFFSET" ]]; then
    # Listado normal (legible)
    fls -r -o "$OFFSET" "$DISK" > "$OUT/fls_recursive.txt" 2> "$OUT/fls_recursive.err" || true
    
    # Bodyfile para mactime (Usamos -m en lugar de -b)
    fls -r -m / -o "$OFFSET" "$DISK" > "$OUT/bodyfile.txt" 2> "$OUT/bodyfile.err" || true
else
    fls -r -m / "$DISK" > "$OUT/bodyfile.txt" 2> "$OUT/bodyfile.err" || true
fi

# 4) Mactime
if [[ -s "$OUT/bodyfile.txt" ]]; then
    echo "[*] Generating timeline..."
    mactime -b "$OUT/bodyfile.txt" -d -y > "$OUT/mactime.csv" 2> "$OUT/mactime.err" || true
    echo "[+] Timeline saved to $OUT/mactime.csv"
else
    echo "[WARN] bodyfile.txt está vacío. Revisa $OUT/bodyfile.err"
    # Si fls falló, intentamos ver el error específico
    cat "$OUT/bodyfile.err"
fi

# 5) Strings
strings -a -n 8 "$DISK" | head -n 20000 > "$OUT/strings_head.txt" 2>/dev/null || true

echo "---"
echo "$OUT"