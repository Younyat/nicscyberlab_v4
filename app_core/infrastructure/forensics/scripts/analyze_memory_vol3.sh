#!/usr/bin/env bash
set -euo pipefail

# 1. Recibir argumentos de la API
CASE_DIR="$1"
DUMP_FILE="$2"
# Forzamos la ruta que tú confirmaste que funciona
SYMBOLS_DIR="/home/younes/vol3_symbols_cache/symbols/linux"
VOL_CMD="$4"
VM_ID="${5:-default_vm}"

# 2. Configurar el directorio de salida para que la API lo encuentre
# Tu API busca en: analysis/vol3/<vm_id>
OUT_DIR="${CASE_DIR}/analysis/vol3/${VM_ID}"
mkdir -p "$OUT_DIR"

echo "--- Iniciando Análisis Directo ---"

# 3. Ejecutar exactamente los comandos que te funcionan a mano
# Redirigimos la salida a los archivos que espera el sistema

echo "[*] Ejecutando Banners..."
$VOL_CMD -f "$DUMP_FILE" -s "$SYMBOLS_DIR" banners.Banners > "$OUT_DIR/01_banners.txt" 2>&1 || true

echo "[*] Ejecutando PsList..."
$VOL_CMD -f "$DUMP_FILE" -s "$SYMBOLS_DIR" linux.pslist.PsList > "$OUT_DIR/02_pslist.txt" 2>&1 || true

echo "[*] Ejecutando Sockstat..."
$VOL_CMD -f "$DUMP_FILE" -s "$SYMBOLS_DIR" linux.sockstat.Sockstat > "$OUT_DIR/04_sockstat.txt" 2>&1 || true

echo "[*] Ejecutando Lsmod..."
$VOL_CMD -f "$DUMP_FILE" -s "$SYMBOLS_DIR" linux.lsmod.Lsmod > "$OUT_DIR/05_lsmod.txt" 2>&1 || true

echo "[*] Ejecutando Check_syscall..."
$VOL_CMD -f "$DUMP_FILE" -s "$SYMBOLS_DIR" linux.check_syscall.Check_syscall > "$OUT_DIR/07_syscalls.txt" 2>&1 || true

echo "[*] Ejecutando Bash History..."
$VOL_CMD -f "$DUMP_FILE" -s "$SYMBOLS_DIR" linux.bash.Bash > "$OUT_DIR/06_bash.txt" 2>&1 || true





echo "============================================================"
echo "[OK] ANÁLISIS COMPLETADO"
echo " Resultados en: $OUT_DIR"
echo "============================================================"

# Imprimir el directorio para que la API lo capture
echo "$OUT_DIR"