#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 1. CONTEXTO
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUMP_DIR="$SCRIPT_DIR/memory_dumps"
RESULTS_DIR="$SCRIPT_DIR/analysis_results"
mkdir -p "$RESULTS_DIR"

# ============================================================
# 2. SELECCIONAR DUMP
# ============================================================
DUMP_FILE=$(ls -1t "$DUMP_DIR"/*.lime | head -n1)

if [[ -z "$DUMP_FILE" ]]; then
    echo "ERROR: No se encontró ningún dump .lime"
    exit 1
fi

echo "[OK] Dump seleccionado:"
echo "     $DUMP_FILE"

# ============================================================
# 3. VERIFICAR VOLATILITY
# ============================================================
if ! command -v vol >/dev/null 2>&1; then
    echo "ERROR: Volatility (vol) no está en el PATH"
    exit 1
fi

vol frameworkinfo >/dev/null
echo "[OK] Volatility disponible"

# ============================================================
# 4. BANNER DEL KERNEL (CORRECTO EN V3)
# ============================================================
echo "[*] Extrayendo banner del kernel..."
vol -f "$DUMP_FILE" banners.Banners \
    | tee "$RESULTS_DIR/01_kernel_banner.txt"

# ============================================================
# 5. LISTA DE PROCESOS
# ============================================================
echo "[*] Listando procesos..."
vol -f "$DUMP_FILE" linux.pslist \
    | tee "$RESULTS_DIR/02_pslist.txt"

# ============================================================
# 6. ÁRBOL DE PROCESOS
# ============================================================
echo "[*] Árbol de procesos..."
vol -f "$DUMP_FILE" linux.pstree \
    | tee "$RESULTS_DIR/03_pstree.txt"

# ============================================================
# 7. CONEXIONES DE RED
# ============================================================
echo "[*] Conexiones de red..."
vol -f "$DUMP_FILE" linux.sockstat \
    | tee "$RESULTS_DIR/04_network_sockets.txt"

# ============================================================
# 8. HISTORIAL DE BASH
# ============================================================
echo "[*] Historial de bash..."
vol -f "$DUMP_FILE" linux.bash \
    | tee "$RESULTS_DIR/05_bash_history.txt"

# ============================================================
# 9. VARIABLES DE ENTORNO
# ============================================================
echo "[*] Variables de entorno..."
vol -f "$DUMP_FILE" linux.envars \
    | tee "$RESULTS_DIR/06_environment_variables.txt"

# ============================================================
# 10. USUARIOS LOGUEADOS
# ============================================================
echo "[*] Usuarios conectados..."
vol -f "$DUMP_FILE" linux.who \
    | tee "$RESULTS_DIR/07_logged_users.txt"

# ============================================================
# 11. MÓDULOS DEL KERNEL
# ============================================================
echo "[*] Módulos del kernel..."
vol -f "$DUMP_FILE" linux.lsmod \
    | tee "$RESULTS_DIR/08_kernel_modules.txt"

# ============================================================
# 12. FINAL
# ============================================================
echo "============================================================"
echo "[OK] ANÁLISIS FORENSE COMPLETADO"
echo " Dump       : $DUMP_FILE"
echo " Resultados : $RESULTS_DIR"
echo "============================================================"
