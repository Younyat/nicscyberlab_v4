#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 1. CONTEXTO Y RUTAS (ACTUALIZADAS)
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DUMP_DIR="$SCRIPT_DIR/memory_dumps"
RESULTS_DIR="$SCRIPT_DIR/analysis_results"
# Ruta específica que mencionaste
SYMBOLS_DIR="$DUMP_DIR/symbols/linux"

mkdir -p "$RESULTS_DIR"

# Archivo de memoria específico
DUMP_FILE="$DUMP_DIR/memdump_victim_3_20260106_204957.lime"

# ============================================================
# 2. VERIFICACIÓN DE ARCHIVOS
# ============================================================
if [[ ! -f "$DUMP_FILE" ]]; then
    echo "ERROR: No se encuentra el dump en: $DUMP_FILE"
    exit 1
fi

# Verificamos si existe el JSON específico en tu ruta
JSON_FILE="$SYMBOLS_DIR/debian-6.1.0-41-cloud.json"
if [[ ! -f "$JSON_FILE" ]]; then
    echo "ERROR: No se encuentra el archivo JSON de símbolos en: $JSON_FILE"
    exit 1
fi

echo "[OK] Dump: $(basename "$DUMP_FILE")"
echo "[OK] Símbolos: $(basename "$JSON_FILE")"

# ============================================================
# 3. VERIFICAR VOLATILITY
# ============================================================
if ! command -v vol >/dev/null 2>&1; then
    echo "ERROR: El comando 'vol' no está disponible. Asegúrate de activar tu venv."
    exit 1
fi

# ============================================================
# 4. EJECUCIÓN DE ANÁLISIS (CON RUTA DE SÍMBOLOS EXPLÍCITA)
# ============================================================
# Usamos el parámetro -s para forzar a Volatility a mirar en tu carpeta de símbolos

log_analysis() {
    local plugin=$1
    local outfile=$2
    echo "[*] Ejecutando $plugin..."
    # -s le indica a Volatility dónde buscar el JSON
    vol -s "$SYMBOLS_DIR" -f "$DUMP_FILE" "$plugin" > "$RESULTS_DIR/$outfile" 2>&1 || echo "    [!] Error en $plugin"
}

log_analysis "banners.Banners" "01_kernel_banner.txt"
log_analysis "linux.pslist.PsList" "02_pslist.txt"
log_analysis "linux.pstree.PsTree" "03_pstree.txt"
log_analysis "linux.sockstat.Sockstat" "04_network_sockets.txt"
log_analysis "linux.bash.Bash" "05_bash_history.txt"
log_analysis "linux.envars.Envars" "06_environment_variables.txt"
log_analysis "linux.lsmod.Lsmod" "08_kernel_modules.txt"

# ============================================================
# 5. FINAL
# ============================================================
echo "============================================================"
echo "[OK] ANÁLISIS COMPLETADO EXITOSAMENTE"
echo " Los resultados están en: $RESULTS_DIR"
echo "============================================================"