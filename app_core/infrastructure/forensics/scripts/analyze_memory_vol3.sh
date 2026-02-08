#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# analyze_memory_vol3.sh (robusto para UI/API)
# ============================================================
# Uso previsto (backend):
#   analyze_memory_vol3.sh <CASE_DIR> <DUMP_FILE|AUTO> <SYMBOLS_DIR|AUTO> <VOL_CMD|AUTO>
#
# Nota importante:
# - Este script IGNORA argumentos extra (por ejemplo vm_id) para no romper la ejecución.
# - NO usa "bash -lc" para evitar inyección/desalineado de parámetros.
# ============================================================

if [[ $# -lt 4 ]]; then
  echo "Uso: $0 <CASE_DIR> <DUMP_FILE|AUTO> <SYMBOLS_DIR|AUTO> <VOL_CMD|AUTO>"
  exit 1
fi

CASE_DIR="$1"
DUMP_IN="$2"
SYMBOLS_IN="$3"
VOL_IN="$4"

OUT_DIR="${CASE_DIR}/memory/analysis_results"
mkdir -p "$OUT_DIR"

# ----------------------------
# Helpers
# ----------------------------
pick_latest_dump() {
  ls -1t "${CASE_DIR}/memory/"*.lime 2>/dev/null | head -n1 || true
}

pick_symbols_dir() {
  # Preferimos el cache que tú ya usas:
  if [[ -d "${HOME}/vol3_symbols_cache/symbols/linux" ]]; then
    echo "${HOME}/vol3_symbols_cache/symbols/linux"
    return 0
  fi

  # Símbolos dentro del caso (si algún día los guardas ahí)
  if [[ -d "${CASE_DIR}/memory/symbols/linux" ]]; then
    echo "${CASE_DIR}/memory/symbols/linux"
    return 0
  fi

  # Cache estándar de Volatility (si existiera)
  if [[ -d "${HOME}/.cache/volatility3/symbols/linux" ]]; then
    echo "${HOME}/.cache/volatility3/symbols/linux"
    return 0
  fi

  return 1
}

resolve_vol_cmd() {
  local v="$1"
  if [[ "$v" == "AUTO" ]]; then
    command -v vol >/dev/null 2>&1 || { echo "ERROR: 'vol' no está en PATH"; exit 1; }
    echo "vol"
    return 0
  fi

  # Si te pasan algo raro (vm_id), lo detectamos:
  if [[ "$v" =~ ^[0-9a-fA-F-]{36}$ ]]; then
    echo "ERROR: VOL_CMD parece un vm_id ($v). Backend está pasando args mal."
    exit 127
  fi

  echo "$v"
}

# ----------------------------
# 1) Resolver DUMP
# ----------------------------
DUMP_FILE="$DUMP_IN"
if [[ "$DUMP_FILE" == "AUTO" ]]; then
  DUMP_FILE="$(pick_latest_dump)"
  [[ -n "${DUMP_FILE:-}" ]] || { echo "ERROR: No se encontró ningún dump .lime"; exit 1; }
else
  # Permite que te pasen "memory/xxx.lime"
  [[ "$DUMP_FILE" != /* ]] && DUMP_FILE="${CASE_DIR}/${DUMP_FILE}"
fi

[[ -f "$DUMP_FILE" ]] || { echo "ERROR: No existe dump: $DUMP_FILE"; exit 1; }
echo "[OK] Dump seleccionado: $DUMP_FILE"

# ----------------------------
# 2) Resolver SYMBOLS_DIR (ojo: debe ser .../linux)
# ----------------------------
SYMBOLS_DIR="$SYMBOLS_IN"
if [[ "$SYMBOLS_DIR" == "AUTO" ]]; then
  SYMBOLS_DIR="$(pick_symbols_dir || true)"
  [[ -n "${SYMBOLS_DIR:-}" ]] || { echo "ERROR: No se encontró SYMBOLS_DIR automáticamente."; exit 1; }
else
  [[ "$SYMBOLS_DIR" != /* ]] && SYMBOLS_DIR="${CASE_DIR}/${SYMBOLS_DIR}"
fi

[[ -d "$SYMBOLS_DIR" ]] || { echo "ERROR: No existe SYMBOLS_DIR: $SYMBOLS_DIR"; exit 1; }
echo "[OK] Symbols dir: $SYMBOLS_DIR"

# ----------------------------
# 3) Resolver VOL_CMD
# ----------------------------
VOL_CMD="$(resolve_vol_cmd "$VOL_IN")"
echo "[OK] VOL_CMD=$VOL_CMD"

# Si VOL_CMD es "vol" debe existir
if [[ "$VOL_CMD" == "vol" ]]; then
  command -v vol >/dev/null 2>&1 || { echo "ERROR: vol no está en PATH"; exit 1; }
fi

# ----------------------------
# 4) Runner (sin bash -lc)
# ----------------------------
run_plugin() {
  local plugin="$1"
  local outfile="$2"

  echo "[*] Ejecutando: $plugin"

  # Guardar stdout+stderr en fichero y también mostrarlo en vivo:
  "$VOL_CMD" -f "$DUMP_FILE" -s "$SYMBOLS_DIR" "$plugin" 2>&1 | tee "$OUT_DIR/$outfile" >/dev/null || true

  if grep -qi "Unsatisfied requirement" "$OUT_DIR/$outfile"; then
    echo "[WARN] $plugin: Unsatisfied requirements. Revisa símbolos/banners."
  fi
}

echo "--- Iniciando Análisis de Memoria ---"

# Banner primero
run_plugin "banners.Banners" "01_kernel_banner.txt"

# Plugins Linux válidos (según tu Vol3)
run_plugin "linux.pslist.PsList"     "02_pslist.txt"
run_plugin "linux.pstree.PsTree"     "03_pstree.txt"
run_plugin "linux.psaux.PsAux"       "04_psaux.txt"
run_plugin "linux.sockstat.Sockstat" "05_sockstat.txt"
run_plugin "linux.sockscan.Sockscan" "06_sockscan.txt"
run_plugin "linux.bash.Bash"         "07_bash_history.txt"
run_plugin "linux.envars.Envars"     "08_envars.txt"
run_plugin "linux.lsmod.Lsmod"       "09_lsmod.txt"
run_plugin "linux.ip.Addr"           "10_ip_addr.txt"
run_plugin "linux.ip.Link"           "11_ip_link.txt"
run_plugin "linux.boottime.Boottime" "12_boottime.txt"

echo "============================================================"
echo "[OK] ANÁLISIS COMPLETADO"
echo " Resultados en: $OUT_DIR"
echo "============================================================"
echo "$OUT_DIR"
