#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#   SURICATA INSTALL/UNINSTALL STRESS TEST
# ============================================================

INSTALL_SCRIPT="./wazuh_installer.sh"
UNINSTALL_SCRIPT="./wazuh_uninstaller.sh"

ITERATIONS=5
SLEEP_BETWEEN=10   # segundos entre install/uninstall
LOG_DIR="./stress_logs"

mkdir -p "$LOG_DIR"

echo "===================================================="
echo " 🔁 SURICATA STRESS TEST"
echo "===================================================="
echo " Iteraciones : $ITERATIONS"
echo " Logs        : $LOG_DIR"
echo "===================================================="

for i in $(seq 1 "$ITERATIONS"); do
    echo
    echo "----------------------------------------------------"
    echo " ▶ ITERACIÓN $i / $ITERATIONS"
    echo "----------------------------------------------------"

    INSTALL_LOG="$LOG_DIR/install_${i}.log"
    UNINSTALL_LOG="$LOG_DIR/uninstall_${i}.log"

    echo "[+] Instalando Suricata (iteración $i)..."
    if ! bash "$INSTALL_SCRIPT" >"$INSTALL_LOG" 2>&1; then
        echo "❌ ERROR en instalación (iteración $i)"
        echo "   Revisa: $INSTALL_LOG"
        exit 1
    fi

    sleep "$SLEEP_BETWEEN"

    echo "[+] Desinstalando Suricata (iteración $i)..."
    if ! bash "$UNINSTALL_SCRIPT" >"$UNINSTALL_LOG" 2>&1; then
        echo "❌ ERROR en desinstalación (iteración $i)"
        echo "   Revisa: $UNINSTALL_LOG"
        exit 1
    fi

    sleep "$SLEEP_BETWEEN"

    echo "✅ Iteración $i completada correctamente"
done

echo
echo "===================================================="
echo " ✅ STRESS TEST COMPLETADO SIN ERRORES"
echo "===================================================="
