#!/usr/bin/env bash
set -euo pipefail

if command -v tcpdump &> /dev/null; then
    echo "[!] Tcpdump ya está instalado."
    echo "data: [FIN]"
    exit 0
fi

echo "[*] Instalando Tcpdump..."
sudo apt update && sudo apt install -y tcpdump

# Verificación
if tcpdump --version &> /dev/null; then
    echo "[OK] Tcpdump verificado correctamente."
else
    echo "[ERROR] Error al verificar Tcpdump."
    exit 1
fi

echo "data: [FIN]"