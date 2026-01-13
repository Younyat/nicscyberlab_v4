#!/usr/bin/env bash
set -euo pipefail

echo "[*] Eliminando Tcpdump..."
sudo apt purge -y tcpdump && sudo apt autoremove -y

# Verificación de borrado
if ! command -v tcpdump &> /dev/null; then
    echo "[OK] Verificación exitosa: Tcpdump eliminado correctamente."
else
    echo "[ERROR] El binario de Tcpdump persiste."
    exit 1
fi

echo "data: [FIN]"