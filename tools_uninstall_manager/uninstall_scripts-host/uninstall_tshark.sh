#!/usr/bin/env bash
set -euo pipefail

echo "[*] Eliminando Tshark..."
sudo apt purge -y tshark && sudo apt autoremove -y

# Verificación de borrado
if ! command -v tshark &> /dev/null; then
    echo "[OK] Verificación exitosa: Tshark eliminado."
else
    echo "[ERROR] Tshark no se pudo eliminar completamente."
    exit 1
fi

echo "data: [FIN]"