#!/usr/bin/env bash
set -euo pipefail

echo "[*] Eliminando mbpoll..."
sudo apt purge -y mbpoll && sudo apt autoremove -y

# Verificación de borrado
if ! command -v mbpoll &> /dev/null; then
    echo "[OK] Verificación exitosa: mbpoll eliminado."
else
    echo "[ERROR] mbpoll no se pudo eliminar completamente."
    exit 1
fi

echo "data: [FIN]"
