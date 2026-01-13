#!/usr/bin/env bash
set -euo pipefail

echo "[*] Iniciando desinstalación de The Sleuth Kit..."
sudo apt purge -y sleuthkit && sudo apt autoremove -y

# Verificación de borrado
if ! command -v fls &> /dev/null; then
    echo "[OK] Verificación exitosa: TSK ha sido eliminado del sistema."
else
    echo "[ERROR] TSK sigue detectado en el sistema."
    exit 1
fi

echo "data: [FIN]"