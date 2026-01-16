#!/usr/bin/env bash
set -euo pipefail

# 1. Pre-verificación
if command -v fls &> /dev/null; then
    echo "[!] TSK ya está instalado en el sistema."
    echo "data: [FIN]"
    exit 0
fi

echo "[*] Instalando TSK..."
sudo apt update && sudo apt install -y sleuthkit

# 2. Verificación Post-instalación
if command -v fls &> /dev/null; then
    VERSION=$(fls -V | head -n 1)
    echo "[OK] Verificación exitosa: $VERSION"
else
    echo "[ERROR] La instalación falló. El binario 'fls' no se encuentra."
    exit 1
fi

echo "data: [FIN]"