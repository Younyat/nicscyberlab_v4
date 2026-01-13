#!/usr/bin/env bash
set -euo pipefail

echo "[*] Eliminando Termshark de /usr/local/bin..."
sudo rm -f /usr/local/bin/termshark
rm -rf "$HOME/.config/termshark"

# Verificación de borrado
if [[ ! -f "/usr/local/bin/termshark" ]]; then
    echo "[OK] Verificación exitosa: El binario de Termshark ha desaparecido."
else
    echo "[ERROR] No se pudo borrar el archivo en /usr/local/bin/termshark."
    exit 1
fi

echo "data: [FIN]"