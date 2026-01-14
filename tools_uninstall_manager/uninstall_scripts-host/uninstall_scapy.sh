#!/usr/bin/env bash
set -euo pipefail

echo "[*] Eliminando Scapy (Python Packet Engine)..."

# Desinstalación vía pip (system-wide)
if python3 - <<EOF &>/dev/null
import scapy
EOF
then
    sudo python3 -m pip uninstall -y scapy
else
    echo "[INFO] Scapy no estaba instalado vía pip."
fi

# Limpieza ligera (no agresiva)
sudo apt autoremove -y >/dev/null 2>&1 || true

# Verificación de borrado
if python3 - <<EOF &>/dev/null
import scapy
EOF
then
    echo "[ERROR] Scapy no se pudo eliminar completamente."
    exit 1
else
    echo "[OK] Verificación exitosa: Scapy eliminado."
fi

echo "data: [FIN]"
