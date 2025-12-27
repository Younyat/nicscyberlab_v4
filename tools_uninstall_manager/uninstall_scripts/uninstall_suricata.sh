#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "===================================================="
echo " Desinstalador Profesional para Suricata Installer"
echo "===================================================="

# 1. Detener procesos (SIN USAR -f para evitar el suicidio del script)
echo "[1/4] Deteniendo procesos de Suricata..."
# Usamos -x para matar solo el binario exacto
sudo pkill -9 -x suricata || true
# También intentamos pararlo si se registró como servicio
sudo systemctl stop suricata 2>/dev/null || true

# 2. Desinstalar paquetes (Lo que borra el binario)
echo "[2/4] Eliminando paquetes y dependencias..."
sudo apt-get purge -y suricata jq net-tools || true
sudo apt-get autoremove -y >/dev/null

# 3. Limpiar archivos y reglas creadas en el paso [3/5] y [4/5]
echo "[3/4] Eliminando archivos de configuración y logs..."
sudo rm -rf /etc/suricata
sudo rm -rf /usr/local/etc/suricata
sudo rm -rf /var/log/suricata
sudo rm -rf /var/lib/suricata

# 4. Revertir modo promiscuo (Paso [5/5] del instalador)
echo "[4/4] Revirtiendo modo promiscuo..."
INTERFACE=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}') || true
if [[ -n "$INTERFACE" ]]; then
    sudo ip link set "$INTERFACE" promisc off || true
fi

echo "----------------------------------------------------"
echo " SURICATA ELIMINADO COMPLETAMENTE"
echo "----------------------------------------------------"
exit 0