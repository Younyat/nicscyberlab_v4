#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ICS TRAFFIC ANALYSIS – UNINSTALLER (HOST LEVEL)
# ============================================================

PROJECT_NAME="ics_traffic_forensics"
INSTALL_DIR="/opt/${PROJECT_NAME}"

echo "============================================================"
echo " DESINSTALANDO ${PROJECT_NAME}"
echo "============================================================"
echo

# Confirmación explícita
read -rp "¿Seguro que quieres DESINSTALAR completamente ${INSTALL_DIR}? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
  echo "[ABORTADO] Desinstalación cancelada."
  exit 0
fi

echo "[+] Deteniendo posibles procesos en ejecución..."
pkill -f "api/backend.py" || true
pkill -f "flask" || true
pkill -f "ics_traffic" || true

echo "[+] Eliminando directorio del proyecto..."
if [[ -d "$INSTALL_DIR" ]]; then
  sudo rm -rf "$INSTALL_DIR"
  echo "[OK] Directorio ${INSTALL_DIR} eliminado"
else
  echo "[INFO] Directorio ${INSTALL_DIR} no existe"
fi

echo "[+] Restaurando permisos de tcpdump y tshark (quitando capabilities)..."
sudo setcap -r /usr/bin/tcpdump || true
sudo setcap -r /usr/bin/tshark || true

echo "[+] (Opcional) Desinstalar dependencias del sistema"
read -rp "¿Deseas eliminar tcpdump, tshark, iptables, python3-venv? (yes/no): " REMOVE_PKGS
if [[ "$REMOVE_PKGS" == "yes" ]]; then
  sudo apt remove -y tcpdump tshark iptables python3-venv python3-pip
  sudo apt autoremove -y
  echo "[OK] Paquetes del sistema eliminados"
else
  echo "[INFO] Paquetes del sistema conservados"
fi

echo "[+] Limpieza de configuraciones residuales (wireshark)..."
sudo rm -rf /etc/wireshark || true

echo
echo "============================================================"
echo " DESINSTALACIÓN COMPLETADA"
echo "============================================================"
echo
echo "Estado final:"
echo " - Proyecto eliminado"
echo " - Entorno virtual eliminado"
echo " - Capturas eliminadas"
echo " - Sistema limpio"
echo
