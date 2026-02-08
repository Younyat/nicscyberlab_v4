#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ICS TRAFFIC ANALYSIS – UNINSTALLER (HOST LEVEL)
# Safe, precise, host-friendly
# ============================================================

PROJECT_NAME="ics_traffic_forensics"
INSTALL_DIR="/opt/${PROJECT_NAME}"

# Optional: if you used systemd service name(s)
SERVICE_NAMES=(
  "ics-traffic-analysis"
  "ics-traffic-forensics"
  "${PROJECT_NAME}"
)

# Optional: if you created a dedicated user
APP_USER="${APP_USER:-}"

# Optional: logs (adjust if you used them)
LOG_DIRS=(
  "/var/log/${PROJECT_NAME}"
)

# Optional: extra config dirs created by your app
CONFIG_DIRS=(
  "/etc/${PROJECT_NAME}"
)

# Behaviour flags
AUTO_YES="no"
REMOVE_PKGS="no"
REMOVE_WIRESHARK_CONF="no"

usage() {
  cat <<EOF
Uso: $0 [--yes] [--remove-pkgs] [--remove-wireshark-conf]

  --yes                  No preguntar confirmación
  --remove-pkgs          (Peligroso) Intentar desinstalar tcpdump/tshark/venv/pip
  --remove-wireshark-conf (Peligroso) Eliminar /etc/wireshark
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) AUTO_YES="yes"; shift ;;
    --remove-pkgs) REMOVE_PKGS="yes"; shift ;;
    --remove-wireshark-conf) REMOVE_WIRESHARK_CONF="yes"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Opción no reconocida: $1"; usage; exit 1 ;;
  esac
done

echo "============================================================"
echo " DESINSTALANDO ${PROJECT_NAME}"
echo "============================================================"
echo " - INSTALL_DIR: ${INSTALL_DIR}"
echo

if [[ "$AUTO_YES" != "yes" ]]; then
  read -rp "¿Seguro que quieres DESINSTALAR completamente ${INSTALL_DIR}? (yes/no): " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    echo "[ABORTADO] Desinstalación cancelada."
    exit 0
  fi
fi

echo "[+] Deteniendo servicios systemd si existen..."
for svc in "${SERVICE_NAMES[@]}"; do
  if systemctl list-unit-files | grep -q "^${svc}\.service"; then
    sudo systemctl stop "${svc}.service" || true
    sudo systemctl disable "${svc}.service" || true
    sudo rm -f "/etc/systemd/system/${svc}.service" || true
    sudo rm -f "/lib/systemd/system/${svc}.service" || true
    echo "  [OK] Servicio eliminado: ${svc}.service"
  fi
done
sudo systemctl daemon-reload || true

echo "[+] Matando procesos únicamente si ejecutan desde ${INSTALL_DIR}..."
if [[ -d "$INSTALL_DIR" ]]; then
  # Busca PIDs con cwd o cmdline apuntando al install dir (más seguro que pkill por nombre)
  PIDS=$(ps -eo pid=,args= | awk -v d="$INSTALL_DIR" '$0 ~ d {print $1}' | tr '\n' ' ' || true)
  if [[ -n "${PIDS// /}" ]]; then
    echo "  [INFO] PIDs encontrados: $PIDS"
    sudo kill $PIDS || true
    sleep 0.5
    sudo kill -9 $PIDS || true
    echo "  [OK] Procesos terminados"
  else
    echo "  [INFO] No se encontraron procesos asociados a ${INSTALL_DIR}"
  fi
else
  echo "  [INFO] INSTALL_DIR no existe, skip kill"
fi

echo "[+] Eliminando directorio del proyecto..."
if [[ -d "$INSTALL_DIR" ]]; then
  sudo rm -rf "$INSTALL_DIR"
  echo "[OK] Directorio ${INSTALL_DIR} eliminado"
else
  echo "[INFO] Directorio ${INSTALL_DIR} no existe"
fi

echo "[+] Eliminando logs específicos del proyecto..."
for d in "${LOG_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    sudo rm -rf "$d"
    echo "  [OK] Eliminado: $d"
  fi
done

echo "[+] Eliminando config específica del proyecto..."
for d in "${CONFIG_DIRS[@]}"; do
  if [[ -d "$d" ]]; then
    sudo rm -rf "$d"
    echo "  [OK] Eliminado: $d"
  fi
done

echo "[+] Restaurando capabilities (tcpdump/tshark) si fueron modificadas..."
TCPDUMP_BIN="$(command -v tcpdump || true)"
TSHARK_BIN="$(command -v tshark || true)"

if [[ -n "$TCPDUMP_BIN" && -e "$TCPDUMP_BIN" ]]; then
  sudo setcap -r "$TCPDUMP_BIN" || true
  echo "  [OK] setcap -r $TCPDUMP_BIN"
else
  echo "  [INFO] tcpdump no encontrado, skip"
fi

if [[ -n "$TSHARK_BIN" && -e "$TSHARK_BIN" ]]; then
  sudo setcap -r "$TSHARK_BIN" || true
  echo "  [OK] setcap -r $TSHARK_BIN"
else
  echo "  [INFO] tshark no encontrado, skip"
fi

if [[ -n "$APP_USER" ]]; then
  echo "[+] Eliminando usuario dedicado (APP_USER=$APP_USER) si existe..."
  if id "$APP_USER" >/dev/null 2>&1; then
    sudo userdel -r "$APP_USER" || true
    echo "  [OK] Usuario eliminado: $APP_USER"
  else
    echo "  [INFO] Usuario no existe: $APP_USER"
  fi
fi

if [[ "$REMOVE_WIRESHARK_CONF" == "yes" ]]; then
  echo "[+] Eliminando /etc/wireshark (peligroso)..."
  sudo rm -rf /etc/wireshark || true
  echo "  [OK] /etc/wireshark eliminado"
else
  echo "[INFO] Conservando /etc/wireshark"
fi

if [[ "$REMOVE_PKGS" == "yes" ]]; then
  echo "[+] Desinstalando paquetes del sistema (peligroso)..."
  sudo apt remove -y tcpdump tshark python3-venv python3-pip || true
  sudo apt autoremove -y || true
  echo "  [OK] Paquetes eliminados (si estaban instalados)"
else
  echo "[INFO] Paquetes del sistema conservados"
fi

echo
echo "============================================================"
echo " DESINSTALACIÓN COMPLETADA"
echo "============================================================"
echo "Estado final:"
echo " - Proyecto eliminado: ${INSTALL_DIR}"
echo " - Services limpiados (si existían)"
echo " - Logs/Config específicos limpiados (si existían)"
echo " - Capabilities restauradas (si aplicaba)"
