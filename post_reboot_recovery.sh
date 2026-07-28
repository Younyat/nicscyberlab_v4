#!/usr/bin/env bash
# =================================================================
# post_reboot_recovery.sh
#
# Un solo script para ejecutar después de reiniciar este host
# (que hace de escritorio Y de nodo compute/controller de OpenStack
# a la vez). Repara lo que NO sobrevive a un reinicio por sí solo:
#
#   1. uplinkbridge (10.0.2.1/24) — puerta de enlace de TODAS las
#      IPs flotantes del laboratorio. Ya se dejó persistente y con
#      autoconnect=yes el 2026-07-27 (ver network/README.md), pero
#      este paso es un respaldo idempotente por si algo no arrancó.
#   2. Reglas NAT/iptables para 10.0.2.0/24 — no hay ningún paquete
#      de persistencia de iptables instalado en este host, así que
#      se restauran aquí desde el backup si hiciera falta.
#   3. Arranca el dashboard (gunicorn + credenciales OpenStack) vía
#      el script ya existente start_dashboard.sh.
#
# Uso:
#   bash post_reboot_recovery.sh
#
# Idempotente: seguro de ejecutar aunque la red ya esté bien.
# =================================================================

set -uo pipefail

APP_PATH="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
IPTABLES_BACKUP="$HOME/iptables_backup_antes_de_reiniciar.rules"

echo "===================================================="
echo " [1/3] Verificando uplinkbridge (red de IPs flotantes)"
echo "===================================================="

if ip -br link show uplinkbridge 2>/dev/null | grep -q "UP"; then
    echo "[OK] uplinkbridge ya está UP."
else
    echo "[INFO] uplinkbridge no está activo — levantándolo..."
    sudo nmcli connection up uplinkbridge
fi

if ip -br addr show uplinkbridge 2>/dev/null | grep -q "10.0.2.1/24"; then
    echo "[OK] uplinkbridge tiene su IP 10.0.2.1/24."
else
    echo "[WARN] uplinkbridge está UP pero sin la IP esperada 10.0.2.1/24 — revisar a mano."
fi

echo
echo "===================================================="
echo " [2/3] Verificando reglas NAT para 10.0.2.0/24"
echo "===================================================="

if sudo iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "10.0.2.0/24"; then
    echo "[OK] Reglas NAT para 10.0.2.0/24 ya presentes."
elif [[ -f "$IPTABLES_BACKUP" ]]; then
    echo "[INFO] No se encontraron reglas NAT — restaurando desde $IPTABLES_BACKUP..."
    sudo iptables-restore < "$IPTABLES_BACKUP"
    echo "[OK] Reglas restauradas."
else
    echo "[WARN] No hay reglas NAT ni backup en $IPTABLES_BACKUP — las IPs flotantes pueden no funcionar. Revisar a mano."
fi

echo
echo "===================================================="
echo " [3/3] Arrancando el dashboard (gunicorn + credenciales OpenStack)"
echo "===================================================="
echo "[INFO] Delegando en start_dashboard.sh (ya carga admin-openrc.sh y levanta gunicorn)."
echo

exec bash "$APP_PATH/start_dashboard.sh"
