#!/usr/bin/env bash
# Ubicación sugerida: /home/younes/nicscyberlab_v3/tools-installer/check_installations/WAZUH_SERVER_CONFIGURATION_FIXER.sh
set -euo pipefail

# --- 1. PARÁMETROS DE ENTRADA ---
TARGET_IP="${1:-}" 
SSH_USER="${2:-ubuntu}"
SSH_KEY="$HOME/.ssh/my_key"
CONF_FILE="/var/ossec/etc/ossec.conf"

if [[ -z "$TARGET_IP" ]]; then
    echo " [ERROR] Uso: $0 <IP_FLOTANTE_MANAGER> [USUARIO]"
    exit 1
fi

ssh_exec() {
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=10 "$SSH_USER@$TARGET_IP" "$1"
}

echo "===================================================="
echo " [FIX] ACTIVANDO MODO LIVE-TIME EN: $TARGET_IP"
echo "===================================================="

# --- 2. ACTIVACIÓN DE MOTORES (LOGIC SEGÚN AUDITORÍA) ---

echo "[1/3] Habilitando Vulnerability Detector (Global + Debian)..."
# Activa el motor principal y el proveedor específico para tus víctimas Debian
ssh_exec "sudo sed -i '/<vulnerability-detector>/,/<\/vulnerability-detector>/ s|<enabled>no</enabled>|<enabled>yes</enabled>|' $CONF_FILE"
ssh_exec "sudo sed -i '/<provider name=\"debian\">/,/<\/provider>/ s|<enabled>no</enabled>|<enabled>yes</enabled>|' $CONF_FILE"

echo "[2/3] Inyectando Real-Time en directorios críticos..."
# Transforma los escaneos programados en detección instantánea
ssh_exec "sudo sed -i 's|<directories >/etc,/usr/bin,/usr/sbin</directories>|<directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">/etc,/usr/bin,/usr/sbin</directories>|' $CONF_FILE"
ssh_exec "sudo sed -i 's|<directories >/bin,/sbin,/boot</directories>|<directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">/bin,/sbin,/boot</directories>|' $CONF_FILE"

echo "[3/3] Reiniciando Wazuh Manager para aplicar cambios..."
ssh_exec "sudo systemctl restart wazuh-manager"

echo "===================================================="
echo " [SUCCESS] Configuración reparada correctamente."
echo " [INFO] Ahora el servidor detectará todo en tiempo real."
echo "===================================================="