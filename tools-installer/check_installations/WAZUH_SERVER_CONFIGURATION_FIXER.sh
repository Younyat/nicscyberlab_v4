#!/usr/bin/env bash
# Ubicación: /home/younes/nicscyberlab_v3/tools-installer/check_installations/WAZUH_SERVER_CONFIGURATION_FIXER.sh
set -euo pipefail

# ============================================================
#  WAZUH SERVER CONFIGURATION FIXER (ULTIMATE VERSION)
#  Objetivo: Activar Vulnerabilidades, FIM Real-time y Debian
# ============================================================

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
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        "$SSH_USER@$TARGET_IP" "$1"
}

echo "===================================================="
echo " [START] OPTIMIZANDO WAZUH MANAGER: $TARGET_IP"
echo "===================================================="

# --- 2. REPARACIÓN DEL MOTOR DE VULNERABILIDADES ---
echo "[1/4] Configurando Vulnerability Detector..."

# Activar el motor global
ssh_exec "sudo sed -i '/<vulnerability-detector>/,/<\/vulnerability-detector>/ s|<enabled>no</enabled>|<enabled>yes</enabled>|' $CONF_FILE"

# Activar el provider de Debian y forzar versiones 10, 11, 12
ssh_exec "sudo sed -i '/<provider name=\"debian\">/,/<\/provider>/ s|<enabled>no</enabled>|<enabled>yes</enabled>|' $CONF_FILE"
ssh_exec "sudo sed -i '/<provider name=\"debian\">/,/<\/provider>/ s|<os>.*</os>|<os>10,11,12</os>|' $CONF_FILE"

# --- 3. REPARACIÓN DE INTEGRIDAD DE ARCHIVOS (FIM) ---
echo "[2/4] Activando Monitoreo en Tiempo Real (FIM)..."

# Modificar directorios críticos para usar realtime="yes" y report_changes="yes"
# Usamos un sed más robusto que ignora espacios extras en los tags
ssh_exec "sudo sed -i 's|<directories.*>/etc,/usr/bin,/usr/sbin</directories>|<directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">/etc,/usr/bin,/usr/sbin</directories>|' $CONF_FILE"
ssh_exec "sudo sed -i 's|<directories.*>/bin,/sbin,/boot</directories>|<directories realtime=\"yes\" check_all=\"yes\" report_changes=\"yes\">/bin,/sbin,/boot</directories>|' $CONF_FILE"

# Asegurar que Syscheck no esté deshabilitado globalmente
ssh_exec "sudo sed -i '/<syscheck>/ s|<disabled>yes</disabled>|<disabled>no</disabled>|' $CONF_FILE"

# --- 4. REPARACIÓN DE SCA (SEGURIDAD DE CONFIGURACIÓN) ---
echo "[3/4] Asegurando escaneo de políticas (SCA)..."
ssh_exec "sudo sed -i '/<sca>/,/<\/sca>/ s|<enabled>no</enabled>|<enabled>yes</enabled>|' $CONF_FILE"

# --- 5. APLICAR CAMBIOS ---
echo "[4/4] Reiniciando Wazuh Manager y limpiando colas..."
ssh_exec "sudo systemctl restart wazuh-manager"

echo "===================================================="
echo " [SUCCESS] MANAGER CONFIGURADO CORRECTAMENTE"
echo " [INFO] Comprobando descarga de base de datos CVE..."
ssh_exec "sudo tail -n 20 /var/ossec/logs/ossec.log | grep -i 'vulnerability-detector' || echo ' [!] El motor está arrancando, espera 1 min.'"
echo "===================================================="