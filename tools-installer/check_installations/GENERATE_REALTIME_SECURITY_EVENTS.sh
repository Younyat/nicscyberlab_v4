#!/usr/bin/env bash
# Ubicación: /home/younes/nicscyberlab_v3/tools-installer/check_installations/GENERATE_REALTIME_SECURITY_EVENTS.sh
set -euo pipefail

# --- PARÁMETROS DE ENTRADA ---
# Ip de la víctima (Agente) y usuario
VICTIM_IP="${1:-10.0.2.172}" 
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"

echo "===================================================="
echo " [LIVE] ACTIVIDAD: GENERANDO ALERTAS DE SEGURIDAD"
echo "===================================================="

# 1. Actividad de Integridad de Archivos (FIM)
# Esto genera una alerta instantánea de creación, modificación y borrado.
echo "[1/2] Realizando cambios en archivos críticos (/etc)..."
ssh -i "$SSH_KEY" "$SSH_USER@$VICTIM_IP" "sudo touch /etc/wazuh_security_event.txt && sudo chmod 777 /etc/wazuh_security_event.txt && sudo rm /etc/wazuh_security_event.txt"

# 2. Actividad de Autenticación (Ataque simulado)
# Esto genera alertas de 'Authentication failure' que verás en Security Events.
echo "[2/2] Simulando intentos de acceso no autorizados..."
for i in {1..3}; do
    ssh -i "$SSH_KEY" -o ConnectTimeout=2 -o BatchMode=yes -o PubkeyAuthentication=no hacker_user@$VICTIM_IP 2>/dev/null || true
done

echo "===================================================="
echo " [OK] Actividad completada con éxito."
echo " [!] RECUERDA: Cambia el rango en Wazuh a 'Last 15 minutes'."
echo "===================================================="