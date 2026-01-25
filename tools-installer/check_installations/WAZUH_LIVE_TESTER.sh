#!/usr/bin/env bash
# Ubicación: /home/younes/nicscyberlab_v3/tools-installer/check_installations/WAZUH_LIVE_TESTER.sh
set -euo pipefail

# --- PARÁMETROS ---




VICTIM_IP="${1:-10.0.2.172}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"






echo "===================================================="
echo " [TEST] GENERANDO ALERTAS EN VIVO PARA EL DASHBOARD"
echo "===================================================="

# 1. Test de Integridad (FIM)
echo "[1/2] Modificando archivos en /etc (Debería salir en Integrity Monitoring)..."
ssh -i "$SSH_KEY" "$SSH_USER@$VICTIM_IP" "sudo touch /etc/alerta_realtime.txt && sudo chmod 777 /etc/alerta_realtime.txt"

# 2. Test de Seguridad (Ataque de fuerza bruta simulado)
echo "[2/2] Generando fallos de SSH (Debería salir en Security Events)..."
for i in {1..3}; do
    ssh -i "$SSH_KEY" -o ConnectTimeout=2 -o BatchMode=yes -o PubkeyAuthentication=no usuario_falso@$VICTIM_IP 2>/dev/null || true
done

echo "===================================================="
echo " [DONE] Pruebas enviadas."
echo " [HINT] Revisa el Dashboard con filtro 'Last 15 minutes'."
echo "===================================================="