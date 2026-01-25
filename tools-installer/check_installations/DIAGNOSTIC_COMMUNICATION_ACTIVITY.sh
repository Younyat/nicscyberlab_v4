#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="10.0.2.172"
MANAGER_IP="10.0.2.136"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

echo "===================================================="
echo " [DIAGNOSTIC] COMPROBANDO FLUJO DE ALERTAS"
echo "===================================================="

# 1. Verificar conectividad de red al puerto 1514 (Eventos)
echo "[1/3] Verificando puerto 1514 en el Manager..."
ssh -i "$SSH_KEY" "$SSH_USER@$VICTIM_IP" "nc -zv $MANAGER_IP 1514" || echo " [!] ERROR: Puerto 1514 cerrado o inalcanzable."

# 2. Verificar estado de sincronización del Agente
echo "[2/3] Comprobando logs de conexión en el Agente..."
ssh -i "$SSH_KEY" "$SSH_USER@$VICTIM_IP" "sudo grep -E 'ERROR|WARNING' /var/ossec/logs/ossec.log | tail -n 5"

# 3. Forzar reinicio del Agente para re-conectar
echo "[3/3] Reiniciando Agente para forzar envío de buffer..."
ssh -i "$SSH_KEY" "$SSH_USER@$VICTIM_IP" "sudo systemctl restart wazuh-agent"

echo "===================================================="
echo " [ACTION] Ejecuta ahora GENERATE_REALTIME_SECURITY_EVENTS.sh"
echo "          y refresca el Dashboard en 10 segundos."
echo "===================================================="