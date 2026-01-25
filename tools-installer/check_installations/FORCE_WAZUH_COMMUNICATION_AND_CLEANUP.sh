#!/usr/bin/env bash
set -euo pipefail

VICTIM_IP="10.0.2.172"
MANAGER_IP="10.0.2.136"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

echo "===================================================="
echo " [FIX] REESTABLECIENDO COMUNICACIÓN AGENTE -> MANAGER"
echo "===================================================="

# 1. Prueba de conexión sin 'nc' (usando bash interno)
echo "[1/3] Verificando ruta al Manager (Puerto 1514)..."
ssh -i "$SSH_KEY" "$SSH_USER@$VICTIM_IP" "timeout 2 bash -c '</dev/tcp/$MANAGER_IP/1514' && echo ' [OK] Puerto 1514 ALCANZABLE' || echo ' [!] ERROR: Puerto 1514 BLOQUEADO'"

# 2. Limpieza de colas y buffer del Agente
# A veces el agente deja de enviar si la cola está corrupta o llena
echo "[2/3] Limpiando buffers y reiniciando el servicio..."
ssh -i "$SSH_KEY" "$SSH_USER@$VICTIM_IP" "sudo rm -f /var/ossec/queue/rids/* && sudo systemctl restart wazuh-agent"

# 3. Verificación de proceso activo
echo "[3/3] Comprobando procesos de Wazuh..."
ssh -i "$SSH_KEY" "$SSH_USER@$VICTIM_IP" "ps aux | grep wazuh-agentd | grep -v grep"

echo "===================================================="
echo " [INFO] Si el puerto 1514 salió como BLOQUEADO, revisa"
echo "        el Firewall de tu Manager (monitor-1)."
echo "===================================================="