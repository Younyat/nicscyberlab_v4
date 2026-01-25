#!/usr/bin/env bash
# Reparador de sincronización Dashboard-Indexer
set -euo pipefail

MANAGER_IP="10.0.2.136"
SSH_USER="ubuntu"
SSH_KEY="$HOME/.ssh/my_key"

echo "===================================================="
echo " [FIX] REINICIANDO MOTOR DE VISUALIZACIÓN"
echo "===================================================="

# Reiniciar los servicios de datos en el servidor
ssh -i "$SSH_KEY" "$SSH_USER@$MANAGER_IP" << 'EOF'
sudo systemctl restart wazuh-indexer
sudo systemctl restart wazuh-dashboard
# Forzar al manager a escribir un evento de estado
sudo /var/ossec/bin/wazuh-control restart
EOF

echo "===================================================="
echo " [OK] Servicios reiniciados."
echo " [!] Vuelve al Dashboard y pulsa REFRESH (F5)."
echo "===================================================="