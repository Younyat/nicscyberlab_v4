#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#   WAZUH MANAGER - AGENT DESTROYER (PRO)
# ============================================================

MANAGER_IP="10.0.2.160"
SSH_USER="ubuntu"
SSH_KEY="$HOME/.ssh/my_key"

AGENT_NAME="Victim-3"

echo "===================================================="
echo " 🧠 WAZUH MANAGER - AGENT DESTROYER"
echo "===================================================="
echo " Manager : $MANAGER_IP"
echo " Agent   : $AGENT_NAME"
echo "===================================================="
echo

read -rp "⚠️  ¿ELIMINAR el agente '$AGENT_NAME' del MANAGER? (yes/NO): " CONFIRM
[[ "$CONFIRM" != "yes" ]] && { echo "Cancelado."; exit 0; }






ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$MANAGER_IP" << EOF
set -euo pipefail

echo ">>> Buscando agente '$AGENT_NAME'..."

AGENT_ID=\$(sudo /var/ossec/bin/manage_agents -l | \
  awk -F',' -v name="$AGENT_NAME" '
    \$2 ~ name {
      gsub(/ID:[[:space:]]*/, "", \$1);
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", \$1);
      print \$1
    }')

if [[ -z "\$AGENT_ID" ]]; then
  echo "✔ El agente no existe en el manager"
  exit 0
fi

echo ">>> Agente encontrado con ID: \$AGENT_ID"
echo ">>> Eliminando agente del manager..."

printf "y\n" | sudo /var/ossec/bin/manage_agents -r "\$AGENT_ID"

echo ">>> Reiniciando wazuh-manager..."
sudo systemctl restart wazuh-manager

echo ">>> DONE: agente eliminado del manager"
EOF


echo "===================================================="
echo " ✅ AGENTE ELIMINADO DEL MANAGER"
echo "===================================================="
