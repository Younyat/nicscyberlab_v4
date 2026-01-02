#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
MANAGER_IP="10.0.2.160"      # IP de tu servidor Wazuh
VICTIM_IP="10.0.2.23"       # REEMPLAZA CON LA IP DE VICTIM 3
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

AGENT_NAME="Victim-3"        # Nombre que aparecerá en el panel de Wazuh
AGENT_VERSION="4.7.3-1"
DEB_FILE="wazuh-agent_${AGENT_VERSION}_amd64.deb"

echo "===================================================="
echo " 🛡️ DESPLEGANDO AGENTE EN: $AGENT_NAME ($VICTIM_IP)"
echo "===================================================="

# Ejecución remota vía SSH
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$VICTIM_IP" << EOF
    set -e
    echo "[1/4] Descargando paquete Wazuh Agent v$AGENT_VERSION..."
    wget -q https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/$DEB_FILE

    echo "[2/4] Instalando con Manager: $MANAGER_IP..."
    sudo WAZUH_MANAGER='$MANAGER_IP' WAZUH_AGENT_NAME='$AGENT_NAME' dpkg -i ./$DEB_FILE

    echo "[3/4] Configurando servicios..."
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent

    echo "[4/4] Verificando estado..."
    if systemctl is-active --quiet wazuh-agent; then
        echo "✅ Agente instalado y funcionando en $AGENT_NAME"
    else
        echo "❌ Error al iniciar el agente"
        exit 1
    fi

    # Limpieza
    rm ./$DEB_FILE
EOF

echo "===================================================="
echo " ✅ PROCESO FINALIZADO"
echo " Revisa tu Dashboard en: https://$MANAGER_IP"
echo "===================================================="