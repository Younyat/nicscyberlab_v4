#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#   SURICATA AUTO INSTALLER (Victim-3)
#   Filosofía: simple, reproducible, profesional
# ============================================================

# --- CONFIGURACIÓN ÚNICA ---
INSTANCE_NAME="Victim 3"
TARGET_IP="10.0.2.23"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

SURICATA_VERSION="suricata"
BASE_DIR="$HOME/suricata-auto"

echo "===================================================="
echo " SURICATA AUTO INSTALLER"
echo "===================================================="
echo " Instance : $INSTANCE_NAME"
echo " Target   : $SSH_USER@$TARGET_IP"
echo "===================================================="

# ------------------------------------------------------------
# [1/6] Verificación de conectividad y sudo
# ------------------------------------------------------------
echo "[1/6] Verificando SSH y configurando sudo sin password..."

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_IP" << EOF
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/suricata_nopasswd
    echo "SSH_READY"
EOF

# ------------------------------------------------------------
# [2/6] Preparación del sistema
# ------------------------------------------------------------
echo "[2/6] Preparando sistema base (APT, dependencias)..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
    sudo apt-get update -y
    sudo apt-get install -y \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        curl \
        jq \
        gnupg \
        lsb-release
EOF

# ------------------------------------------------------------
# [3/6] Instalación de Suricata
# ------------------------------------------------------------
echo "[3/6] Instalando Suricata..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
    sudo add-apt-repository -y ppa:oisf/suricata-stable
    sudo apt-get update -y
    sudo apt-get install -y suricata
EOF

# ------------------------------------------------------------
# [4/6] Detección de interfaz de red
# ------------------------------------------------------------
echo "[4/6] Detectando interfaz de red principal..."

INTERFACE=$(ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" \
    "ip route get 8.8.8.8 | awk '{print \$5; exit}'")

if [[ -z "$INTERFACE" ]]; then
    echo "❌ No se pudo detectar la interfaz de red"
    exit 1
fi

echo " Interfaz detectada: $INTERFACE"

# ------------------------------------------------------------
# [5/6] Configuración profesional de Suricata
# ------------------------------------------------------------
echo "[5/6] Configurando Suricata (AF_PACKET + reglas)..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << EOF
    sudo sed -i "s|^# *- interface: .*|- interface: $INTERFACE|" /etc/suricata/suricata.yaml
    sudo sed -i "s|^ *- interface: eth0|  - interface: $INTERFACE|" /etc/suricata/suricata.yaml

    # Activar modo AF_PACKET de alto rendimiento
    sudo sed -i "/af-packet:/,/^$/c\\af-packet:\\n  - interface: $INTERFACE\\n    threads: auto\\n    cluster-id: 99\\n    cluster-type: cluster_flow\\n    defrag: yes" /etc/suricata/suricata.yaml

    # Descargar reglas oficiales
    sudo suricata-update

    sudo systemctl daemon-reexec
    sudo systemctl enable suricata
    sudo systemctl restart suricata
EOF

# ------------------------------------------------------------
# [6/6] Validación final
# ------------------------------------------------------------
echo "[6/6] Validando estado de Suricata..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
    sudo suricata -T -c /etc/suricata/suricata.yaml -v
    sudo systemctl status suricata --no-pager
EOF

echo "===================================================="
echo " ✅ SURICATA INSTALADO CORRECTAMENTE"
echo "===================================================="
echo " Instancia : Victim-3"
echo " IP        : 10.0.2.23"
echo " Servicio  : suricata (activo)"
echo " Logs      : /var/log/suricata/"
echo "===================================================="
