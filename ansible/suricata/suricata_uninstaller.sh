#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#   SURICATA UNINSTALLER (Victim-3)
#   Limpieza real – sin falsos positivos dpkg
# ============================================================

INSTANCE_NAME="Victim 3"
TARGET_IP="10.0.2.23"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

START_TIME=$(date +%s)

echo "===================================================="
echo " 🧠 SURICATA UNINSTALLER"
echo "===================================================="
echo " Instance : $INSTANCE_NAME"
echo " Target   : $SSH_USER@$TARGET_IP"
echo "===================================================="

# ------------------------------------------------------------
# [1/6] Verificar SSH y sudo
# ------------------------------------------------------------
echo "[1/6] Verificando acceso SSH y sudo..."

ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_IP" << EOF
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/suricata_nopasswd
    echo "SSH_READY"
EOF

# ------------------------------------------------------------
# [2/6] Detener servicios y procesos
# ------------------------------------------------------------
echo "[2/6] Deteniendo Suricata y procesos activos..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
    sudo systemctl stop suricata 2>/dev/null || true
    sudo systemctl disable suricata 2>/dev/null || true

    # Kill seguro por si quedó colgado
    sudo pkill -9 suricata 2>/dev/null || true
EOF

# ------------------------------------------------------------
# [3/6] Purga de paquetes
# ------------------------------------------------------------
echo "[3/6] Eliminando paquetes Suricata..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
    if dpkg -l | grep -q suricata; then
        sudo apt-get purge -y suricata suricata-update || true
        sudo apt-get autoremove -y --purge || true
    else
        echo "Suricata no estaba instalado"
    fi
EOF

# ------------------------------------------------------------
# [4/6] Eliminación de ficheros residuales
# ------------------------------------------------------------
echo "[4/6] Eliminando restos de configuración y logs..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
    sudo rm -rf /etc/suricata
    sudo rm -rf /var/lib/suricata
    sudo rm -rf /var/log/suricata
    sudo rm -rf /usr/share/suricata
    sudo rm -rf /var/run/suricata*
EOF

# ------------------------------------------------------------
# [5/6] Limpieza de usuarios y reglas
# ------------------------------------------------------------
echo "[5/6] Limpieza de usuario y reglas residuales..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
    # Usuario
    if id suricata &>/dev/null; then
        sudo deluser --remove-home suricata || true
    fi

    # Reglas descargadas
    sudo rm -rf /var/lib/suricata/rules || true
EOF

# ------------------------------------------------------------
# [6/6] Validación final
# ------------------------------------------------------------
echo "[6/6] Validación post-uninstall..."

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << 'EOF'
    if command -v suricata >/dev/null; then
        echo "❌ ERROR: binario suricata aún existe"
        exit 1
    fi

    systemctl list-unit-files | grep -q suricata && \
        echo "⚠️ Unidad systemd residual detectada" || \
        echo "✅ Sin unidades systemd"

    echo "Estado dpkg:"
    dpkg -l | grep suricata || echo "OK – dpkg limpio"
EOF

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "===================================================="
echo " ✅ SURICATA ELIMINADO COMPLETAMENTE"
echo "===================================================="
echo " Instancia : $INSTANCE_NAME"
echo " IP        : $TARGET_IP"
echo " Tiempo    : ${DURATION}s"
echo "===================================================="
