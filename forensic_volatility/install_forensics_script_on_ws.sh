#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 1. CONFIGURACIÓN
# ============================================================
VM_NAME="Ubuntu_Forensics_Workstation"
SSH_USER="ubuntu"
SSH_KEY="$HOME/.ssh/my_key"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_SCRIPT="$SCRIPT_DIR/forensics_install.sh"
REMOTE_SCRIPT="/home/ubuntu/forensics_install.sh"

# ============================================================
# 2. VALIDACIONES
# ============================================================
if [[ ! -f "$LOCAL_SCRIPT" ]]; then
    echo "ERROR: No se encuentra forensics_install.sh en $SCRIPT_DIR"
    exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
    echo "ERROR: Clave SSH no encontrada: $SSH_KEY"
    exit 1
fi

# ============================================================
# 3. CARGAR CREDENCIALES OPENSTACK
# ============================================================
OPENRC="$HOME/admin-openrc.sh"

if [[ ! -f "$OPENRC" ]]; then
    echo "ERROR: admin-openrc.sh no encontrado en $OPENRC"
    exit 1
fi

source "$OPENRC"
echo "[OK] Credenciales OpenStack cargadas"

# ============================================================
# 4. RESOLVER IP FLOTANTE DE LA WORKSTATION
# ============================================================
echo "[1/4] Resolviendo IP flotante de $VM_NAME..."

FIXED_IP=$(openstack server show "$VM_NAME" -f value -c addresses \
  | grep -oP '192\.168\.100\.\d+' | head -n1)

if [[ -z "$FIXED_IP" ]]; then
    echo "ERROR: No se pudo obtener IP privada"
    exit 1
fi

FIP=$(openstack floating ip list \
  --fixed-ip-address "$FIXED_IP" \
  -f value -c "Floating IP Address" | head -n1)

if [[ -z "$FIP" ]]; then
    echo "ERROR: La VM no tiene IP flotante asociada"
    exit 1
fi

echo "[OK] IP flotante: $FIP"

# ============================================================
# 5. COPIAR SCRIPT A LA WORKSTATION
# ============================================================
echo "[2/4] Copiando forensics_install.sh..."

scp -i "$SSH_KEY" \
  -o StrictHostKeyChecking=no \
  "$LOCAL_SCRIPT" \
  "$SSH_USER@$FIP:$REMOTE_SCRIPT"

# ============================================================
# 6. EJECUTAR SCRIPT (OUTPUT EN TIEMPO REAL)
# ============================================================
echo "[3/4] Ejecutando instalación (salida en directo)"
echo "--------------------------------------------------"

ssh -tt -i "$SSH_KEY" \
  -o StrictHostKeyChecking=no \
  "$SSH_USER@$FIP" << EOF
chmod +x $REMOTE_SCRIPT
sudo bash $REMOTE_SCRIPT
EOF

# ============================================================
# 7. FINAL
# ============================================================
echo "--------------------------------------------------"
echo "[4/4] Instalación completada en Ubuntu_Forensics_Workstation"
