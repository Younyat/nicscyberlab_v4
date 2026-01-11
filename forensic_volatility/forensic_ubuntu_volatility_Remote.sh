#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 1. LOGGING Y CONTEXTO
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
INSTALL_LOG="$LOG_DIR/ubuntu_forensics_$TIMESTAMP.log"

exec > >(tee -a "$INSTALL_LOG") 2>&1

# ============================================================
# 2. OPENSTACK CREDENTIALS
# ============================================================
OPENRC_PATH="$(realpath "$SCRIPT_DIR/../admin-openrc.sh")"
[[ -f "$OPENRC_PATH" ]] || { echo "ERROR: admin-openrc.sh no encontrado"; exit 1; }
source "$OPENRC_PATH"

# ============================================================
# 3. CONFIGURACIÓN VM
# ============================================================
VM_NAME="Ubuntu_Forensics_Workstation"
IMAGE="ubuntu-22.04"
FLAVOR="S_2CPU_4GB"
PRIVATE_NET="net_private_01"
EXTERNAL_NET="net_external_01"
KEY_NAME="my_key"
SSH_KEY="$HOME/.ssh/my_key"
SSH_USER="ubuntu"
SG_NAME="forensics-sg"

TCP_PORTS=(22)

log() { echo "[INFO] $*"; }
ok()  { echo "[OK]   $*"; }

# ============================================================
# 4. OPENSTACK (IDEMPOTENTE)
# ============================================================
openstack flavor show "$FLAVOR" >/dev/null 2>&1 || \
  openstack flavor create "$FLAVOR" --vcpus 2 --ram 4096 --disk 40 --public

openstack security group show "$SG_NAME" >/dev/null 2>&1 || \
  openstack security group create "$SG_NAME"

for p in "${TCP_PORTS[@]}"; do
  openstack security group rule create \
    --ingress --proto tcp --dst-port "$p" "$SG_NAME" 2>/dev/null || true
done

# ============================================================
# 5. LANZAR VM
# ============================================================
openstack server show "$VM_NAME" >/dev/null 2>&1 || \
openstack server create \
  --image "$IMAGE" \
  --flavor "$FLAVOR" \
  --key-name "$KEY_NAME" \
  --network "$PRIVATE_NET" \
  --security-group "$SG_NAME" \
  "$VM_NAME"

log "Esperando estado ACTIVE..."
until [[ "$(openstack server show "$VM_NAME" -f value -c status)" == "ACTIVE" ]]; do
  sleep 3
done

FIXED_IP=$(openstack server show "$VM_NAME" -f value -c addresses | grep -oP '192\.168\.100\.\d+')
FIP=$(openstack floating ip list --fixed-ip-address "$FIXED_IP" -f value -c "Floating IP Address" | head -n1)

if [[ -z "$FIP" ]]; then
  FIP=$(openstack floating ip create "$EXTERNAL_NET" -f value -c floating_ip_address)
  openstack server add floating ip "$VM_NAME" "$FIP"
fi

ok "VM disponible en $FIP"

until nc -z "$FIP" 22; do sleep 5; done

# ============================================================
# 6. ANSIBLE – BASE FORENSICS (SIN AUTOPSY, SIN VOLATILITY)
# ============================================================
ANSIBLE_DIR="/tmp/ansible_forensics_$TIMESTAMP"
mkdir -p "$ANSIBLE_DIR"

cat > "$ANSIBLE_DIR/hosts.ini" <<EOF
[forensic]
$FIP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$ANSIBLE_DIR/base_playbook.yml" <<'EOF'
---
- name: Base Forensics Node (clean)
  hosts: forensic
  become: true

  tasks:
    - name: Esperar conexión SSH
      wait_for_connection:
        timeout: 300

    - name: Recolectar facts
      setup:

    - name: Instalar herramientas forenses base (CLI)
      apt:
        update_cache: true
        name:
          - testdisk
          - binwalk
          - libafflib-dev
          - libewf-dev
          - libsqlite3-dev
          - unzip
          - wget
          - git
        state: present

    - name: Marcar nodo forense base listo
      file:
        path: /opt/FORENSICS_BASE_READY
        state: touch
EOF

ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook \
  -i "$ANSIBLE_DIR/hosts.ini" \
  "$ANSIBLE_DIR/base_playbook.yml"

# ============================================================
# 7. ANSIBLE – VOLATILITY 3 (OFICIAL GITHUB)
# ============================================================
log "Instalando Volatility 3 (modo oficial GitHub)"

ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook \
  -i "$ANSIBLE_DIR/hosts.ini" \
  "$SCRIPT_DIR/install_volatility3.yml"

# ============================================================
# 8. FINAL
# ============================================================
ok "DESPLIEGUE FORENSE COMPLETADO"

echo "============================================================"
echo " VM FORENSICS LISTA"
echo "------------------------------------------------------------"
echo " SSH        : ssh -i $SSH_KEY $SSH_USER@$FIP"
echo " Volatility : usar comando 'vol'"
echo " Logs       : $INSTALL_LOG"
echo "============================================================"
