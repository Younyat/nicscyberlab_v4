#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# 0. VARIABLES DE CONFIGURACIÓN (EDITAR AQUÍ)
# ============================================================
# Nombre de la máquina donde se instalará Volatility
VM_FORENSIC_NAME="Ubuntu_Forensics_Workstation"

# Patrón para buscar la máquina víctima en OpenStack
VICTIM_PATTERN="victim"

# Configuración de infraestructura para la estación forense
IMAGE_FORENSIC="ubuntu-22.04"
FLAVOR_FORENSIC="M_2CPU_8GB"
PRIVATE_NET="net_private_01"
EXTERNAL_NET="net_external_01"
KEY_NAME="my_key"
SSH_KEY="$HOME/.ssh/my_key"
SSH_USER="ubuntu"
SG_NAME="forensics-sg"

# Versión del kernel de la víctima para los símbolos
KERNEL_VER="6.1.0-41-cloud-amd64"

# ============================================================
# 1. LOGGING Y DEPENDENCIAS LOCALES
# ============================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
INSTALL_LOG="$LOG_DIR/install_$TIMESTAMP.log"
exec > >(tee -a "$INSTALL_LOG") 2>&1

log() { echo "[INFO] $*"; }
ok()  { echo "[OK]   $*"; }

# --- VERIFICACIÓN DE ANSIBLE LOCAL ---
if ! command -v ansible-playbook >/dev/null 2>&1; then
    log "Ansible no detectado localmente. Instalando..."
    sudo apt update && sudo apt install -y python3-pip
    pip3 install ansible
    ok "Ansible instalado en el sistema local."
fi

# ============================================================
# 2. OPENSTACK CREDENTIALS
# ============================================================
OPENRC_PATH="$(realpath "$SCRIPT_DIR/../admin-openrc.sh")"
[[ -f "$OPENRC_PATH" ]] || { echo "ERROR: admin-openrc.sh no encontrado"; exit 1; }
source "$OPENRC_PATH"

# ============================================================
# 3. DETECCIÓN AUTOMÁTICA DE VÍCTIMA
# ============================================================
log "Buscando una instancia en OpenStack que contenga: '$VICTIM_PATTERN'..."

VM_VICTIM_NAME=$(openstack server list -f value -c Name | grep -i "$VICTIM_PATTERN" | head -n1)

if [[ -z "$VM_VICTIM_NAME" ]]; then
    echo "ERROR: No se encontró ninguna instancia con el patrón '$VICTIM_PATTERN'."
    exit 1
fi

IMAGE_VICTIM=$(openstack server show "$VM_VICTIM_NAME" -f value -c image | cut -d'(' -f1 | xargs)

if [[ "$IMAGE_VICTIM" =~ "ubuntu" ]]; then
    REPO_TYPE="ubuntu"
elif [[ "$IMAGE_VICTIM" =~ "debian" || "$IMAGE_VICTIM" =~ "kali" ]]; then
    REPO_TYPE="debian"
else
    echo "ERROR: La imagen de la víctima ($IMAGE_VICTIM) no es compatible."
    exit 1
fi

ok "Víctima encontrada: $VM_VICTIM_NAME | OS detectado: $REPO_TYPE"

# ============================================================
# 4. LANZAMIENTO COMPLETO DE LA VM FORENSE
# ============================================================
log "Iniciando despliegue de infraestructura para: $VM_FORENSIC_NAME"

# Verificar o crear Flavor
openstack flavor show "$FLAVOR_FORENSIC" >/dev/null 2>&1 || \
openstack flavor create "$FLAVOR_FORENSIC" --vcpus 2 --ram 8192 --disk 20 --public

# Verificar o crear Security Group
openstack security group show "$SG_NAME" >/dev/null 2>&1 || \
  openstack security group create "$SG_NAME"

# Asegurar regla SSH
openstack security group rule create --ingress --proto tcp --dst-port 22 "$SG_NAME" 2>/dev/null || true

# Crear instancia si no existe
if ! openstack server show "$VM_FORENSIC_NAME" >/dev/null 2>&1; then
    log "Creando servidor $VM_FORENSIC_NAME..."
    openstack server create \
      --image "$IMAGE_FORENSIC" \
      --flavor "$FLAVOR_FORENSIC" \
      --key-name "$KEY_NAME" \
      --network "$PRIVATE_NET" \
      --security-group "$SG_NAME" \
      "$VM_FORENSIC_NAME"

    log "Esperando que la VM esté ACTIVE..."
    until [[ "$(openstack server show "$VM_FORENSIC_NAME" -f value -c status)" == "ACTIVE" ]]; do sleep 3; done
else
    ok "La instancia $VM_FORENSIC_NAME ya existe."
fi

# Gestión de IP Flotante
FIXED_IP=$(openstack server show "$VM_FORENSIC_NAME" -f value -c addresses | grep -oP '192\.168\.100\.\d+')
FIP=$(openstack floating ip list --fixed-ip-address "$FIXED_IP" -f value -c "Floating IP Address" | head -n1)

if [[ -z "$FIP" ]]; then
    log "Asignando nueva IP flotante..."
    FIP=$(openstack floating ip create "$EXTERNAL_NET" -f value -c floating_ip_address)
    openstack server add floating ip "$VM_FORENSIC_NAME" "$FIP"
fi

ok "Estación Forense lista en IP: $FIP"
log "Comprobando conectividad SSH..."
until nc -z "$FIP" 22; do sleep 5; done

# ============================================================
# 5. ANSIBLE - CONFIGURACIÓN REMOTA DETALLADA
# ============================================================
ANSIBLE_DIR="/tmp/ansible_forensics_$TIMESTAMP"
mkdir -p "$ANSIBLE_DIR"

cat > "$ANSIBLE_DIR/hosts.ini" <<EOF
[forensic]
$FIP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$ANSIBLE_DIR/setup.yml" <<EOF
---
- name: Forensic Workstation Detailed Setup
  hosts: forensic
  become: true
  vars:
    vol_dir: "/home/ubuntu/volatility3"
    symbols_dir: "/home/ubuntu/volatility3/volatility3/symbols/linux"
    kernel_ver: "$KERNEL_VER"
    repo_type: "$REPO_TYPE"

  tasks:
    - name: Verificar estado previo de Volatility
      stat:
        path: "/usr/local/bin/vol"
      register: vol_bin

    - name: 1. Instalar herramientas base del sistema
      apt:
        update_cache: true
        name: [git, python3-venv, python3-pip, wget, curl, binutils, build-essential, libffi-dev, libssl-dev, xz-utils]
        state: present
      when: not vol_bin.stat.exists

    - name: 2. Clonar Repositorio Volatility 3
      git:
        repo: https://github.com/volatilityfoundation/volatility3.git
        dest: "{{ vol_dir }}"
      when: not vol_bin.stat.exists

    - name: 3. Entorno Virtual e instalar dependencias (CORREGIDO)
      pip:
        name: "."
        chdir: "{{ vol_dir }}"
        virtualenv: "{{ vol_dir }}/venv"
        virtualenv_command: "/usr/bin/python3 -m venv"
        extra_args: "-e"
      when: not vol_bin.stat.exists

    - name: 4. Crear ejecutable global 'vol'
      copy:
        dest: /usr/local/bin/vol
        mode: '0755'
        content: |
          #!/bin/bash
          source {{ vol_dir }}/venv/bin/activate
          python3 {{ vol_dir }}/vol.py "\$@"
      when: not vol_bin.stat.exists

    - name: 5. Instalar dwarf2json y preparar símbolos
      shell: |
        # Descarga de dwarf2json
        wget -N https://github.com/volatilityfoundation/dwarf2json/releases/latest/download/dwarf2json-linux-amd64 -O /usr/local/bin/dwarf2json
        chmod +x /usr/local/bin/dwarf2json
        mkdir -p {{ symbols_dir }}
        
        KVER="{{ kernel_ver }}"
        cd /tmp
        
        if [ "{{ repo_type }}" = "debian" ]; then
            BASE="http://security.debian.org/debian-security/pool/updates/main/l/linux/"
            PKG=\$(curl -s \$BASE | grep -oP "linux-image-\${KVER}-dbg_[^\" ]+" | head -1)
            URL="\${BASE}\${PKG}"
        else
            BASE="http://ddebs.ubuntu.com/pool/main/l/linux/"
            PKG=\$(curl -s \$BASE | grep -oP "linux-image-\${KVER}-dbgsym_[^\" ]+" | head -1)
            URL="\${BASE}\${PKG}"
        fi

        wget -N "\$URL"
        ar x \$(basename "\$URL")
        tar -xf data.tar.xz ./usr/lib/debug/boot/vmlinux-\${KVER}
        /usr/local/bin/dwarf2json linux --elf ./usr/lib/debug/boot/vmlinux-\${KVER} > {{ symbols_dir }}/\${KVER}.json
      args:
        executable: /bin/bash
        creates: "{{ symbols_dir }}/{{ kernel_ver }}.json"

    - name: Ajustar permisos finales
      file:
        path: "{{ vol_dir }}"
        owner: ubuntu
        group: ubuntu
        recurse: yes
EOF

log "Ejecutando aprovisionamiento remoto con Ansible..."
ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i "$ANSIBLE_DIR/hosts.ini" "$ANSIBLE_DIR/setup.yml"

# ============================================================
# 6. RESUMEN FINAL
# ============================================================

ok "ESTACIÓN DE TRABAJO CONFIGURADA"
echo "------------------------------------------------------------"
echo " Nombre VM  : $VM_FORENSIC_NAME"
echo " IP Pública : $FIP"
echo " Víctima    : $VM_VICTIM_NAME"
echo " Kernel     : $KERNEL_VER"
echo "------------------------------------------------------------"
echo " Acceso SSH: ssh -i $SSH_KEY ubuntu@$FIP"
echo "------------------------------------------------------------"