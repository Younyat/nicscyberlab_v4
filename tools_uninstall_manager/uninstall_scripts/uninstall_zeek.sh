#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ZEEK IDS UNINSTALLER (INTEGRATED WITH PYTHON MANAGER)
# ============================================================

# --- 1. CONFIGURACION DE RUTAS RELATIVAS ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
ADMIN_OPENRC="$PROJECT_ROOT/admin-openrc.sh"

# --- 2. PARAMETROS RECIBIDOS DESDE EL MANAGER (Python) ---
# $1: instance | $2: ssh_key | $3: target_ip | $4: ssh_user
INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Argumentos insuficientes recibidos de Python."
    exit 1
fi

# --- 3. TRABAJO TEMPORAL ---
# Normalizamos el nombre para evitar conflictos en el sistema de archivos
CLEAN_NAME="${INSTANCE_NAME// /_}"
TEMP_WORK_DIR="/tmp/ansible_zeek_cleanup_${CLEAN_NAME}"
mkdir -p "$TEMP_WORK_DIR"

# --- 4. GENERACION DE INVENTARIO Y PLAYBOOK ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

cat > "$TEMP_WORK_DIR/zeek-cleanup.yml" <<'EOF'
---
- name: Borrado Total de Zeek IDS
  hosts: target
  become: true
  tasks:
    - name: 1. Detener instancias de Zeek mediante zeekctl
      command: /opt/zeek/bin/zeekctl stop
      ignore_errors: true

    - name: 2. Matar procesos Zeek residuales
      shell: pkill -9 zeek
      ignore_errors: true
      changed_when: false

    - name: 3. Eliminar paquetes de Zeek (Purge)
      apt:
        name: "zeek*"
        state: absent
        purge: true

    - name: 4. Eliminar directorios, logs y repositorios
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /opt/zeek
        - /var/log/zeek
        - /etc/apt/sources.list.d/network:zeek.list
        - /etc/apt/trusted.gpg.d/network_zeek.gpg

    - name: 5. Limpiar dependencias y archivos huerfanos
      apt:
        autoremove: true
        purge: true

    - name: 6. Limpiar sudoers de Ansible
      file:
        path: /etc/sudoers.d/ansible_nopasswd
        state: absent
EOF

# --- 5. EJECUCION DE ANSIBLE ---
echo "Iniciando desinstalacion de Zeek en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/zeek-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

# --- 6. LIMPIEZA FINAL ---
rm -rf "$TEMP_WORK_DIR"

echo "Proceso de desinstalacion de Zeek finalizado en $INSTANCE_NAME"