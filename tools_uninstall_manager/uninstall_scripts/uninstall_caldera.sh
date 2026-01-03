#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  CALDERA UNINSTALLER (SERVER & AGENT - INTEGRATED)
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
TEMP_WORK_DIR="/tmp/ansible_caldera_cleanup_${INSTANCE_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

# --- 4. GENERACION DE INVENTARIO ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[caldera_target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

# --- 5. GENERACION DEL PLAYBOOK DE PURGA ---
cat > "$TEMP_WORK_DIR/caldera-cleanup.yml" <<'EOF'
---
- name: Desinstalacion completa de componentes Caldera
  hosts: caldera_target
  become: true
  tasks:
    - name: 1. Detener y deshabilitar servicios (Servidor y Agente)
      systemd:
        name: "{{ item }}"
        state: stopped
        enabled: false
      loop:
        - caldera
        - caldera-agent
      ignore_errors: true

    - name: 2. Matar procesos residuales (Python server y binarios Sandcat)
      shell: |
        pkill -9 -f "server.py" || true
        pkill -9 -f "sandcat" || true
        pkill -9 -f "splunkd" || true
      ignore_errors: true
      changed_when: false

    - name: 3. Eliminar archivos de servicio systemd
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /etc/systemd/system/caldera.service
        - /etc/systemd/system/caldera-agent.service

    - name: 4. Eliminar directorios de instalacion (Servidor y Agente)
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /opt/caldera
        - /home/{{ ansible_user }}/caldera
        - /usr/local/bin/sandcat
        - /usr/local/bin/splunkd
        - /usr/local/bin/sandcat_paw

    - name: 5. Recargar daemon-reload
      systemd:
        daemon_reload: true

    - name: 6. Limpiar sudoers de Ansible
      file:
        path: /etc/sudoers.d/ansible_nopasswd
        state: absent
EOF

# --- 6. EJECUCION DE ANSIBLE ---
echo "Iniciando purga de Caldera en $INSTANCE_NAME ($TARGET_IP)"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/caldera-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

# --- 7. LIMPIEZA FINAL ---
rm -rf "$TEMP_WORK_DIR"

echo "Proceso de desinstalacion de Caldera finalizado en $INSTANCE_NAME"