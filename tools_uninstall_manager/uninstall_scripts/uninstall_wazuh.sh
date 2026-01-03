#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# WAZUH ALL-IN-ONE UNINSTALLER (INTEGRATED WITH PYTHON MANAGER)
# ============================================================

# --- 1. PARAMETROS RECIBIDOS DESDE EL MANAGER (Python) ---
# $1: instance | $2: ssh_key | $3: target_ip | $4: ssh_user
INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Argumentos insuficientes recibidos de Python."
    exit 1
fi

# --- 2. TRABAJO TEMPORAL ---
CLEAN_NAME="${INSTANCE_NAME// /_}"
TEMP_WORK_DIR="/tmp/ansible_wazuh_server_cleanup_${CLEAN_NAME}"
mkdir -p "$TEMP_WORK_DIR"

# --- 3. GENERACION DE INVENTARIO Y PLAYBOOK ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[wazuh_server]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

cat > "$TEMP_WORK_DIR/wazuh-cleanup.yml" <<'EOF'
---
- name: Desinstalacion completa de Wazuh Stack (Server)
  hosts: wazuh_server
  become: true
  tasks:
    - name: 1. Detener servicios de Wazuh
      systemd:
        name: "{{ item }}"
        state: stopped
        enabled: false
      loop:
        - wazuh-dashboard
        - wazuh-manager
        - wazuh-indexer
        - filebeat
      ignore_errors: true

    - name: 2. Purga de paquetes (apt purge)
      apt:
        name:
          - wazuh-indexer
          - wazuh-manager
          - wazuh-dashboard
          - filebeat
          - wazuh-agent
        state: absent
        purge: true

    - name: 3. Limpieza de dependencias y repositorios
      apt:
        autoremove: true
        purge: true

    - name: 4. Eliminacion de directorios de datos, indices y logs
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /var/ossec
        - /var/lib/wazuh-indexer
        - /etc/wazuh-indexer
        - /etc/wazuh-dashboard
        - /etc/wazuh-manager
        - /etc/filebeat
        - /var/log/wazuh-indexer
        - /var/log/wazuh-dashboard
        - /usr/share/wazuh-indexer
        - /usr/share/wazuh-dashboard

    - name: 5. Eliminacion del repositorio de Wazuh
      file:
        path: "/etc/apt/sources.list.d/wazuh.list"
        state: absent

    - name: 6. Matar procesos Java/OpenSearch residuales
      shell: pkill -9 -f "wazuh|opensearch"
      ignore_errors: true
      changed_when: false

    - name: 7. Limpiar sudoers de Ansible
      file:
        path: /etc/sudoers.d/ansible_nopasswd
        state: absent
EOF

# --- 4. EJECUCION DE ANSIBLE ---
echo "Iniciando desinstalacion profunda de Wazuh Server en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/wazuh-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

# --- 5. LIMPIEZA FINAL ---
rm -rf "$TEMP_WORK_DIR"

echo "Proceso de desinstalacion de Wazuh Server finalizado en $INSTANCE_NAME"