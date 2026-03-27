#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  MBPOLL UNINSTALLER
# ============================================================

INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$SSH_KEY" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Uso: $0 <INSTANCE_NAME> <SSH_KEY> <TARGET_IP> <SSH_USER>"
    exit 1
fi

TEMP_WORK_DIR="/tmp/ansible_mbpoll_cleanup_${INSTANCE_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$TEMP_WORK_DIR/mbpoll-cleanup.yml" <<'EOF'
---
- name: Desinstalacion completa de mbpoll
  hosts: target
  become: true
  tasks:
    - name: 1. Comprobar si mbpoll esta instalado
      command: dpkg -s mbpoll
      register: mbpoll_installed
      failed_when: false
      changed_when: false

    - name: 2. Purgar paquete mbpoll
      apt:
        name: mbpoll
        state: absent
        purge: true
      when: mbpoll_installed.rc == 0

    - name: 3. Limpieza final de APT
      apt:
        autoremove: true
        autoclean: true

    - name: 4. Verificar que mbpoll ya no existe
      shell: command -v mbpoll
      register: mbpoll_check
      failed_when: false
      changed_when: false

    - name: 5. Mostrar resultado final
      debug:
        msg: >-
          mbpoll desinstalado correctamente
      when: mbpoll_check.rc != 0

    - name: 6. Avisar si sigue presente
      debug:
        msg: >-
          Advertencia: mbpoll sigue presente en el sistema
      when: mbpoll_check.rc == 0
EOF

echo "Iniciando desinstalacion de mbpoll en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/mbpoll-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

rm -rf "$TEMP_WORK_DIR"
echo "Proceso de desinstalacion de mbpoll finalizado en $INSTANCE_NAME"