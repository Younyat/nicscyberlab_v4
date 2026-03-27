#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="mbpoll_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No se proporciono la IP de destino."
    exit 1
fi

BASE_DIR="/tmp/ansible_mbpoll_$INSTANCE_ID"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[mbpoll_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/mbpoll-install.yml" <<'EOF'
---
- name: Instalar mbpoll
  hosts: mbpoll_host
  become: true
  tasks:
    - name: Actualizar cache de apt
      apt:
        update_cache: true

    - name: Instalar mbpoll
      apt:
        name: mbpoll
        state: present

    - name: Validar instalacion
      command: mbpoll -h
      register: mbpoll_help
      changed_when: false

    - name: Mostrar resultado
      debug:
        msg: "mbpoll instalado correctamente"
EOF

echo "===================================================="
echo " INSTALANDO MBPOLL"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/mbpoll-install.yml"; then
    echo "----------------------------------------------------"
    echo "  MBPOLL INSTALADO CON EXITO"
    echo "----------------------------------------------------"
else
    echo "  Fallo en la instalacion de mbpoll"
    exit 1
fi

rm -rf "$BASE_DIR"