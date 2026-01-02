#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
INSTANCE_NAME="Wazuh-Server-Single"
SSH_USER="ubuntu"
SSH_KEY="$HOME/.ssh/my_key"
TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

echo "===================================================="
echo " 🔥 ELIMINANDO ZEEK DE $INSTANCE_NAME"
echo "===================================================="

ansible-playbook -i "$TARGET_IP," -u "$SSH_USER" --private-key "$SSH_KEY" \
    --ssh-common-args='-o StrictHostKeyChecking=no' --become <<'EOF'
---
- name: Borrado Total de Zeek
  hosts: all
  tasks:
    - name: 1. Detener Zeek
      command: /opt/zeek/bin/zeekctl stop
      ignore_errors: true

    - name: 2. Eliminar paquete
      apt:
        name: zeek*
        state: absent
        purge: true

    - name: 3. Eliminar archivos y logs
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /opt/zeek
        - /etc/apt/sources.list.d/network:zeek.list
        - /etc/apt/trusted.gpg.d/network_zeek.gpg

    - name: 4. Limpiar dependencias
      apt:
        autoremove: true
        purge: true
EOF

echo " ✅ ZEEK ELIMINADO"