#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
INSTANCE_NAME="victim 3"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"
TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

echo "===================================================="
echo " 🔥 DESINSTALANDO SNORT DE $INSTANCE_NAME"
echo "===================================================="

ansible-playbook -i "$TARGET_IP," -u "$SSH_USER" --private-key "$SSH_KEY" \
    --ssh-common-args='-o StrictHostKeyChecking=no' --become <<'EOF'
---
- name: Borrado Total de Snort
  hosts: all
  tasks:
    - name: 1. Detener servicio
      systemd:
        name: snort
        state: stopped
        enabled: false
      ignore_errors: true

    - name: 2. Purgar paquetes
      apt:
        name: snort
        state: absent
        purge: true

    - name: 3. Eliminar directorios residuales
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /etc/snort
        - /var/log/snort
        - /var/lib/snort
        - /etc/default/snort

    - name: 4. Limpiar dependencias
      apt:
        autoremove: true
        purge: true
EOF

echo " ✅ SNORT ELIMINADO COMPLETAMENTE"