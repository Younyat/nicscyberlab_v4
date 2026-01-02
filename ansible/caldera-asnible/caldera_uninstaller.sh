#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
INSTANCE_NAME="attack 2"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"
TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

echo "===================================================="
echo " 🔥 ELIMINANDO CALDERA DE $INSTANCE_NAME"
echo "===================================================="

ansible-playbook -i "$TARGET_IP," -u "$SSH_USER" --private-key "$SSH_KEY" \
    --ssh-common-args='-o StrictHostKeyChecking=no' --become <<'EOF'
---
- name: Borrado de Caldera
  hosts: all
  tasks:
    - name: 1. Detener y eliminar servicio
      systemd:
        name: caldera
        state: stopped
        enabled: false
      ignore_errors: true

    - name: 2. Eliminar archivo de servicio
      file:
        path: /etc/systemd/system/caldera.service
        state: absent

    - name: 3. Eliminar directorio de la aplicación
      file:
        path: /opt/caldera
        state: absent

    - name: 4. Limpiar daemon-reload
      systemd:
        daemon_reload: true
EOF

echo " ✅ CALDERA ELIMINADO"