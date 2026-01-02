#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
INSTANCE_NAME="attack 2"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

# Obtener la IP de la instancia
echo "🔍 Obteniendo IP de la instancia: $INSTANCE_NAME..."
TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

# Verificar si se obtuvo una IP
if [ -z "$TARGET_IP" ]; then
    echo "❌ Error: No se pudo encontrar la IP para la instancia $INSTANCE_NAME"
    exit 1
fi

echo "===================================================="
echo " 🔥 ELIMINANDO NMAP DE $INSTANCE_NAME ($TARGET_IP)"
echo "===================================================="

# Se añade /dev/stdin al final para que Ansible acepte el bloque EOF
ansible-playbook -i "$TARGET_IP," -u "$SSH_USER" --private-key "$SSH_KEY" \
    --ssh-common-args='-o StrictHostKeyChecking=no' --become /dev/stdin <<'EOF'
---
- name: Borrado de Nmap
  hosts: all
  tasks:
    - name: 1. Eliminar paquetes de Nmap
      apt:
        name: 
          - nmap
          - ncat
          - ndiff
        state: absent
        purge: true

    - name: 2. Limpiar dependencias y archivos huérfanos
      apt:
        autoremove: true
        purge: true
EOF

echo "===================================================="
echo " ✅ PROCESO FINALIZADO"
echo "===================================================="