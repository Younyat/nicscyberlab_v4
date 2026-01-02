#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH ALL-IN-ONE UNINSTALLER (TOTAL CLEANUP)
# ============================================================

# --- CONFIGURACIÓN (Debe coincidir con tu instalador) ---
INSTANCE_NAME="Wazuh-Server-Single"
SSH_USER="ubuntu"
SSH_KEY="$HOME/.ssh/my_key"
BASE_DIR="$HOME/ansible/wazuh-auto"

echo "===================================================="
echo " [1/3] DETECTANDO INSTANCIA WAZUH"
echo "===================================================="

TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: No se pudo encontrar la IP para $INSTANCE_NAME"
    exit 1
fi

echo "IP detectada para limpieza: $TARGET_IP"

# 1. Crear Playbook de desinstalación
echo "[2/3] Generando Playbook de desinstalación total..."
mkdir -p "$BASE_DIR/playbooks"

cat > "$BASE_DIR/playbooks/wazuh-cleanup.yml" <<'EOF'
---
- name: Desinstalación completa de Wazuh Stack
  hosts: all
  become: true
  tasks:
    - name: 1. Detener todos los servicios de Wazuh
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

    - name: 2. Eliminar paquetes y configuraciones (Purge)
      apt:
        name:
          - wazuh-indexer
          - wazuh-manager
          - wazuh-dashboard
          - filebeat
          - wazuh-agent
        state: absent
        purge: true

    - name: 3. Limpiar dependencias y repositorios
      apt:
        autoremove: true
        purge: true

    - name: 4. Eliminar directorios de datos, certificados y logs
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /var/ossec                # Core de Wazuh Manager
        - /var/lib/wazuh-indexer    # Datos de los índices (Base de datos)
        - /etc/wazuh-indexer
        - /etc/wazuh-dashboard
        - /etc/wazuh-manager
        - /etc/filebeat
        - /var/log/wazuh-indexer
        - /var/log/wazuh-dashboard
        - /usr/share/wazuh-indexer
        - /usr/share/wazuh-dashboard

    - name: 5. Eliminar el repositorio de Wazuh de las listas de APT
      file:
        path: "/etc/apt/sources.list.d/wazuh.list"
        state: absent

    - name: 6. Matar procesos Java residuales (Indexer/Dashboard)
      shell: pkill -9 -f "wazuh|opensearch"
      ignore_errors: true
      changed_when: false

    - name: 7. Limpiar reglas de sudoers de Ansible
      file:
        path: /etc/sudoers.d/ansible_nopasswd
        state: absent

    - name: Finalizado
      debug:
        msg: "Limpieza profunda de Wazuh completada en el servidor."
EOF

# 2. Ejecutar la desinstalación
echo "[3/3] Ejecutando limpieza con Ansible..."
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TARGET_IP," -u "$SSH_USER" --private-key "$SSH_KEY" \
    --ssh-common-args='-o StrictHostKeyChecking=no' \
    "$BASE_DIR/playbooks/wazuh-cleanup.yml"

echo "===================================================="
echo " ✅ WAZUH HA SIDO ELIMINADO COMPLETAMENTE"
echo "===================================================="
echo " Servidor: $INSTANCE_NAME ($TARGET_IP)"
echo " Estado  : Limpio (Paquetes, datos y logs borrados)"
echo "===================================================="