#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  CALDERA SERVER INSTALLER - ROBUST VERSION (No emojis)
#  Integra: Fix de Magma (npm), Health Checks y PEP 668
# ============================================================

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="caldera_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No se proporciono la IP de destino."
    exit 1
fi

TEMP_WORK_DIR="/tmp/ansible_caldera_$INSTANCE_ID"
mkdir -p "$TEMP_WORK_DIR"

# --- 1. GENERACION DE INVENTARIO ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[caldera_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

# --- 2. PLAYBOOK MEJORADO CON TU LOGICA ---
cat > "$TEMP_WORK_DIR/caldera-install.yml" <<'EOF'
---
- name: Instalacion Robusta de MITRE Caldera
  hosts: caldera_host
  become: true
  tasks:
    - name: 1. Instalar dependencias base y Node.js 20
      shell: |
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y python3 python3-pip git build-essential nodejs libmagic-dev jq
      args:
        executable: /bin/bash

    - name: 2. Clonar Caldera recursivamente
      git:
        repo: 'https://github.com/mitre/caldera.git'
        dest: /opt/caldera
        version: 'master'
        recursive: yes
        force: yes

    - name: 3. Corregir dependencias de Magma (npm)
      shell: |
        cd /opt/caldera/plugins/magma
        npm install vite@2.9.15 @vitejs/plugin-vue@2.3.4 vue@3.2.45 --legacy-peer-deps
      args:
        executable: /bin/bash

    - name: 4. Instalar requisitos Python (Fix PEP 668)
      pip:
        requirements: /opt/caldera/requirements.txt
        executable: pip3
        extra_args: --break-system-packages

    - name: 5. Configurar Servicio con Health Check
      copy:
        dest: /etc/systemd/system/caldera.service
        content: |
          [Unit]
          Description=MITRE Caldera (Robust Mode)
          After=network.target

          [Service]
          User=root
          WorkingDirectory=/opt/caldera
          ExecStart=/usr/bin/python3 server.py --insecure --build
          Restart=always
          RestartSec=10

          [Install]
          WantedBy=multi-user.target

    - name: 6. Iniciar y esperar puerto 8888
      systemd:
        name: caldera
        state: restarted
        enabled: true
        daemon_reload: true

    - name: 7. Validacion de disponibilidad HTTP
      uri:
        url: "http://127.0.0.1:8888"
        status_code: 200
      register: result
      until: result.status == 200
      retries: 30
      delay: 10
EOF

echo "===================================================="
echo " EJECUTANDO DESPLIEGUE ROBUSTO EN: $TARGET_IP"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/caldera-install.yml"; then
    echo "----------------------------------------------------"
    echo " CALDERA INSTALADO Y VALIDADO"
    echo " URL: http://$TARGET_IP:8888"
    echo "----------------------------------------------------"
else
    echo " ERROR critico en la instalacion."
    exit 1
fi

rm -rf "$TEMP_WORK_DIR"