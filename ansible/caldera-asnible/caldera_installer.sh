#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
INSTANCE_NAME="attack 2" # Recomendado instalarlo en el server de gestión
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"
BASE_DIR="$HOME/ansible/caldera-auto"

echo "===================================================="
echo " [1/3] PREPARANDO ENTORNO PARA MITRE CALDERA"
echo "===================================================="

TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [[ -z "${TARGET_IP:-}" ]]; then
  echo "ERROR: No se encontró IP para $INSTANCE_NAME"
  exit 1
fi

mkdir -p "$BASE_DIR"/{inventory,playbooks}

# Generar Inventario
cat > "$BASE_DIR/inventory/hosts.ini" <<EOF
[caldera_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

echo "[2/3] CREANDO PLAYBOOK DE CALDERA"

cat > "$BASE_DIR/playbooks/caldera-install.yml" <<'EOF'
---
- name: Instalación de MITRE Caldera
  hosts: caldera_host
  become: true
  tasks:
    - name: 1. Instalar dependencias de sistema y Python
      apt:
        name: [python3, python3-pip, git, python3-venv, build-essential]
        state: present
        update_cache: true

    - name: 2. Clonar repositorio de Caldera (Recursivo)
      git:
        repo: 'https://github.com/mitre/caldera.git'
        dest: /opt/caldera
        version: 'v5.0.0' # Versión estable
        recursive: yes
        force: yes

    - name: 3. Instalar requerimientos de Python
      pip:
        requirements: /opt/caldera/requirements.txt
        executable: pip3

    - name: 4. Crear servicio Systemd para Caldera
      copy:
        dest: /etc/systemd/system/caldera.service
        content: |
          [Unit]
          Description=MITRE Caldera Adversary Emulation
          After=network.target

          [Service]
          User=root
          WorkingDirectory=/opt/caldera
          ExecStart=/usr/bin/python3 server.py --insecure
          Restart=always

          [Install]
          WantedBy=multi-user.target

    - name: 5. Iniciar y habilitar servicio
      systemd:
        name: caldera
        state: restarted
        enabled: true
        daemon_reload: true

    - name: 6. Esperar a que el puerto 8888 esté abierto
      wait_for:
        port: 8888
        delay: 5
        timeout: 60
EOF

echo "[3/3] EJECUTANDO ANSIBLE"
ansible-playbook -i "$BASE_DIR/inventory/hosts.ini" "$BASE_DIR/playbooks/caldera-install.yml"

echo "===================================================="
echo " ✅ CALDERA INSTALADO"
echo " URL      : http://$TARGET_IP:8888"
echo " Login    : Ver conf/default.yml (usualmente admin/admin)"
echo "===================================================="