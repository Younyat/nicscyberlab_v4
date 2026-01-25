#!/usr/bin/env bash
# Ubicación: /home/younes/nicscyberlab_v3/tools-installer/scripts/install_wazuh_agent.sh
set -euo pipefail

# --- 1. PARÁMETROS RECIBIDOS DEL MASTER ---
# El Master envía estos argumentos automáticamente
VICTIM_IP="${1:-}"
SSH_USER_VICTIM="${2:-debian}" 
SSH_KEY="$HOME/.ssh/my_key"
WAZUH_VERSION="4.7.3"


if [[ -z "$VICTIM_IP" ]]; then 
    echo " [ERROR] No se recibió la IP de la víctima desde el Master."
    exit 1
fi

# --- 2. BÚSQUEDA DINÁMICA DEL MANAGER (OPENSTACK) ---
# Aprovechamos que el Master ya hizo el 'source admin-openrc.sh'
echo " [INFO] Localizando Manager Wazuh en OpenStack..."
MONITOR_DATA=$(openstack server list --name "monitor" -f json | jq -r '.[0] // empty')

if [[ -z "$MONITOR_DATA" ]]; then
    echo " [WARN] No se encontró instancia 'monitor'. Usando IP de respaldo."
    MANAGER_IP="10.0.2.160"
else
    MANAGER_IP=$(echo "$MONITOR_DATA" | jq -r '.Networks' | grep -oP '\d+\.\d+\.\d+\.\d+' | head -n 1)
    echo " [OK] Manager detectado en: $MANAGER_IP"
fi

# --- 3. PREPARACIÓN DE ANSIBLE (ENTORNO LOCAL) ---
# Creamos carpetas únicas por IP para evitar colisiones si ejecutas varios a la vez
BASE_DIR="$HOME/ansible/wazuh-agent-$VICTIM_IP"
mkdir -p "$BASE_DIR"

# Generar Inventario dinámico
cat > "$BASE_DIR/hosts.ini" <<EOF
[victim]
$VICTIM_IP ansible_user=$SSH_USER_VICTIM ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_extra_args='-o StrictHostKeyChecking=no'
EOF

# Generar Playbook con tu lógica de limpieza

cat > "$BASE_DIR/install_agent.yml" <<EOF
---
- name: "Instalación Limpia de Wazuh Agent"
  hosts: victim
  become: true
  tasks:
    - name: "Limpieza radical de versiones previas"
      shell: |
        systemctl stop wazuh-agent || true
        apt-get purge -y wazuh-agent || true
        rm -rf /var/ossec
        rm -rf /etc/wazuh-agent
      args: { executable: /bin/bash }

    - name: "Instalar dependencias necesarias"
      apt:
        name: [ 'curl', 'apt-transport-https', 'gnupg' ]
        state: present
        update_cache: yes

    - name: "Añadir llave GPG de Wazuh"
      apt_key:
        url: https://packages.wazuh.com/key/GPG-KEY-WAZUH
        state: present

    - name: "Añadir repositorio de Wazuh"
      apt_repository:
        repo: "deb https://packages.wazuh.com/4.x/apt/ stable main"
        state: present

    - name: "Instalar Wazuh Agent v$WAZUH_VERSION"
      apt:
        name: "wazuh-agent=$WAZUH_VERSION-1"
        state: present
        update_cache: yes
        force: yes

    - name: "Vincular con Manager $MANAGER_IP"
      lineinfile:
        path: /var/ossec/etc/ossec.conf
        regexp: '<address>.*</address>'
        line: "      <address>$MANAGER_IP</address>"

    - name: "Reiniciar y habilitar servicio"
      systemd: { name: wazuh-agent, state: restarted, enabled: true, daemon_reload: true }
EOF

# --- 4. EJECUCIÓN ---
echo " [INFO] Lanzando Ansible-Playbook..."
export ANSIBLE_HOST_KEY_CHECKING=False

# Si el playbook tiene éxito, el script termina con éxito (exit 0)
# Si falla, termina con error (exit 1) y el Master marcará "error" en el JSON
if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/install_agent.yml"; then
    echo " [SUCCESS] Proceso de Ansible completado para $VICTIM_IP."
    exit 0
else
    echo " [ERROR] Falló la ejecución de Ansible."
    exit 1
fi