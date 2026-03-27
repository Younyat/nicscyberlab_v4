#!/usr/bin/env bash
# Ubicación: /home/younes/nicscyberlab_v3/tools-installer/scripts/install_wazuh_agent.sh
set -euo pipefail

# ============================================================
#  WAZUH AGENT INSTALLER - REPAIR & AUTO-CLEAN VERSION
# ============================================================

# --- 1. PARÁMETROS RECIBIDOS DEL MASTER ---
VICTIM_IP="${1:-}"
SSH_USER_VICTIM="${2:-debian}" 
SSH_KEY="$HOME/.ssh/my_key"
WAZUH_VERSION="4.7.3"
W_PASS="admin" 

if [[ -z "$VICTIM_IP" ]]; then 
    echo " [ERROR] No se recibió la IP de la víctima desde el Master."
    exit 1
fi

# --- 2. BÚSQUEDA DINÁMICA DEL MANAGER (OPENSTACK) ---
echo " [INFO] Localizando Manager Wazuh en OpenStack..."
MONITOR_DATA=$(openstack server list --name "monitor" -f json | jq -r '.[0] // empty')

if [[ -z "$MONITOR_DATA" ]]; then
    echo " [WARN] No se encontró instancia 'monitor'. Usando IP de respaldo."
    MANAGER_IP="10.0.2.136"
else
    MANAGER_IP=$(echo "$MONITOR_DATA" | jq -r '.Networks' | grep -oP '\d+\.\d+\.\d+\.\d+' | head -n 1)
    echo " [OK] Manager detectado en: $MANAGER_IP"
fi

# --- 3. LIMPIEZA PREVENTIVA EN EL MANAGER (EVITA AXIOS ERROR) ---
echo " [INFO] Eliminando registros antiguos en el Manager para evitar conflictos de ID..."
# Buscamos el ID dinámicamente para no depender de 001 o 002
OLD_AGENT_ID=$(ssh -i "$SSH_KEY" "ubuntu@$MANAGER_IP" "sudo /var/ossec/bin/manage_agents -l" | grep -i "victim" | cut -d',' -f1 | cut -d' ' -f4 || echo "")

if [[ ! -z "$OLD_AGENT_ID" ]]; then
    echo " [FIX] Borrando agente antiguo ID: $OLD_AGENT_ID"
    ssh -i "$SSH_KEY" "ubuntu@$MANAGER_IP" "sudo /var/ossec/bin/manage_agents -r $OLD_AGENT_ID"
    # Reiniciamos el Manager para que la API no busque bases de datos inexistentes
    ssh -i "$SSH_KEY" "ubuntu@$MANAGER_IP" "sudo systemctl restart wazuh-manager"
    sleep 5
fi

# --- 4. PREPARACIÓN DE ANSIBLE (ENTORNO LOCAL) ---
BASE_DIR="$HOME/ansible/wazuh-agent-$VICTIM_IP"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[victim]
$VICTIM_IP ansible_user=$SSH_USER_VICTIM ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_extra_args='-o StrictHostKeyChecking=no'
EOF

# --- 5. GENERAR PLAYBOOK ---
cat > "$BASE_DIR/install_agent.yml" <<EOF
---
- name: "Instalación y Configuración Completa de Wazuh Agent"
  hosts: victim
  become: true
  tasks:
    - name: "Limpieza radical de instalaciones previas"
      shell: |
        systemctl stop wazuh-agent || true
        apt-get purge -y wazuh-agent || true
        rm -rf /var/ossec
        rm -rf /etc/wazuh-agent
      args: { executable: /bin/bash }

    - name: "Instalar dependencias y repositorios"
      shell: |
        apt-get update
        apt-get install -y curl apt-transport-https gnupg
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
        apt-get update
      args: { executable: /bin/bash }

    - name: "Instalar Wazuh Agent v$WAZUH_VERSION"
      apt:
        name: "wazuh-agent=$WAZUH_VERSION-1"
        state: present
        force: yes

    - name: "Configurar conexión con el Manager"
      lineinfile:
        path: /var/ossec/etc/ossec.conf
        regexp: '<address>.*</address>'
        line: "      <address>$MANAGER_IP</address>"

    - name: "Configurar recolección de logs"
      blockinfile:
        path: /var/ossec/etc/ossec.conf
        insertbefore: "</ossec_config>"
        marker: ""
        block: |
          <localfile>
            <log_format>syslog</log_format>
            <location>/var/log/auth.log</location>
          </localfile>
          <localfile>
            <log_format>syslog</log_format>
            <location>/var/log/syslog</location>
          </localfile>

    - name: "Enrolamiento Activo"
      shell: "/var/ossec/bin/agent-auth -m $MANAGER_IP -P $W_PASS -i -A \$(hostname)"
      ignore_errors: yes

    - name: "Habilitar y reiniciar servicio"
      systemd: 
        name: wazuh-agent 
        state: restarted 
        enabled: true 
        daemon_reload: true
EOF

# --- 6. EJECUCIÓN ---
echo " [INFO] Ejecutando Ansible-Playbook..."
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/install_agent.yml"; then
    echo " [SUCCESS] Agente instalado y Dashboard protegido."
    rm -rf "$BASE_DIR"
    exit 0
else
    echo " [ERROR] Falló la instalación."
    exit 1
fi