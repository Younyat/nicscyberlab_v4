#!/usr/bin/env bash
set -euo pipefail

# --- CONFIG ---
SSH_USER_VICTIM="debian"
SSH_KEY="$HOME/.ssh/my_key"
WAZUH_VERSION="4.7.3"
VICTIM_IP="10.0.2.23"
MANAGER_IP="10.0.2.160"

BASE_DIR="$HOME/ansible/wazuh-agent-pro"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[victim]
$VICTIM_IP ansible_user=$SSH_USER_VICTIM ansible_ssh_private_key_file=$SSH_KEY
EOF

cat > "$BASE_DIR/install_agent.yml" <<EOF
---
- name: "Reinstalación Total Limpia de Wazuh Agent"
  hosts: victim
  become: true
  tasks:
    - name: "1. ELIMINACIÓN RADICAL (Limpieza total de restos de v4.9)"
      shell: |
        systemctl stop wazuh-agent || true
        apt-get purge -y wazuh-agent || true
        rm -rf /var/ossec
        rm -rf /etc/wazuh-agent
      args:
        executable: /bin/bash

    - name: "2. Re-importar GPG"
      apt_key:
        url: https://packages.wazuh.com/key/GPG-KEY-WAZUH
        state: present

    - name: "3. Añadir repositorio oficial"
      apt_repository:
        repo: "deb https://packages.wazuh.com/4.x/apt/ stable main"
        state: present

    - name: "4. Instalación limpia de versión $WAZUH_VERSION"
      apt:
        name: "wazuh-agent=$WAZUH_VERSION-1"
        state: present
        update_cache: true

    - name: "5. Configurar IP del Manager en ossec.conf"
      lineinfile:
        path: /var/ossec/etc/ossec.conf
        regexp: '<address>.*</address>'
        line: "      <address>$MANAGER_IP</address>"

    - name: "6. Iniciar Servicio"
      systemd:
        name: wazuh-agent
        state: started
        enabled: true
        daemon_reload: true

    - name: "7. VERIFICACIÓN: Comprobar si el proceso está en ejecución"
      shell: ps aux | grep wazuh-agentd | grep -v grep
      register: ps_check

    - name: "8. Mostrar resultado del proceso"
      debug:
        msg: "Proceso levantado: {{ ps_check.stdout }}"
EOF

echo "===================================================="
echo " 🔥 EJECUTANDO REINSTALACIÓN LIMPIA (BORRADO TOTAL)"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/install_agent.yml"