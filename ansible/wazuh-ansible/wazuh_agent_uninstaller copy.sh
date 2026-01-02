#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
VICTIM_NAME="victim 3"
MANAGER_NAME="Wazuh-Server-Single"
SSH_KEY="$HOME/.ssh/my_key"

BASE_DIR="$HOME/ansible/wazuh-agent-cleanup"
mkdir -p "$BASE_DIR"

echo "===================================================="
echo " 🕵️ DETECTANDO IPS EN EL ENTORNO"
echo "===================================================="

VICTIM_IP=$(openstack server show "$VICTIM_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)
MANAGER_IP=$(openstack server show "$MANAGER_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

echo "Víctima (Agente): $VICTIM_IP"
echo "Manager (Servidor): $MANAGER_IP"

# 1. Generar Inventario Temporal
cat > "$BASE_DIR/hosts.ini" <<EOF
[victim]
$VICTIM_IP ansible_user=debian ansible_ssh_private_key_file=$SSH_KEY

[manager]
$MANAGER_IP ansible_user=ubuntu ansible_ssh_private_key_file=$SSH_KEY
EOF

# 2. Crear el Playbook Profesional
cat > "$BASE_DIR/uninstall_agent_complete.yml" <<'EOF'
---
- name: Desinstalación Profesional y Completa de Wazuh Agent
  hosts: victim
  become: true
  vars:
    agent_name: "Victim-3" # Nombre como aparece en el Dashboard

  tasks:
    # --- FASE 1: LIMPIEZA EN LA VÍCTIMA ---
    - name: 1.1 Detener y purgar el paquete wazuh-agent
      apt:
        name: wazuh-agent
        state: absent
        purge: true

    - name: 1.2 Eliminar restos de directorios /var/ossec
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /var/ossec
        - /var/log/wazuh-agent
        - /etc/wazuh-agent

    - name: 1.3 Limpiar usuarios y grupos de Wazuh
      user:
        name: wazuh
        state: absent
        remove: yes
      ignore_errors: true

    # --- FASE 2: ELIMINACIÓN EN EL MANAGER (Delegado) ---
    - name: 2.1 Obtener ID del agente en el Manager
      shell: |
        /var/ossec/bin/manage_agents -l | grep -w "{{ agent_name }}" | cut -d',' -f1 | awk '{print $2}'
      delegate_to: "{{ groups['manager'][0] }}"
      remote_user: ubuntu
      register: agent_id
      changed_when: false
      become: true

    - name: 2.2 Eliminar agente del Manager si existe
      shell: |
        /var/ossec/bin/manage_agents -r {{ agent_id.stdout }}
      delegate_to: "{{ groups['manager'][0] }}"
      remote_user: ubuntu
      when: agent_id.stdout != ""
      become: true
      notify: Reiniciar Wazuh Manager

    - name: 2.3 Forzar borrado de base de datos del agente en Manager
      file:
        path: "/var/ossec/queue/db/{{ agent_id.stdout }}.db"
        state: absent
      delegate_to: "{{ groups['manager'][0] }}"
      remote_user: ubuntu
      when: agent_id.stdout != ""
      become: true

  handlers:
    - name: Reiniciar Wazuh Manager
      systemd:
        name: wazuh-manager
        state: restarted
      delegate_to: "{{ groups['manager'][0] }}"
      remote_user: ubuntu
EOF

# 3. Ejecutar Ansible
echo "===================================================="
echo " 🚀 INICIANDO DESINSTALACIÓN CRUZADA"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/uninstall_agent_complete.yml"

echo "===================================================="
echo " ✅ AGENTE ELIMINADO DE LA VÍCTIMA Y DEL MANAGER"
echo "===================================================="