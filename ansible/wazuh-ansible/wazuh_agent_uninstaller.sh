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

# 1. Generar Inventario
cat > "$BASE_DIR/hosts.ini" <<EOF
[victim]
$VICTIM_IP ansible_user=debian ansible_ssh_private_key_file=$SSH_KEY

[manager]
$MANAGER_IP ansible_user=ubuntu ansible_ssh_private_key_file=$SSH_KEY
EOF

# 2. Crear el Playbook Profesional Blindado
cat > "$BASE_DIR/uninstall_agent_complete.yml" <<'EOF'
---
- name: Desinstalación Forense y Limpieza de Identidad
  hosts: victim
  become: true
  vars:
    # Usamos búsqueda insensible a mayúsculas para mayor fiabilidad
    agent_search_name: "victim-3" 

  tasks:
    # --- FASE 1: LIMPIEZA EN LA VÍCTIMA ---
    - name: 1.1 Detener y purgar wazuh-agent
      apt:
        name: wazuh-agent
        state: absent
        purge: true
      ignore_errors: true

    - name: 1.2 Eliminar directorios críticos
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /var/ossec
        - /etc/wazuh-agent

    # --- FASE 2: LIMPIEZA EN EL MANAGER ---
    - name: 2.1 Buscar ID del agente (Insensitive Search)
      # El comando 'manage_agents -l' devuelve una lista. Filtramos por el nombre.
      shell: |
        /var/ossec/bin/manage_agents -l | grep -i "{{ agent_search_name }}" | cut -d',' -f1 | awk '{print $2}' | head -n 1
      delegate_to: "{{ groups['manager'][0] }}"
      register: agent_id
      changed_when: false

    - name: 2.2 Eliminar registro del agente en el Manager
      # Usamos 'expect' o simplemente pasamos el ID al comando de borrado
      # manage_agents no tiene flag -y, así que el ID debe ser exacto.
      shell: |
        /var/ossec/bin/manage_agents -r {{ agent_id.stdout }}
      delegate_to: "{{ groups['manager'][0] }}"
      when: agent_id.stdout != ""
      notify: Reiniciar Wazuh Manager

    - name: 2.3 Borrar base de datos forense residual
      file:
        path: "/var/ossec/queue/db/{{ agent_id.stdout }}.db"
        state: absent
      delegate_to: "{{ groups['manager'][0] }}"
      when: agent_id.stdout != ""

  handlers:
    - name: Reiniciar Wazuh Manager
      systemd:
        name: wazuh-manager
        state: restarted
      delegate_to: "{{ groups['manager'][0] }}"
EOF

# 3. Ejecución
echo "===================================================="
echo " 🚀 INICIANDO LIMPIEZA CRUZADA (VÍCTIMA + MANAGER)"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/uninstall_agent_complete.yml"