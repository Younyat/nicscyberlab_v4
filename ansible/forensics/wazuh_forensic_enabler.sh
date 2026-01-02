#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
MANAGER_IP="10.0.2.160"
VICTIM_IP="10.0.2.23"
SSH_KEY="$HOME/.ssh/my_key"

BASE_DIR=$(pwd)
mkdir -p "$BASE_DIR"

# 1. Generar Inventario
cat > "$BASE_DIR/hosts.ini" <<EOF
[manager]
$MANAGER_IP ansible_user=ubuntu ansible_ssh_private_key_file=$SSH_KEY
[victim]
$VICTIM_IP ansible_user=debian ansible_ssh_private_key_file=$SSH_KEY
EOF

# 2. Crear el Playbook de Reparación y Activación
cat > "$BASE_DIR/fix_forensics.yml" <<'EOF'
---
- name: "Activación de Capacidades Forenses"
  hosts: all
  become: true
  tasks:
    # --- ARREGLO EN EL MANAGER (MONITOR) ---
    - name: "MANAGER: Activar Logall y Logall_JSON"
      lineinfile:
        path: /var/ossec/etc/ossec.conf
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '<logall>.*</logall>', line: '    <logall>yes</logall>' }
        - { regexp: '<logall_json>.*</logall_json>', line: '    <logall_json>yes</logall_json>' }
      when: "'manager' in group_names"
      notify: Restart Manager

    # --- ARREGLO EN LA VÍCTIMA ---
    - name: "VÍCTIMA: Instalar Auditd"
      apt:
        name: auditd
        state: present
        update_cache: true
      when: "'victim' in group_names"

    - name: "VÍCTIMA: Configurar reglas de auditoría de comandos"
      blockinfile:
        path: /etc/audit/rules.d/forensics.rules
        create: yes
        block: |
          -a always,exit -F arch=b64 -S execve -k forensic_cmds
          -w /etc/shadow -p wa -k forensic_shadow
      when: "'victim' in group_names"
      notify: Restart Auditd

    - name: "VÍCTIMA: Configurar Wazuh para leer logs de Auditd"
      blockinfile:
        path: /var/ossec/etc/ossec.conf
        insertafter: '<ossec_config>'
        block: |
          <localfile>
            <log_format>audit</log_format>
            <location>/var/log/audit/audit.log</location>
          </localfile>
      when: "'victim' in group_names"
      notify: Restart Agent

  handlers:
    - name: Restart Manager
      systemd: { name: wazuh-manager, state: restarted }
    - name: Restart Agent
      systemd: { name: wazuh-agent, state: restarted }
    - name: Restart Auditd
      service: { name: auditd, state: restarted }
EOF

# 3. Ejecución
echo "===================================================="
echo " 🛠️ APLICANDO CONFIGURACIÓN FORENSE (FIX)"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/fix_forensics.yml"