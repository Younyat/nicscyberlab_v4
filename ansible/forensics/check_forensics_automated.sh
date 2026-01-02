#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
MANAGER_IP="10.0.2.160"
VICTIM_IP="10.0.2.23"
SSH_KEY="$HOME/.ssh/my_key"

BASE_DIR="$HOME/ansible/forensics-check"
mkdir -p "$BASE_DIR"

# 1. Generar Inventario Temporal
cat > "$BASE_DIR/hosts.ini" <<EOF
[manager]
$MANAGER_IP ansible_user=ubuntu ansible_ssh_private_key_file=$SSH_KEY

[victim]
$VICTIM_IP ansible_user=debian ansible_ssh_private_key_file=$SSH_KEY
EOF

# 2. Crear el Playbook de Auditoría
cat > "$BASE_DIR/audit_script.yml" <<'EOF'
---
- name: "Auditoría de Configuración Forense"
  hosts: all
  become: true
  gather_facts: no
  tasks:
    # --- PRUEBAS EN EL MANAGER ---
    - name: "Checking Manager Config"
      block:
        - shell: "grep -P '<logall>yes</logall>' /var/ossec/etc/ossec.conf"
          register: check_logall
          ignore_errors: true
        - shell: "grep -P '<logall_json>yes</logall_json>' /var/ossec/etc/ossec.conf"
          register: check_json
          ignore_errors: true
      when: "'manager' in group_names"

    # --- PRUEBAS EN LA VÍCTIMA ---
    - name: "Checking Victim Config"
      block:
        - shell: "dpkg -l | grep auditd"
          register: check_auditd_pkg
          ignore_errors: true
        - shell: "systemctl is-active auditd"
          register: check_auditd_svc
          ignore_errors: true
        - shell: "grep '/var/log/audit/audit.log' /var/ossec/etc/ossec.conf"
          register: check_wazuh_audit
          ignore_errors: true
      when: "'victim' in group_names"

    # --- REPORTE ---
    - name: "Generar Reporte"
      debug:
        msg:
          - "=========================================="
          - "RESULTADOS PARA: {{ inventory_hostname }}"
          - "=========================================="
          - "MANAGER - Guardado de logs (Logall): {{ 'OK (Activo)' if (check_logall is defined and check_logall.rc == 0) else 'FAIL (Inactivo)' }}"
          - "MANAGER - Formato JSON Forense: {{ 'OK (Activo)' if (check_json is defined and check_json.rc == 0) else 'FAIL (Inactivo)' }}"
          - "VÍCTIMA - Auditd Instalado: {{ 'OK' if (check_auditd_pkg is defined and check_auditd_pkg.rc == 0) else 'FAIL' }}"
          - "VÍCTIMA - Auditd Corriendo: {{ 'OK' if (check_auditd_svc is defined and check_auditd_svc.rc == 0) else 'FAIL' }}"
          - "VÍCTIMA - Enlace Wazuh <-> Auditd: {{ 'OK' if (check_wazuh_audit is defined and check_wazuh_audit.rc == 0) else 'FAIL' }}"
EOF

# 3. Ejecución
echo "===================================================="
echo " 🔍 INICIANDO AUDITORÍA FORENSE AUTOMATIZADA"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/audit_script.yml"