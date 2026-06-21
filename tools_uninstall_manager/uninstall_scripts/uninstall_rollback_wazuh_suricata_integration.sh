#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH + SURICATA INTEGRATION ROLLBACK
# ============================================================

INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$SSH_KEY" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Uso: $0 <INSTANCE_NAME> <SSH_KEY> <TARGET_IP> <SSH_USER>"
    exit 1
fi

TEMP_WORK_DIR="/tmp/ansible_wazuh_suricata_cleanup_${INSTANCE_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$TEMP_WORK_DIR/wazuh-suricata-cleanup.yml" <<'EOF'
---
- name: Deshacer integracion Wazuh + Suricata
  hosts: target
  become: true
  vars:
    remote_ossec: /var/ossec/etc/ossec.conf
    remote_local_rules: /var/ossec/etc/rules/local_rules.xml

  tasks:
    - name: 0. Verificar si ossec.conf existe
      stat:
        path: "{{ remote_ossec }}"
      register: ossec_conf_stat

    - name: 0b. Verificar si local_rules.xml existe
      stat:
        path: "{{ remote_local_rules }}"
      register: local_rules_stat

    - name: 1. Eliminar bloque NICS_SURICATA de ossec.conf
      blockinfile:
        path: "{{ remote_ossec }}"
        marker: "<!-- {mark} NICS_SURICATA -->"
        state: absent
      when: ossec_conf_stat.stat.exists

    - name: 1b. Eliminar reglas locales OT Modbus de local_rules.xml
      blockinfile:
        path: "{{ remote_local_rules }}"
        marker: "<!-- {mark} NICS_SURICATA_OT_MODBUS -->"
        state: absent
      when: local_rules_stat.stat.exists

    - name: 2. Reiniciar wazuh-agent si existe ossec.conf
      service:
        name: wazuh-agent
        state: restarted
      register: wazuh_restart
      failed_when: false
      when: ossec_conf_stat.stat.exists

    - name: 3. Verificar que wazuh-agent sigue activo si pudo reiniciarse
      command: systemctl is-active wazuh-agent
      register: wazuh_status
      changed_when: false
      failed_when: wazuh_restart.failed is defined and not wazuh_restart.failed and wazuh_status.stdout.strip() != "active"
      when: ossec_conf_stat.stat.exists

    - name: 4. Mostrar resultado final
      debug:
        msg: >-
          Integracion Wazuh + Suricata eliminada correctamente
          (o ya ausente en el nodo si no habia Wazuh local disponible).
EOF

echo "Iniciando rollback de integracion Wazuh + Suricata en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/wazuh-suricata-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

rm -rf "$TEMP_WORK_DIR"
echo "Proceso de rollback Wazuh + Suricata finalizado en $INSTANCE_NAME"
