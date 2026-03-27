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

  tasks:
    - name: 1. Eliminar bloque NICS_SURICATA de ossec.conf
      blockinfile:
        path: "{{ remote_ossec }}"
        marker: "<!-- {mark} -->"
        marker_begin: "NICS_SURICATA_BEGIN"
        marker_end: "NICS_SURICATA_END"
        state: absent

    - name: 2. Reiniciar wazuh-agent
      service:
        name: wazuh-agent
        state: restarted

    - name: 3. Verificar que wazuh-agent sigue activo
      command: systemctl is-active wazuh-agent
      register: wazuh_status
      changed_when: false
      failed_when: wazuh_status.stdout.strip() != "active"

    - name: 4. Mostrar resultado final
      debug:
        msg: "Integracion Wazuh + Suricata eliminada correctamente"
EOF

echo "Iniciando rollback de integracion Wazuh + Suricata en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/wazuh-suricata-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

rm -rf "$TEMP_WORK_DIR"
echo "Proceso de rollback Wazuh + Suricata finalizado en $INSTANCE_NAME"