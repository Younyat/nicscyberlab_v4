#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  SURICATA ICMP RULE ROLLBACK
# ============================================================

INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$SSH_KEY" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Uso: $0 <INSTANCE_NAME> <SSH_KEY> <TARGET_IP> <SSH_USER>"
    exit 1
fi

TEMP_WORK_DIR="/tmp/ansible_suricata_ping_cleanup_${INSTANCE_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$TEMP_WORK_DIR/suricata-ping-cleanup.yml" <<'EOF'
---
- name: Deshacer regla ICMP personalizada de Suricata
  hosts: target
  become: true
  vars:
    rule_file: /var/lib/suricata/rules/nics-ping.rules
    suricata_yaml: /etc/suricata/suricata.yaml

  tasks:
    - name: 1. Eliminar fichero de regla ICMP
      file:
        path: "{{ rule_file }}"
        state: absent

    - name: 2. Eliminar referencia a nics-ping.rules en suricata.yaml
      lineinfile:
        path: "{{ suricata_yaml }}"
        line: '  - nics-ping.rules'
        state: absent

    - name: 3. Validar configuracion de Suricata
      command: suricata -T -c "{{ suricata_yaml }}"
      register: suricata_test
      changed_when: false
      failed_when: suricata_test.rc != 0

    - name: 4. Reiniciar Suricata
      service:
        name: suricata
        state: restarted

    - name: 5. Verificar que Suricata sigue activa
      command: systemctl is-active suricata
      register: suricata_status
      changed_when: false
      failed_when: suricata_status.stdout.strip() != "active"

    - name: 6. Mostrar resultado final
      debug:
        msg: "Regla ICMP personalizada eliminada correctamente de Suricata"
EOF

echo "Iniciando rollback de regla ICMP de Suricata en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/suricata-ping-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

rm -rf "$TEMP_WORK_DIR"
echo "Proceso de rollback de regla ICMP de Suricata finalizado en $INSTANCE_NAME"