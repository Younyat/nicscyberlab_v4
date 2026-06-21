#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH FIM REALTIME UNINSTALLER
# ============================================================

INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$SSH_KEY" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Uso: $0 <INSTANCE_NAME> <SSH_KEY> <TARGET_IP> <SSH_USER>"
    exit 1
fi

TEMP_WORK_DIR="/tmp/ansible_wazuh_fim_cleanup_${INSTANCE_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$TEMP_WORK_DIR/wazuh-fim-cleanup.yml" <<'EOF'
---
- name: Desactivar FIM realtime en Wazuh Agent
  hosts: target
  become: true
  vars:
    remote_ossec: /var/ossec/etc/ossec.conf

  tasks:
    - name: Verificar que ossec.conf existe
      stat:
        path: "{{ remote_ossec }}"
      register: ossec_conf_stat

    - name: Crear copia de seguridad de ossec.conf
      copy:
        src: "{{ remote_ossec }}"
        dest: "{{ remote_ossec }}.bak_uninstall_fim"
        remote_src: true
        mode: preserve
      when: ossec_conf_stat.stat.exists

    - name: Desactivar realtime en /etc,/usr/bin,/usr/sbin
      replace:
        path: "{{ remote_ossec }}"
        regexp: '^\s*<directories realtime="yes">/etc,/usr/bin,/usr/sbin</directories>\s*$'
        replace: '    <directories>/etc,/usr/bin,/usr/sbin</directories>'
      when: ossec_conf_stat.stat.exists

    - name: Desactivar realtime en /bin,/sbin,/boot
      replace:
        path: "{{ remote_ossec }}"
        regexp: '^\s*<directories realtime="yes">/bin,/sbin,/boot</directories>\s*$'
        replace: '    <directories>/bin,/sbin,/boot</directories>'
      when: ossec_conf_stat.stat.exists

    - name: Reiniciar wazuh-agent si el servicio existe
      service:
        name: wazuh-agent
        state: restarted
      register: wazuh_restart
      failed_when: false
      when: ossec_conf_stat.stat.exists

    - name: Verificar estado final si el servicio pudo reiniciarse
      command: systemctl is-active wazuh-agent
      register: wazuh_status
      changed_when: false
      failed_when: wazuh_restart.failed is defined and not wazuh_restart.failed and wazuh_status.stdout.strip() != "active"
      when: ossec_conf_stat.stat.exists

    - name: Mostrar resultado final
      debug:
        msg: >-
          FIM realtime desactivado correctamente
          (o ya ausente en el nodo si Wazuh local no estaba disponible).
EOF

echo "Iniciando desactivacion de Wazuh FIM Realtime en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/wazuh-fim-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

rm -rf "$TEMP_WORK_DIR"
echo "Proceso de desactivacion Wazuh FIM Realtime finalizado en $INSTANCE_NAME"
