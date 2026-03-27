#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="wazuh_suricata_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No se proporciono la IP de destino."
    exit 1
fi

BASE_DIR="/tmp/ansible_wazuh_suricata_$INSTANCE_ID"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/wazuh-suricata-integration.yml" <<'EOF'
---
- name: Integrar Suricata eve.json con Wazuh Agent
  hosts: target
  become: true
  vars:
    remote_ossec: /var/ossec/etc/ossec.conf
    remote_log: /var/ossec/logs/ossec.log
    suricata_eve: /var/log/suricata/eve.json

  tasks:
    - name: Verificar que wazuh-agent esta activo
      command: systemctl is-active wazuh-agent
      register: wazuh_status
      changed_when: false
      failed_when: wazuh_status.stdout.strip() != "active"

    - name: Verificar que Suricata esta activa
      command: systemctl is-active suricata
      register: suricata_status
      changed_when: false
      failed_when: suricata_status.stdout.strip() != "active"

    - name: Verificar que existe eve.json de Suricata
      stat:
        path: "{{ suricata_eve }}"
      register: eve_stat

    - name: Fallar si no existe eve.json
      fail:
        msg: "No existe {{ suricata_eve }}"
      when: not eve_stat.stat.exists

    - name: Verificar que ossec.conf existe
      stat:
        path: "{{ remote_ossec }}"
      register: ossec_conf_stat

    - name: Fallar si no existe ossec.conf
      fail:
        msg: "No existe {{ remote_ossec }}"
      when: not ossec_conf_stat.stat.exists

    - name: Verificar si eve.json ya esta registrado en ossec.conf
      shell: grep -qF '<location>{{ suricata_eve }}</location>' "{{ remote_ossec }}"
      args:
        executable: /bin/bash
      register: suricata_block_exists
      changed_when: false
      failed_when: false

    - name: Insertar bloque localfile de Suricata antes del cierre de ossec_config
      blockinfile:
        path: "{{ remote_ossec }}"
        marker: "<!-- {mark} NICS_SURICATA -->"
        insertbefore: '</ossec_config>'
        block: |
          <localfile>
            <log_format>json</log_format>
            <location>{{ suricata_eve }}</location>
          </localfile>
      when: suricata_block_exists.rc != 0

    - name: Reiniciar wazuh-agent
      service:
        name: wazuh-agent
        state: restarted

    - name: Verificar que wazuh-agent sigue activo
      command: systemctl is-active wazuh-agent
      register: wazuh_restart_status
      changed_when: false
      failed_when: wazuh_restart_status.stdout.strip() != "active"

    - name: Verificar si Wazuh ya analiza eve.json
      shell: grep -q 'Analyzing JSON file.*suricata/eve.json' "{{ remote_log }}"
      args:
        executable: /bin/bash
      register: wazuh_log_check
      changed_when: false
      failed_when: false

    - name: Mostrar resultado final si ya esta enganchado
      debug:
        msg: "OK: Suricata enganchada correctamente a Wazuh"
      when: wazuh_log_check.rc == 0

    - name: Mostrar resultado final si aun no hay eventos
      debug:
        msg: "INFO: Configuracion aplicada. Falta generar trafico o alertas para ver eventos en Wazuh"
      when: wazuh_log_check.rc != 0
EOF

echo "===================================================="
echo " INTEGRANDO SURICATA CON WAZUH"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/wazuh-suricata-integration.yml"; then
    echo "----------------------------------------------------"
    echo "  INTEGRACION WAZUH + SURICATA COMPLETADA"
    echo "----------------------------------------------------"
else
    echo "  Fallo en la integracion Wazuh + Suricata"
    exit 1
fi

rm -rf "$BASE_DIR"