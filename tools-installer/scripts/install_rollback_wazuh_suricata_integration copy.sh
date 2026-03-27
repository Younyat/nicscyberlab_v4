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
    begin_mark: "<!-- NICS_SURICATA_BEGIN -->"
    end_mark: "<!-- NICS_SURICATA_END -->"
    suricata_block: |
      <!-- NICS_SURICATA_BEGIN -->
      <ossec_config>
        <localfile>
          <log_format>json</log_format>
          <location>/var/log/suricata/eve.json</location>
        </localfile>
      </ossec_config>
      <!-- NICS_SURICATA_END -->

  tasks:
    - name: Verificar que wazuh-agent esta activo
      command: systemctl is-active wazuh-agent
      register: wazuh_status
      changed_when: false
      failed_when: wazuh_status.stdout.strip() != "active"

    - name: Verificar que Realtime FIM ya esta configurado
      shell: grep -qE '<directories[^>]*realtime="yes"' "{{ remote_ossec }}"
      register: fim_check
      changed_when: false
      failed_when: fim_check.rc != 0

    - name: Verificar que Suricata esta activa
      command: systemctl is-active suricata
      register: suricata_status
      changed_when: false
      failed_when: suricata_status.stdout.strip() != "active"

    - name: Verificar si el bloque Suricata ya existe
      shell: grep -qF "{{ begin_mark }}" "{{ remote_ossec }}"
      register: block_exists
      changed_when: false
      failed_when: false

    - name: Añadir bloque Suricata a ossec.conf si no existe
      blockinfile:
        path: "{{ remote_ossec }}"
        marker: "{mark}"
        marker_begin: "NICS_SURICATA_BEGIN"
        marker_end: "NICS_SURICATA_END"
        insertafter: EOF
        block: |
          <ossec_config>
            <localfile>
              <log_format>json</log_format>
              <location>{{ suricata_eve }}</location>
            </localfile>
          </ossec_config>
      when: block_exists.rc != 0

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