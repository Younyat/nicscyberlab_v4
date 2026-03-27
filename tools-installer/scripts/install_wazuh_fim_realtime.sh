#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="wazuh_fim_realtime_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No se proporciono la IP de destino."
    exit 1
fi

BASE_DIR="/tmp/ansible_wazuh_fim_realtime_$INSTANCE_ID"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/wazuh-fim-realtime.yml" <<'EOF'
---
- name: Activar FIM realtime en Wazuh Agent
  hosts: target
  become: true
  vars:
    remote_ossec: /var/ossec/etc/ossec.conf
    remote_log: /var/ossec/logs/ossec.log

  tasks:
    - name: Verificar que wazuh-agent esta activo
      command: systemctl is-active wazuh-agent
      register: wazuh_status
      changed_when: false
      failed_when: wazuh_status.stdout.strip() != "active"

    - name: Verificar que ossec.conf existe
      stat:
        path: "{{ remote_ossec }}"
      register: ossec_conf_stat

    - name: Fallar si no existe ossec.conf
      fail:
        msg: "No existe {{ remote_ossec }}"
      when: not ossec_conf_stat.stat.exists

    - name: Crear copia de seguridad de ossec.conf
      copy:
        src: "{{ remote_ossec }}"
        dest: "{{ remote_ossec }}.bak_ansible"
        remote_src: true
        mode: preserve

    - name: Activar realtime en /etc,/usr/bin,/usr/sbin
      replace:
        path: "{{ remote_ossec }}"
        regexp: '^\s*<directories>/etc,/usr/bin,/usr/sbin</directories>\s*$'
        replace: '    <directories realtime="yes">/etc,/usr/bin,/usr/sbin</directories>'

    - name: Activar realtime en /bin,/sbin,/boot
      replace:
        path: "{{ remote_ossec }}"
        regexp: '^\s*<directories>/bin,/sbin,/boot</directories>\s*$'
        replace: '    <directories realtime="yes">/bin,/sbin,/boot</directories>'

    - name: Verificar que quedaron entradas realtime en ossec.conf
      shell: |
        grep -n '<directories realtime="yes">/etc,/usr/bin,/usr/sbin</directories>' "{{ remote_ossec }}" && \
        grep -n '<directories realtime="yes">/bin,/sbin,/boot</directories>' "{{ remote_ossec }}"
      args:
        executable: /bin/bash
      register: realtime_conf_check
      changed_when: false
      failed_when: realtime_conf_check.rc != 0

    - name: Reiniciar wazuh-agent
      service:
        name: wazuh-agent
        state: restarted

    - name: Esperar a que el agente arranque
      pause:
        seconds: 3

    - name: Verificar que wazuh-agent sigue activo
      command: systemctl is-active wazuh-agent
      register: wazuh_restart_status
      changed_when: false
      failed_when: wazuh_restart_status.stdout.strip() != "active"

    - name: Verificar si Wazuh ya muestra rutas con realtime
      shell: grep -i "Monitoring path:" "{{ remote_log }}" | grep -i "realtime"
      args:
        executable: /bin/bash
      register: realtime_log_check
      changed_when: false
      failed_when: false

    - name: Mostrar resultado final si realtime ya aparece en logs
      debug:
        msg: "OK: FIM realtime activado correctamente en Wazuh"
      when: realtime_log_check.rc == 0

    - name: Mostrar resultado final si aun no aparece realtime en logs
      debug:
        msg: "INFO: Configuracion aplicada y agente reiniciado. Revisa de nuevo ossec.log en unos segundos"
      when: realtime_log_check.rc != 0
EOF

echo "===================================================="
echo " ACTIVANDO FIM REALTIME EN WAZUH"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/wazuh-fim-realtime.yml"; then
    echo "----------------------------------------------------"
    echo "  FIM REALTIME ACTIVADO CORRECTAMENTE"
    echo "----------------------------------------------------"
else
    echo "  Fallo al activar FIM realtime en Wazuh"
    exit 1
fi

rm -rf "$BASE_DIR"