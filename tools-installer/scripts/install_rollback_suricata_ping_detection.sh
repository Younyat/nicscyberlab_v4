#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="suricata_ping_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No se proporciono la IP de destino."
    exit 1
fi

BASE_DIR="/tmp/ansible_suricata_ping_$INSTANCE_ID"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/suricata-ping-detection.yml" <<'EOF'
---
- name: Configurar deteccion ICMP Ping en Suricata
  hosts: target
  become: true
  vars:
    rules_dir: /var/lib/suricata/rules
    rule_file: /var/lib/suricata/rules/nics-ping.rules
    suricata_yaml: /etc/suricata/suricata.yaml
    rule_content: 'alert icmp any any -> any any (msg:"NICS ICMP Ping Detected"; itype:8; classtype:network-scan; sid:9200001; rev:1;)'

  tasks:
    - name: Verificar que Suricata esta instalada
      shell: command -v suricata
      args:
        executable: /bin/bash
      register: suricata_bin
      changed_when: false
      failed_when: suricata_bin.rc != 0

    - name: Verificar que existe suricata.yaml
      stat:
        path: "{{ suricata_yaml }}"
      register: suricata_yaml_stat

    - name: Fallar si no existe suricata.yaml
      fail:
        msg: "suricata.yaml no encontrado en {{ suricata_yaml }}"
      when: not suricata_yaml_stat.stat.exists

    - name: Crear directorio de reglas
      file:
        path: "{{ rules_dir }}"
        state: directory
        owner: root
        group: root
        mode: '0755'

    - name: Crear regla ICMP personalizada
      copy:
        dest: "{{ rule_file }}"
        content: "{{ rule_content }}\n"
        owner: root
        group: root
        mode: '0640'

    - name: Verificar si la regla ya esta registrada en suricata.yaml
      shell: grep -q 'nics-ping.rules' "{{ suricata_yaml }}"
      args:
        executable: /bin/bash
      register: rule_registered
      changed_when: false
      failed_when: false

    - name: Registrar nics-ping.rules en suricata.yaml
      lineinfile:
        path: "{{ suricata_yaml }}"
        insertafter: '^rule-files:'
        line: '  - nics-ping.rules'
        state: present
      when: rule_registered.rc != 0

    - name: Validar configuracion de Suricata
      command: suricata -T -c "{{ suricata_yaml }}"
      register: suricata_test
      changed_when: false
      failed_when: suricata_test.rc != 0

    - name: Reiniciar Suricata
      service:
        name: suricata
        state: restarted

    - name: Verificar que Suricata sigue activa
      command: systemctl is-active suricata
      register: suricata_status
      changed_when: false
      failed_when: suricata_status.stdout.strip() != "active"

    - name: Mostrar resultado final
      debug:
        msg: "OK: Regla ICMP desplegada correctamente. Prueba con ping y revisa /var/log/suricata/eve.json"
EOF

echo "===================================================="
echo " CONFIGURANDO DETECCION ICMP EN SURICATA"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/suricata-ping-detection.yml"; then
    echo "----------------------------------------------------"
    echo "  DETECCION ICMP EN SURICATA CONFIGURADA"
    echo "----------------------------------------------------"
else
    echo "  Fallo en la configuracion ICMP de Suricata"
    exit 1
fi

rm -rf "$BASE_DIR"