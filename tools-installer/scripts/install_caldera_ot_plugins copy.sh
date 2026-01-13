#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"

TEMP_WORK_DIR="/tmp/ansible_ot_final"
mkdir -p "$TEMP_WORK_DIR"

cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[caldera_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$TEMP_WORK_DIR/ot-install-final.yml" <<'EOF'
---
- name: Instalacion de Plugins OT Individuales
  hosts: caldera_host
  become: true
  vars:
    caldera_path: "/opt/caldera"

  tasks:
    - name: 1. Eliminar rastro del plugin 'ot' fallido
      file:
        path: "{{ caldera_path }}/plugins/ot"
        state: absent

    - name: 2. Clonar el repositorio contenedor con submódulos
      git:
        repo: 'https://github.com/mitre/caldera-ot.git'
        dest: "/tmp/caldera-ot-repo"
        recursive: yes

    - name: 3. Mover protocolos individuales a la carpeta de plugins de Caldera
      shell: |
        cp -r /tmp/caldera-ot-repo/modbus {{ caldera_path }}/plugins/
        cp -r /tmp/caldera-ot-repo/bacnet {{ caldera_path }}/plugins/
        cp -r /tmp/caldera-ot-repo/dnp3 {{ caldera_path }}/plugins/
        cp -r /tmp/caldera-ot-repo/profinet {{ caldera_path }}/plugins/
      args:
        executable: /bin/bash

    - name: 4. Instalar dependencias de Python para los protocolos
      pip:
        name: [pymodbus, bacpypes, scapy, cryptography]
        executable: pip3
        extra_args: --break-system-packages

    - name: 5. Habilitar plugins en default.yml (Formato correcto)
      blockinfile:
        path: "{{ caldera_path }}/conf/default.yml"
        insertafter: '^plugins:'
        block: |
          - modbus
          - bacnet
          - dnp3
          - profinet

    - name: 6. Reiniciar Caldera
      systemd:
        name: caldera
        state: restarted
EOF

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/ot-install-final.yml"