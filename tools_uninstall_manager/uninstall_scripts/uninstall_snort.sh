#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  SNORT 3 (SOURCE) & SNORT 2 (APT) UNINSTALLER
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Argumentos insuficientes recibidos de Python."
    exit 1
fi

TEMP_WORK_DIR="/tmp/ansible_snort_cleanup_${INSTANCE_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

cat > "$TEMP_WORK_DIR/snort-cleanup.yml" <<'EOF'
---
- name: Borrado Total de Snort IDS (Source + APT)
  hosts: target
  become: true
  tasks:
    - name: 1. Detener servicios potenciales
      service:
        name: "{{ item }}"
        state: stopped
        enabled: false
      ignore_errors: true
      loop:
        - snort
        - snort3

    - name: 2. Eliminar binarios y librerias compiladas (Snort 3)
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /usr/local/bin/snort
        - /usr/local/lib/libdaq.so
        - /usr/local/lib/libdaq.a
        - /usr/local/lib/daq
        - /usr/local/include/daq.h
        - /usr/local/lib/pkgconfig/libdaq.pc

    - name: 3. Purgar paquetes de repositorio (Snort 2 si existiera)
      apt:
        name: snort
        state: absent
        purge: true
      ignore_errors: true

    - name: 4. Eliminar todos los directorios de configuracion y logs
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /etc/snort
        - /var/log/snort
        - /var/lib/snort
        - /etc/default/snort
        - /opt/snort_build      # Limpia la carpeta de compilacion anterior
        - /opt/snort3-src

    - name: 5. Refrescar cache de librerias del sistema
      command: ldconfig

    - name: 6. Limpieza final de APT
      apt:
        autoremove: true
        autoclean: true
      # Nota: Se elimino 'purge: true' de aqui porque causa conflicto con autoclean
EOF

echo "Iniciando desinstalacion de Snort en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/snort-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

rm -rf "$TEMP_WORK_DIR"
echo "Proceso de desinstalacion de Snort finalizado en $INSTANCE_NAME"