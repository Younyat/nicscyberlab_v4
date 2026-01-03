#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  SURICATA IDS UNINSTALLER (INTEGRATED WITH PYTHON MANAGER)
# ============================================================

# --- 1. CONFIGURACION DE RUTAS RELATIVAS ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
ADMIN_OPENRC="$PROJECT_ROOT/admin-openrc.sh"

# --- 2. PARAMETROS RECIBIDOS DESDE EL MANAGER (Python) ---
# $1: instance | $2: ssh_key | $3: target_ip | $4: ssh_user
INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Argumentos insuficientes recibidos de Python."
    exit 1
fi

# --- 3. TRABAJO TEMPORAL ---
# Se normaliza el nombre de la instancia para la ruta temporal
TEMP_WORK_DIR="/tmp/ansible_suricata_cleanup_${INSTANCE_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

# --- 4. GENERACION DE INVENTARIO Y PLAYBOOK ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[suricata_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

cat > "$TEMP_WORK_DIR/suricata-cleanup.yml" <<'EOF'
---
- name: Desinstalacion completa de Suricata IDS
  hosts: suricata_host
  become: true
  tasks:
    - name: 1. Detener el servicio Suricata
      systemd:
        name: suricata
        state: stopped
        enabled: false
      ignore_errors: true

    - name: 2. Eliminar paquetes de Suricata y dependencias (Purge)
      apt:
        name: 
          - suricata
          - suricata-update
        state: absent
        purge: true

    - name: 3. Eliminar dependencias no utilizadas
      apt:
        autoremove: true
        purge: true

    - name: 4. Eliminar directorios residuales (logs y reglas)
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /etc/suricata
        - /var/log/suricata
        - /var/lib/suricata
        - /run/suricata

    - name: 5. Matar procesos residuales de Suricata
      shell: pkill -9 suricata
      ignore_errors: true
      changed_when: false

    - name: 6. Limpiar sudoers de Ansible
      file:
        path: /etc/sudoers.d/ansible_nopasswd
        state: absent
EOF

# --- 5. EJECUCION DE ANSIBLE ---
echo "Iniciando purga total de Suricata en $TARGET_IP con usuario $SSH_USER"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/suricata-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

# --- 6. LIMPIEZA FINAL ---
rm -rf "$TEMP_WORK_DIR"

echo "Proceso de desinstalacion de Suricata finalizado en $INSTANCE_NAME"