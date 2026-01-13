#!/usr/bin/env bash
set -euo pipefail

# --- 1. CONFIGURACION DE RUTAS RELATIVAS ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"

# --- 2. PARAMETROS RECIBIDOS DESDE EL MANAGER (Python) ---
INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Argumentos insuficientes recibidos de Python."
    exit 1
fi

# --- 3. TRABAJO TEMPORAL ---
TEMP_WORK_DIR="/tmp/ansible_ot_cleanup_${INSTANCE_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

# --- 4. GENERACION DE INVENTARIO ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[caldera_target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

# --- 5. GENERACION DEL PLAYBOOK DE LIMPIEZA DEL PLUGIN ---
cat > "$TEMP_WORK_DIR/ot-cleanup.yml" <<'EOF'
---
- name: Eliminar unicamente el Plugin OT de Caldera
  hosts: caldera_target
  become: true
  vars:
    caldera_path: "/opt/caldera"
    ot_plugins: [modbus, bacnet, dnp3, profinet, iec61850]

  tasks:
    - name: 1. Eliminar el bloque gestionado por Ansible (comentarios incluidos)
      blockinfile:
        path: "{{ caldera_path }}/conf/default.yml"
        marker: "# {mark} ANSIBLE MANAGED BLOCK"
        state: absent

    - name: 2. Limpieza de seguridad de cualquier linea huerfana de OT
      lineinfile:
        path: "{{ caldera_path }}/conf/default.yml"
        regexp: '^\s*-\s*{{ item }}$'
        state: absent
      loop: "{{ ot_plugins }}"

    - name: 3. Eliminar directorios de los plugins OT
      file:
        path: "{{ caldera_path }}/plugins/{{ item }}"
        state: absent
      loop: "{{ ot_plugins }}"

    - name: 4. Limpiar cache de base de datos
      file:
        path: "{{ caldera_path }}/data/plugins.db"
        state: absent

    - name: 5. Reiniciar Caldera
      systemd:
        name: caldera
        state: restarted

    - name: 6. Esperar a que el servicio IT este disponible
      wait_for:
        port: 8888
        delay: 5
        timeout: 60
EOF

# --- 6. EJECUCION DE ANSIBLE ---
echo "Iniciando desinstalacion del Plugin OT en $INSTANCE_NAME ($TARGET_IP)"
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/ot-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

# --- 7. LIMPIEZA FINAL ---
rm -rf "$TEMP_WORK_DIR"
echo "Proceso finalizado en $INSTANCE_NAME"