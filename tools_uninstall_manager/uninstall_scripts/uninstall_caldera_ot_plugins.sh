#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  CALDERA OT PLUGIN UNINSTALLER (SOLO COMPONENTES OT)
#  Mantiene el servidor core y el agente funcionando perfectamente.
# ============================================================

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

# --- 5. GENERACION DEL PLAYBOOK DE LIMPIEZA ---
cat > "$TEMP_WORK_DIR/ot-cleanup.yml" <<'EOF'
---
- name: Eliminar unicamente el Plugin OT de Caldera
  hosts: caldera_target
  become: true
  vars:
    caldera_path: "/opt/caldera"
    ot_plugins: [modbus, bacnet, dnp3, profinet, iec61850]

  tasks:
    - name: 1. Limpiar rastro de bloques Ansible en default.yml
      blockinfile:
        path: "{{ caldera_path }}/conf/default.yml"
        marker: "# {mark} ANSIBLE MANAGED BLOCK"
        state: absent

    - name: 2. Eliminar cualquier linea residual de los protocolos OT
      lineinfile:
        path: "{{ caldera_path }}/conf/default.yml"
        regexp: '^\s*-\s*{{ item }}$'
        state: absent
      loop: "{{ ot_plugins }}"

    - name: 3. Eliminar directorios fisicos de los plugins OT
      file:
        path: "{{ caldera_path }}/plugins/{{ item }}"
        state: absent
      loop: "{{ ot_plugins }}"

    - name: 4. Limpiar base de datos para reconstruccion limpia del indice
      file:
        path: "{{ caldera_path }}/data/plugins.db"
        state: absent

    - name: 5. Detener el servicio Caldera de forma controlada
      systemd:
        name: caldera
        state: stopped
      ignore_errors: true

    - name: 6. Limpiar procesos de Python residuales (Evita bloqueos del puerto 8888)
      shell: "pkill -9 -f server.py || true"
      ignore_errors: true
      changed_when: false

    - name: 7. Iniciar Caldera con la nueva configuracion limpia
      systemd:
        name: caldera
        state: started
        enabled: true
        daemon_reload: true

    - name: 8. Validar disponibilidad del puerto 8888
      wait_for:
        port: 8888
        host: 127.0.0.1
        state: started
        delay: 5
        timeout: 90
EOF

# --- 6. EJECUCION DE ANSIBLE ---
echo "Iniciando desinstalacion quirurgica del Plugin OT en $INSTANCE_NAME ($TARGET_IP)"
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/ot-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'; then
    echo "----------------------------------------------------"
    echo " ✅ DESINSTALACION OT COMPLETADA CON EXITO"
    echo " El servidor Caldera sigue operativo en el puerto 8888"
    echo "----------------------------------------------------"
else
    echo "----------------------------------------------------"
    echo " ❌ ERROR: Fallo la desinstalacion o el reinicio."
    echo "----------------------------------------------------"
    exit 1
fi

# --- 7. LIMPIEZA FINAL ---
rm -rf "$TEMP_WORK_DIR"
echo "Proceso finalizado para la instancia: $INSTANCE_NAME"