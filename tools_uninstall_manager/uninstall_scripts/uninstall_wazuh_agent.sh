#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH AGENT UNINSTALLER (INTEGRATED WITH PYTHON MANAGER)
# ============================================================

# --- 1. CONFIGURACION DE RUTAS RELATIVAS ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
ADMIN_OPENRC="$PROJECT_ROOT/admin-openrc.sh"

# --- 2. PARAMETROS RECIBIDOS DESDE EL MANAGER (Python) ---
# $1: instance | $2: ssh_key | $3: target_ip | $4: ssh_user
VICTIM_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
VICTIM_USER="${4:-}"

if [[ -z "$VICTIM_NAME" || -z "$TARGET_IP" || -z "$VICTIM_USER" ]]; then
    echo "ERROR: Argumentos insuficientes recibidos de Python."
    exit 1
fi

# --- 3. CARGAR ENTORNO OPENSTACK ---
if [[ -f "$ADMIN_OPENRC" ]]; then 
    source "$ADMIN_OPENRC"
    if ! openstack token issue &>/dev/null; then
        echo "ERROR: Credenciales de OpenStack expiradas."
        exit 1
    fi
else 
    echo "ERROR: No se encontro admin-openrc.sh"; exit 1
fi

# --- 4. DESCUBRIMIENTO DEL MONITOR (MANAGER) ---
MANAGER_NAME=$(openstack server list --name monitor -f value -c Name | head -n 1)

if [[ -z "$MANAGER_NAME" ]]; then
    echo "ERROR: No se encontro la instancia de monitoreo (monitor)."
    exit 1
fi

MANAGER_IP=$(openstack server show "$MANAGER_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

# --- 5. PREPARACION DE ANSIBLE ---
TEMP_WORK_DIR="/tmp/ansible_cleanup_${VICTIM_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[victim]
$TARGET_IP ansible_user=$VICTIM_USER ansible_ssh_private_key_file=$SSH_KEY

[manager]
$MANAGER_IP ansible_user=ubuntu ansible_ssh_private_key_file=$SSH_KEY
EOF

# --- 6. PLAYBOOK DE DESINSTALACION ---
cat > "$TEMP_WORK_DIR/purgar_wazuh.yml" <<'EOF'
---
- name: Limpieza en Victima
  hosts: victim
  become: true
  tasks:
    - name: Purga de paquete wazuh-agent
      apt:
        name: wazuh-agent
        state: absent
        purge: true
      ignore_errors: true

    - name: Eliminacion de directorios
      file:
        path: "{{ item }}"
        state: absent
      loop: ["/var/ossec", "/etc/wazuh-agent"]

- name: Limpieza en Manager (Monitor)
  hosts: manager
  become: true
  tasks:
    - name: Busqueda de ID de agente
      shell: |
        /var/ossec/bin/manage_agents -l | grep -i "{{ victim_name }}" | cut -d',' -f1 | awk '{print $2}' | head -n 1
      register: agent_id
      changed_when: false

    - name: Eliminacion de registro de agente
      shell: "/var/ossec/bin/manage_agents -r {{ agent_id.stdout }}"
      when: agent_id.stdout != ""
      notify: Restart Wazuh

    - name: Borrado de base de datos de agente
      file:
        path: "/var/ossec/queue/db/{{ agent_id.stdout }}.db"
        state: absent
      when: agent_id.stdout != ""

  handlers:
    - name: Restart Wazuh
      systemd:
        name: wazuh-manager
        state: restarted
EOF

# --- 7. EJECUCION ---
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/purgar_wazuh.yml" \
    -e "victim_name=$VICTIM_NAME"

# --- 8. LIMPIEZA ---
rm -rf "$TEMP_WORK_DIR"
echo "Desinstalacion de Wazuh Agent finalizada en $VICTIM_NAME"