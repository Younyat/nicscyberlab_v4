#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  CALDERA AGENT UNINSTALLER (INTEGRATED WITH PYTHON MANAGER)
# ============================================================

# --- 1. CONFIGURACIÓN DE RUTAS ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
ADMIN_OPENRC="$PROJECT_ROOT/admin-openrc.sh"

# --- 2. PARÁMETROS RECIBIDOS ---
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
    echo "ERROR: No se encontró admin-openrc.sh"; exit 1
fi

# --- 4. DESCUBRIMIENTO DEL ATACANTE (ATTACK) ---
# Buscamos dinámicamente la instancia que contiene "attack" en su nombre
ATTACK_NAME=$(openstack server list --name attack -f value -c Name | head -n 1)

if [[ -z "$ATTACK_NAME" ]]; then
    echo "ERROR: No se encontró la instancia de ataque (attack)."
    exit 1
fi

ATTACK_IP=$(openstack server show "$ATTACK_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

# --- 5. PREPARACIÓN DE ANSIBLE ---
TEMP_WORK_DIR="/tmp/ansible_cleanup_caldera_${VICTIM_NAME// /_}"
mkdir -p "$TEMP_WORK_DIR"

cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[victim]
$TARGET_IP ansible_user=$VICTIM_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_extra_args='-o StrictHostKeyChecking=no'

[attacker]
$ATTACK_IP ansible_user=debian ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_extra_args='-o StrictHostKeyChecking=no'
EOF

# --- 6. PLAYBOOK DE DESINSTALACIÓN ---
cat > "$TEMP_WORK_DIR/purgar_caldera.yml" <<'EOF'
---
- name: Limpieza en Victima
  hosts: victim
  become: true
  tasks:
    - name: "1. Recuperar el PAW del agente"
      shell: "cat /usr/local/bin/sandcat_paw 2>/dev/null || echo 'unknown'"
      register: agent_paw
      changed_when: false

    - name: "2. Detener servicio caldera-agent"
      systemd:
        name: caldera-agent
        state: stopped
        enabled: false
      ignore_errors: true

    - name: "3. Matar procesos residuales de forma individual (evita error rc-9)"
      shell: "{{ item }}"
      loop:
        - "pkill -9 -f sandcat || true"
        - "pkill -9 -f splunkd || true"
      ignore_errors: true

    - name: "4. Eliminar archivos del agente y servicio"
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /etc/systemd/system/caldera-agent.service
        - /usr/local/bin/sandcat
        - /usr/local/bin/splunkd
        - /usr/local/bin/sandcat_paw

    - name: "5. Recargar systemd"
      systemd:
        daemon_reload: true

- name: Limpieza en Manager (Attack)
  hosts: attacker
  become: true
  vars:
    # Obtenemos el PAW recolectado de la víctima
    target_paw: "{{ hostvars[groups['victim'][0]]['agent_paw']['stdout'] }}"
  tasks:
    - name: "6. Eliminar registro físico del agente en el servidor"
      file:
        path: "/home/debian/caldera/data/agents/{{ target_paw }}.yml"
        state: absent
      when: target_paw != "unknown"
      ignore_errors: true

    - name: "7. Reiniciar servicio Caldera para refrescar Dashboard"
      systemd:
        name: caldera
        state: restarted
      ignore_errors: true
EOF

# --- 7. EJECUCIÓN ---
export ANSIBLE_HOST_KEY_CHECKING=False

echo " [INFO] Ejecutando purga completa en $VICTIM_NAME y sincronizando con $ATTACK_NAME..."
ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/purgar_caldera.yml"

# --- 8. LIMPIEZA DE ARCHIVOS TEMPORALES ---
rm -rf "$TEMP_WORK_DIR"
echo "Desinstalacion de Caldera finalizada correctamente para $VICTIM_NAME."