#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# WAZUH AGENT INSTALLER - AUTO-FIX MANAGER + AUTO-ENROLL
# ============================================================

VICTIM_IP="${1:-}"
SSH_USER_VICTIM="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
WAZUH_VERSION="4.7.3"
MANAGER_SSH_USER="ubuntu"

if [[ -z "$VICTIM_IP" ]]; then
    echo "[ERROR] No se recibió la IP de la víctima."
    exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
    echo "[ERROR] No existe la clave SSH: $SSH_KEY"
    exit 1
fi

# ------------------------------------------------------------
# 1. LOCALIZAR MANAGER
# ------------------------------------------------------------
echo "[INFO] Localizando Manager Wazuh en OpenStack..."

MONITOR_ID="$(
    openstack server list -f value -c ID -c Name \
    | awk 'BEGIN{IGNORECASE=1} $0 ~ /monitor/ {print $1; exit}'
)"

if [[ -z "$MONITOR_ID" ]]; then
    echo "[ERROR] No se encontró ninguna instancia cuyo nombre contenga 'monitor'."
    exit 1
fi

MONITOR_NAME="$(openstack server show "$MONITOR_ID" -f value -c name 2>/dev/null || true)"
[[ -z "$MONITOR_NAME" ]] && MONITOR_NAME="$MONITOR_ID"

ADDRESSES_RAW="$(openstack server show "$MONITOR_ID" -f value -c addresses 2>/dev/null || true)"

if [[ -z "$ADDRESSES_RAW" ]]; then
    echo "[ERROR] No se pudieron obtener las direcciones de la instancia '${MONITOR_NAME}'."
    exit 1
fi

CANDIDATE_IPS="$(
    echo "$ADDRESSES_RAW" \
    | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' \
    | awk '!seen[$0]++'
)"

if [[ -z "$CANDIDATE_IPS" ]]; then
    echo "[ERROR] No se encontró ninguna IP válida en la instancia '${MONITOR_NAME}'."
    echo "[DEBUG] addresses=${ADDRESSES_RAW}"
    exit 1
fi

MANAGER_IP=""
for ip in $CANDIDATE_IPS; do
    echo "[INFO] Probando acceso SSH al manager en ${ip}..."
    if ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        "${MANAGER_SSH_USER}@${ip}" "echo ok" >/dev/null 2>&1; then
        MANAGER_IP="$ip"
        break
    fi
done

if [[ -z "$MANAGER_IP" ]]; then
    echo "[ERROR] Se encontraron IPs para '${MONITOR_NAME}', pero ninguna responde por SSH."
    echo "[DEBUG] IPs detectadas: $CANDIDATE_IPS"
    exit 1
fi

echo "[OK] Manager detectado: ${MONITOR_NAME}"
echo "[OK] IP seleccionada del manager: ${MANAGER_IP}"

# ------------------------------------------------------------
# 2. OBTENER HOSTNAME REAL DE LA VICTIMA
# ------------------------------------------------------------
echo "[INFO] Obteniendo hostname real de la máquina remota..."

REMOTE_HOSTNAME="$(
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${SSH_USER_VICTIM}@${VICTIM_IP}" "hostname" 2>/dev/null || true
)"

if [[ -z "$REMOTE_HOSTNAME" ]]; then
    echo "[ERROR] No se pudo obtener el hostname remoto de ${VICTIM_IP}"
    exit 1
fi

echo "[OK] Hostname remoto detectado: ${REMOTE_HOSTNAME}"

# ------------------------------------------------------------
# 3. CORREGIR AUTOMATICAMENTE EL MANAGER
# ------------------------------------------------------------
echo "[INFO] Corrigiendo configuración de enrollment en el manager..."

ssh -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "${MANAGER_SSH_USER}@${MANAGER_IP}" "bash -s" <<'EOF'
set -euo pipefail

CONF="/var/ossec/etc/ossec.conf"

sudo cp "$CONF" "${CONF}.bak.$(date +%Y%m%d%H%M%S)"

sudo python3 - <<'PY'
import re
from pathlib import Path

conf = Path("/var/ossec/etc/ossec.conf")
text = conf.read_text()

new_auth = """  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>no</use_source_ip>
    <remote_enrollment>yes</remote_enrollment>
    <force>
      <enabled>yes</enabled>
      <key_mismatch>yes</key_mismatch>
      <disconnected_time enabled="yes">1h</disconnected_time>
      <after_registration_time>1h</after_registration_time>
    </force>
    <purge>yes</purge>
    <use_password>no</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>/var/ossec/etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>/var/ossec/etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>"""

pattern = re.compile(r'^[ \t]*<auth>.*?</auth>', re.DOTALL | re.MULTILINE)

if pattern.search(text):
    text = pattern.sub(new_auth, text, count=1)
else:
    text = text.replace("</ossec_config>", f"{new_auth}\n</ossec_config>")

conf.write_text(text)
PY

sudo systemctl restart wazuh-manager
sleep 5

echo "[MANAGER] Servicio wazuh-manager:"
sudo systemctl is-active wazuh-manager

echo "[MANAGER] Puerto 1515:"
sudo ss -lntp | grep 1515 || true

echo "[MANAGER] Bloque auth final:"
sudo grep -n -A20 -B5 "<auth>" "$CONF" || true
EOF

# ------------------------------------------------------------
# 4. ELIMINAR AGENTE ANTIGUO CON EL MISMO HOSTNAME
# ------------------------------------------------------------
echo "[INFO] Buscando agente previo '${REMOTE_HOSTNAME}' en el manager..."

OLD_AGENT_ID="$(
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${MANAGER_SSH_USER}@${MANAGER_IP}" \
        "sudo /var/ossec/bin/manage_agents -l" 2>/dev/null \
    | awk -F',' -v host="$REMOTE_HOSTNAME" '
        /ID:/ {
            id=$1
            name=$2
            gsub(/^.*ID: /, "", id)
            gsub(/^ Name: /, "", name)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", id)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
            if (name == host) print id
        }
    ' | head -n 1
)"

if [[ -n "${OLD_AGENT_ID:-}" ]]; then
    echo "[FIX] Eliminando agente antiguo en manager. ID=${OLD_AGENT_ID}, Name=${REMOTE_HOSTNAME}"
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${MANAGER_SSH_USER}@${MANAGER_IP}" \
        "sudo /var/ossec/bin/manage_agents -r ${OLD_AGENT_ID}"

    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${MANAGER_SSH_USER}@${MANAGER_IP}" \
        "sudo systemctl restart wazuh-manager"

    sleep 5
else
    echo "[INFO] No existe agente previo con nombre ${REMOTE_HOSTNAME} en el manager."
fi

# ------------------------------------------------------------
# 5. PREPARAR ANSIBLE
# ------------------------------------------------------------
BASE_DIR="$HOME/ansible/wazuh-agent-${VICTIM_IP}"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[victim]
$VICTIM_IP ansible_user=$SSH_USER_VICTIM ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
EOF

cat > "$BASE_DIR/install_agent.yml" <<EOF
---
- name: Instalación y configuración estricta de Wazuh Agent
  hosts: victim
  become: true
  vars:
    manager_ip: "$MANAGER_IP"
    wazuh_version: "$WAZUH_VERSION"
    remote_hostname: "$REMOTE_HOSTNAME"

  tasks:
    - name: Detener agente si existe
      shell: |
        systemctl stop wazuh-agent || true
      args:
        executable: /bin/bash
      changed_when: false

    - name: Eliminar instalación previa del agente
      shell: |
        apt-get purge -y wazuh-agent || true
        apt-get autoremove -y || true
        rm -rf /var/ossec
        rm -rf /etc/wazuh-agent
      args:
        executable: /bin/bash

    - name: Instalar dependencias y repositorio
      shell: |
        apt-get update
        apt-get install -y curl apt-transport-https gnupg
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
        echo "deb https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
        apt-get update
      args:
        executable: /bin/bash

    - name: Instalar Wazuh Agent
      apt:
        name: "wazuh-agent={{ wazuh_version }}-1"
        state: present
        force: true

    - name: Configurar dirección del manager
      replace:
        path: /var/ossec/etc/ossec.conf
        regexp: '<address>.*?</address>'
        replace: '<address>{{ manager_ip }}</address>'

    - name: Eliminar bloque previo de logs NICS si existe
      blockinfile:
        path: /var/ossec/etc/ossec.conf
        marker: "<!-- {mark} NICS_DEFAULT_LOGS -->"
        state: absent

    - name: Insertar bloque único de logs NICS
      blockinfile:
        path: /var/ossec/etc/ossec.conf
        marker: "<!-- {mark} NICS_DEFAULT_LOGS -->"
        insertbefore: "</ossec_config>"
        block: |
          <localfile>
            <log_format>syslog</log_format>
            <location>/var/log/auth.log</location>
          </localfile>
          <localfile>
            <log_format>syslog</log_format>
            <location>/var/log/syslog</location>
          </localfile>

    - name: Vaciar claves locales previas
      shell: |
        truncate -s 0 /var/ossec/etc/client.keys
      args:
        executable: /bin/bash

    - name: Enrolar agente sin contraseña
      shell: |
        /var/ossec/bin/agent-auth -m {{ manager_ip }} -A {{ remote_hostname }}
      args:
        executable: /bin/bash
      register: agent_auth_result
      changed_when: true
      failed_when: agent_auth_result.rc != 0

    - name: Reiniciar agente
      systemd:
        name: wazuh-agent
        state: restarted
        enabled: true
        daemon_reload: true

    - name: Esperar unos segundos para conexión real
      pause:
        seconds: 25

    - name: Comprobar que el agente está activo
      command: systemctl is-active wazuh-agent
      register: wazuh_active
      changed_when: false
      failed_when: wazuh_active.stdout.strip() != "active"

    - name: Comprobar actividad en logs del agente
      shell: |
        grep -Ei "Connected to the server|Starting agent|Agent started|Connected" /var/ossec/logs/ossec.log | tail -n 20
      args:
        executable: /bin/bash
      register: wazuh_connected
      changed_when: false
      failed_when: wazuh_connected.rc != 0

    - name: Mostrar confirmación final
      debug:
        msg: "OK: Wazuh Agent instalado, enrolado y con actividad en logs contra {{ manager_ip }}"
EOF

# ------------------------------------------------------------
# 6. EJECUTAR
# ------------------------------------------------------------
echo "[INFO] Ejecutando Ansible Playbook..."
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/install_agent.yml"; then
    echo "[SUCCESS] Agente Wazuh instalado y conectado correctamente."
    rm -rf "$BASE_DIR"
    exit 0
else
    echo "[ERROR] Falló la instalación o la conexión final del agente."
    exit 1
fi