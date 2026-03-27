#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  SURICATA FULL AUTO DEPLOY (ANSIBLE)
#  Filosofía: Identidad basada en IP, compatible con Master
# ============================================================

# --- 1. PARÁMETROS RECIBIDOS ---
# El Master envía: $1=IP, $2=User
TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"

# Variables de entorno internas
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="suricata_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo " ERROR: No se proporcionó la IP de destino para Suricata."
    exit 1
fi

# --- 2. PREPARACIÓN DE ENTORNO TEMPORAL ---
BASE_DIR="/tmp/ansible_suricata_$INSTANCE_ID"
mkdir -p "$BASE_DIR"/{inventory,playbooks}

echo "===================================================="
echo " [1/3] CONFIGURANDO SURICATA EN: $TARGET_IP"
echo "===================================================="

# Generar Inventario Dinámico
cat > "$BASE_DIR/inventory/hosts.ini" <<EOF
[suricata]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

echo "[2/3] GENERANDO PLAYBOOK DE INSTALACIÓN"

cat > "$BASE_DIR/playbooks/suricata-aio.yml" <<'EOF'
---
- name: Instalación Definitiva de Suricata IDS
  hosts: suricata
  become: true
  tasks:
    - name: 1. Instalar Suricata y utilidades
      apt:
        name: [suricata, jq, curl, net-tools]
        state: present
        update_cache: true

    - name: 2. Detectar Interfaz de Red Activa
      shell: "ip route get 8.8.8.8 | awk '{print $5; exit}'"
      register: iface_detected
      changed_when: false

    - name: 3. Configurar suricata.yaml (Optimizado)
      copy:
        dest: /etc/suricata/suricata.yaml
        owner: root
        group: root
        mode: '0644'
        content: |
          %YAML 1.1
          ---
          vars:
            address-groups:
              HOME_NET: "[10.0.2.0/24]"
              EXTERNAL_NET: "!$HOME_NET"

          default-log-dir: /var/log/suricata/

          stats:
            enabled: yes
            interval: 10s

          outputs:
            - fast:
                enabled: yes
                filename: fast.log
            - eve-log:
                enabled: yes
                filetype: regular
                filename: eve.json
                types: [alert, http, dns, tls]

          af-packet:
            - interface: {{ iface_detected.stdout }}
              cluster-id: 99
              cluster-type: cluster_flow
              defrag: yes

          default-rule-path: /var/lib/suricata/rules
          rule-files:
            - suricata.rules

    - name: 4. Crear regla de alerta ICMP (Test)
      copy:
        dest: /var/lib/suricata/rules/suricata.rules
        content: |
          alert icmp any any -> any any (msg:"ALERTA: Ping Detectado"; sid:1000001; rev:1;)

    - name: 5. Validar y Reiniciar Servicio
      systemd:
        name: suricata
        state: restarted
        enabled: true
        daemon_reload: true

    - name: 6. Verificar estado activo
      command: systemctl is-active suricata
      register: suri_status
      changed_when: false

    - debug:
        msg: "Suricata activo en {{ iface_detected.stdout }} (IP: {{ inventory_hostname }})"
EOF



echo "[3/3] EJECUTANDO DESPLIEGUE ANSIBLE"
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/inventory/hosts.ini" "$BASE_DIR/playbooks/suricata-aio.yml"; then
    echo "----------------------------------------------------"
    echo "  SURICATA INSTALADO Y MONITORIZANDO EN $TARGET_IP"
    echo "----------------------------------------------------"
else
    echo "  ERROR en la instalación de Suricata."
    exit 1
fi

# --- 3. LIMPIEZA FINAL ---
rm -rf "$BASE_DIR"