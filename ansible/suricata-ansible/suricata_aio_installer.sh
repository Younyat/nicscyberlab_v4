#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  SURICATA FULL AUTO DEPLOY (CLEAN INSTALL) - 2025
# ============================================================

# --- CONFIGURACIÓN ---
INSTANCE_NAME="victim 3"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"
BASE_DIR="$HOME/ansible/suricata-auto"

echo "===================================================="
echo " [1/3] DETECTANDO IP Y PREPARANDO ENTORNO"
echo "===================================================="

TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [[ -z "${TARGET_IP:-}" ]]; then
  echo "ERROR: No se encontró la IP para $INSTANCE_NAME"
  exit 1
fi

mkdir -p "$BASE_DIR"/{inventory,playbooks}

# Generar Inventario
cat > "$BASE_DIR/inventory/hosts.ini" <<EOF
[suricata]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

echo "[2/3] CREANDO PLAYBOOK DE CONFIGURACIÓN LIMPIA"

cat > "$BASE_DIR/playbooks/suricata-aio.yml" <<'EOF'
---
- name: Instalación Definitiva de Suricata
  hosts: suricata
  become: true
  tasks:
    - name: Instalar Suricata y dependencias
      apt:
        name: [suricata, jq, curl]
        state: present
        update_cache: true

    - name: Detectar Interfaz Activa
      shell: "ip route get 8.8.8.8 | awk '{print $5; exit}'"
      register: iface_detected
      changed_when: false

    - name: Escribir suricata.yaml (Configuración Mínima Robusta)
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
            interval: 8s

          outputs:
            - fast:
                enabled: yes
                filename: fast.log
            - eve-log:
                enabled: yes
                filetype: regular
                filename: eve.json
                types:
                  - alert
                  - http
                  - dns

          af-packet:
            - interface: {{ iface_detected.stdout }}
              cluster-id: 99
              cluster-type: cluster_flow
              defrag: yes

          logging:
            outputs:
              - console:
                  enabled: yes
              - file:
                  enabled: yes
                  filename: suricata.log

          default-rule-path: /var/lib/suricata/rules
          rule-files:
            - suricata.rules

    - name: Crear regla de prueba (ICMP Alert)
      copy:
        dest: /var/lib/suricata/rules/suricata.rules
        content: |
          alert icmp any any -> any any (msg:"TEST: Ping Detectado"; sid:1000001; rev:1;)

    - name: Validar configuración
      command: suricata -T -c /etc/suricata/suricata.yaml
      register: test_result

    - name: Reiniciar y Habilitar Suricata
      systemd:
        name: suricata
        state: restarted
        enabled: true

    - name: Verificar estado final
      command: systemctl is-active suricata
      register: suri_status

    - debug:
        msg: "Suricata desplegado con éxito en {{ iface_detected.stdout }}. Estado: {{ suri_status.stdout }}"
EOF

echo "[3/3] EJECUTANDO DESPLIEGUE"
ansible-playbook -i "$BASE_DIR/inventory/hosts.ini" "$BASE_DIR/playbooks/suricata-aio.yml"

echo "===================================================="
echo " ✅ TODO LISTO"
echo " Haz un 'ping $TARGET_IP' y revisa /var/log/suricata/fast.log"
echo "===================================================="