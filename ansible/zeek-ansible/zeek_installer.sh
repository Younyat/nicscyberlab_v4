#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
INSTANCE_NAME="Wazuh-Server-Single"
SSH_USER="ubuntu"
SSH_KEY="$HOME/.ssh/my_key"
BASE_DIR="$HOME/ansible/zeek-auto"

echo "===================================================="
echo " [1/3] PREPARANDO ENTORNO PARA ZEEK"
echo "===================================================="

TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [[ -z "${TARGET_IP:-}" ]]; then
  echo "ERROR: No se encontró IP para $INSTANCE_NAME"
  exit 1
fi

mkdir -p "$BASE_DIR"/{inventory,playbooks}

# Generar Inventario
cat > "$BASE_DIR/inventory/hosts.ini" <<EOF
[zeek_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

echo "[2/3] CREANDO PLAYBOOK DE ZEEK"

cat > "$BASE_DIR/playbooks/zeek-install.yml" <<'EOF'
---
- name: Instalación de Zeek Network Monitor
  hosts: zeek_host
  become: true
  tasks:
    - name: 1. Instalar dependencias iniciales
      apt:
        name: [curl, gnupg2, ca-certificates, procps]
        state: present
        update_cache: true

    - name: 2. Añadir repositorio oficial de Zeek
      shell: |
        echo 'deb http://download.opensuse.org/repositories/network:/zeek/Debian_12/ /' | tee /etc/apt/sources.list.d/network:zeek.list
        curl -fsSL https://download.opensuse.org/repositories/network:/zeek/Debian_12/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/network_zeek.gpg > /dev/null
      args:
        creates: /etc/apt/sources.list.d/network:zeek.list

    - name: 3. Instalar Zeek
      apt:
        name: zeek-6.0 # Versión LTS actual
        state: present
        update_cache: true

    - name: 4. Añadir Zeek al PATH del sistema
      lineinfile:
        path: /etc/environment
        line: 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/zeek/bin"'
        state: present

    - name: 5. Detectar Interfaz
      shell: "ip route get 8.8.8.8 | awk '{print $5; exit}'"
      register: iface_detected

    - name: 6. Configurar interfaz en node.cfg
      lineinfile:
        path: /opt/zeek/etc/node.cfg
        regexp: '^interface='
        line: "interface={{ iface_detected.stdout }}"

    - name: 7. Desplegar e iniciar Zeek vía ZeekControl
      command: "{{ item }}"
      loop:
        - /opt/zeek/bin/zeekctl install
        - /opt/zeek/bin/zeekctl start
      changed_when: false

    - name: 8. Verificar estado
      command: /opt/zeek/bin/zeekctl status
      register: zeek_status

    - debug:
        var: zeek_status.stdout_lines
EOF

echo "[3/3] EJECUTANDO ANSIBLE"
ansible-playbook -i "$BASE_DIR/inventory/hosts.ini" "$BASE_DIR/playbooks/zeek-install.yml"