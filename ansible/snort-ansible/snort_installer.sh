#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
INSTANCE_NAME="victim 3"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

# Variables de Red
SNORT_HOME_NET="10.0.2.0/24"
BASE_DIR="$HOME/ansible/snort-auto"

echo "===================================================="
echo " [1/3] PREPARANDO ENTORNO PARA SNORT"
echo "===================================================="

TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [[ -z "${TARGET_IP:-}" ]]; then
  echo "ERROR: No se encontró IP para $INSTANCE_NAME"
  exit 1
fi

mkdir -p "$BASE_DIR"/{inventory,playbooks}

# Generar Inventario
cat > "$BASE_DIR/inventory/hosts.ini" <<EOF
[snort_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

echo "[2/3] CREANDO PLAYBOOK DE SNORT"

cat > "$BASE_DIR/playbooks/snort-install.yml" <<'EOF'
---
- name: Instalación de Snort NIDS
  hosts: snort_host
  become: true
  tasks:
    - name: 1. Instalar Snort y dependencias
      apt:
        name: [snort, jq, tcpdump]
        state: present
        update_cache: true

    - name: 2. Detectar Interfaz
      shell: "ip route get 8.8.8.8 | awk '{print $5; exit}'"
      register: iface_detected

    - name: 3. Configurar HOME_NET en snort.conf
      lineinfile:
        path: /etc/snort/snort.conf
        regexp: '^ipvar HOME_NET'
        line: 'ipvar HOME_NET {{ snort_home_net }}'

    - name: 4. Configurar EXTERNAL_NET
      lineinfile:
        path: /etc/snort/snort.conf
        regexp: '^ipvar EXTERNAL_NET'
        line: 'ipvar EXTERNAL_NET !$HOME_NET'

    - name: 5. Crear regla de prueba personalizada
      copy:
        dest: /etc/snort/rules/local.rules
        content: |
          alert icmp any any -> $HOME_NET any (msg:"ALERTA SNORT: Ping Detectado"; sid:1000001; rev:1;)

    - name: 6. Validar configuración de Snort
      command: "snort -T -c /etc/snort/snort.conf"
      register: snort_test
      changed_when: false

    - name: 7. Asegurar que Snort use la interfaz correcta (Config Debian)
      lineinfile:
        path: /etc/snort/snort.debian.conf
        regexp: '^DEBIAN_SNORT_INTERFACE='
        line: 'DEBIAN_SNORT_INTERFACE="{{ iface_detected.stdout }}"'

    - name: 8. Reiniciar servicio Snort
      systemd:
        name: snort
        state: restarted
        enabled: true

    - name: Verificar estado
      command: systemctl is-active snort
      register: status
    
    - debug:
        msg: "Snort activo en {{ iface_detected.stdout }}. Estado: {{ status.stdout }}"
EOF

echo "[3/3] EJECUTANDO ANSIBLE"
ansible-playbook -i "$BASE_DIR/inventory/hosts.ini" "$BASE_DIR/playbooks/snort-install.yml" -e "snort_home_net=$SNORT_HOME_NET"