#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ---
INSTANCE_NAME="attack 2" # Recomendado instalarlo en el server de gestión
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"
BASE_DIR="$HOME/ansible/nmap-auto"

echo "===================================================="
echo " [1/3] PREPARANDO ENTORNO PARA NMAP"
echo "===================================================="

TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [[ -z "${TARGET_IP:-}" ]]; then
  echo "ERROR: No se encontró IP para $INSTANCE_NAME"
  exit 1
fi

mkdir -p "$BASE_DIR"/{inventory,playbooks}

# Generar Inventario
cat > "$BASE_DIR/inventory/hosts.ini" <<EOF
[scanner_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

echo "[2/3] CREANDO PLAYBOOK DE NMAP"

cat > "$BASE_DIR/playbooks/nmap-install.yml" <<'EOF'
---
- name: Instalación de Suite Nmap
  hosts: scanner_host
  become: true
  tasks:
    - name: 1. Instalar Nmap y herramientas de red
      apt:
        name: 
          - nmap
          - ncat
          - ndiff
        state: present
        update_cache: true

    - name: 2. Actualizar base de datos de scripts NSE
      command: nmap --script-updatedb
      changed_when: false

    - name: 3. Verificar instalación
      command: nmap --version
      register: nmap_ver
      changed_when: false

    - debug:
        msg: "Nmap instalado correctamente: {{ nmap_ver.stdout_lines[0] }}"
EOF

echo "[3/3] EJECUTANDO ANSIBLE"
ansible-playbook -i "$BASE_DIR/inventory/hosts.ini" "$BASE_DIR/playbooks/nmap-install.yml"