#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  NMAP SUITE DYNAMIC DEPLOYER
#  Filosofía: Basado en IP, compatible con Master Orchestrator
# ============================================================

# --- 1. PARÁMETROS RECIBIDOS ---
# El Master envía: $1=IP, $2=User
TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"

# Variables de entorno y rutas
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="nmap_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo " ERROR: No se proporcionó la IP de destino para Nmap."
    exit 1
fi

# --- 2. PREPARACIÓN DE ENTORNO TEMPORAL ---
BASE_DIR="/tmp/ansible_nmap_$INSTANCE_ID"
mkdir -p "$BASE_DIR"/{inventory,playbooks}

echo "===================================================="
echo " [1/3] CONFIGURANDO ESCÁNER EN: $TARGET_IP"
echo "===================================================="

# Generar Inventario Dinámico
cat > "$BASE_DIR/inventory/hosts.ini" <<EOF
[scanner_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

echo "[2/3] GENERANDO PLAYBOOK DE INSTALACIÓN"

cat > "$BASE_DIR/playbooks/nmap-install.yml" <<'EOF'
---
- name: Instalación de Suite Nmap Profesional
  hosts: scanner_host
  become: true
  tasks:
    - name: 1. Instalar Nmap, Ncat y Ndiff
      apt:
        name: 
          - nmap
          - ncat
          - ndiff
          - tcpdump
        state: present
        update_cache: true

    - name: 2. Descargar dependencias para scripts NSE
      apt:
        name: [lua-lpeg, libblas3]
        state: present

    - name: 3. Actualizar base de datos de scripts NSE
      command: nmap --script-updatedb
      changed_when: false

    - name: 4. Verificar binarios instalados
      command: "{{ item }} --version"
      loop:
        - nmap
        - ncat
      register: tool_check
      changed_when: false

    - debug:
        msg: "Suite Nmap lista en {{ inventory_hostname }}. Versión: {{ tool_check.results[0].stdout_lines[0] }}"
EOF



echo "[3/3] EJECUTANDO DESPLIEGUE ANSIBLE"
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/inventory/hosts.ini" "$BASE_DIR/playbooks/nmap-install.yml"; then
    echo "----------------------------------------------------"
    echo "  NMAP INSTALADO EXITOSAMENTE EN $TARGET_IP"
    echo "----------------------------------------------------"
else
    echo "  ERROR en la instalación de Nmap."
    exit 1
fi

# --- 3. LIMPIEZA FINAL ---
rm -rf "$BASE_DIR"