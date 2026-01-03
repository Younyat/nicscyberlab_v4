#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  NMAP & NCAT UNINSTALLER (TOTAL CLEANUP)
# ============================================================

# --- 1. CONFIGURACIÓN DE RUTAS RELATIVAS ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Subimos niveles para llegar a la raíz del proyecto
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../" && pwd)"
ADMIN_OPENRC="$PROJECT_ROOT/admin-openrc.sh"

# --- 2. CARGAR ENTORNO OPENSTACK ---
if [[ -f "$ADMIN_OPENRC" ]]; then 
    source "$ADMIN_OPENRC"
    echo "[OK] Credenciales OpenStack cargadas."
    
    # Verificación de seguridad: ¿Token válido?
    if ! openstack token issue &>/dev/null; then
        echo "ERROR: Las credenciales de OpenStack han expirado o son incorrectas."
        exit 1
    fi
else 
    echo "ERROR: No se encontró admin-openrc.sh en $ADMIN_OPENRC"
    exit 1
fi

# --- 3. PARÁMETROS ---
# Recibe el nombre de la instancia (ej: "attack 2") y la llave desde Python
INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-$HOME/.ssh/my_key}"
SSH_USER="debian" 

if [[ -z "$INSTANCE_NAME" ]]; then
    echo "ERROR: No se recibió el nombre de la instancia (INSTANCE_NAME)."
    exit 1
fi

# --- 4. DETECCIÓN DINÁMICA DE IP ---
echo " Buscando IP para Nmap en: $INSTANCE_NAME..."
TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [[ -z "$TARGET_IP" ]]; then
    echo " Error: No se pudo encontrar la IP interna para $INSTANCE_NAME"
    exit 1
fi

# Carpeta temporal para el proceso de Ansible
TEMP_WORK_DIR="/tmp/ansible_nmap_cleanup_$INSTANCE_NAME"
mkdir -p "$TEMP_WORK_DIR"

# --- 5. GENERACIÓN DE INVENTARIO Y PLAYBOOK ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

cat > "$TEMP_WORK_DIR/nmap-cleanup.yml" <<'EOF'
---
- name: Borrado de la suite Nmap
  hosts: target
  become: true
  tasks:
    - name: 1. Eliminar paquetes de Nmap (nmap, ncat, ndiff)
      apt:
        name: 
          - nmap
          - ncat
          - ndiff
        state: absent
        purge: true

    - name: 2. Limpiar dependencias y archivos huérfanos
      apt:
        autoremove: true
        purge: true

    - name: 3. Limpiar caché de apt
      apt:
        autoclean: true

    - name: 4. Limpiar sudoers de Ansible
      file:
        path: /etc/sudoers.d/ansible_nopasswd
        state: absent
EOF

# --- 6. EJECUCIÓN DE ANSIBLE ---
echo "===================================================="
echo "  ELIMINANDO NMAP DE $INSTANCE_NAME ($TARGET_IP)"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/nmap-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no'

# --- 7. LIMPIEZA FINAL ---
rm -rf "$TEMP_WORK_DIR"

echo "===================================================="
echo "  PROCESO FINALIZADO - NMAP ELIMINADO"
echo "===================================================="