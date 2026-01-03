#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NMAP & NCAT UNINSTALLER - INTEGRATED VERSION
# ============================================================

# 1. PARAMETROS RECIBIDOS DESDE PYTHON
# ------------------------------------------------------------
INSTANCE_NAME="${1:-}"  # Nombre de la instancia
SSH_KEY="${2:-}"        # Ruta de la clave privada
TARGET_IP="${3:-}"      # IP ya detectada por Python
SSH_USER="${4:-}"       # Usuario ya confirmado por Python

# Validacion de argumentos para evitar ejecuciones fallidas
if [[ -z "$INSTANCE_NAME" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Argumentos insuficientes. Se requiere Instance, Key, IP y User."
    exit 1
fi

# 2. CONFIGURACION DE ENTORNO TEMPORAL
# ------------------------------------------------------------
# Limpiamos el nombre de la instancia para evitar errores con espacios en rutas
CLEAN_NAME="${INSTANCE_NAME// /_}"
TEMP_WORK_DIR="/tmp/ansible_nmap_cleanup_${CLEAN_NAME}"
mkdir -p "$TEMP_WORK_DIR"

echo "Preparando desinstalacion para $INSTANCE_NAME en $TARGET_IP con usuario $SSH_USER"

# 3. GENERACION DINAMICA DE INVENTARIO
# ------------------------------------------------------------
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY
EOF

# 4. GENERACION DEL PLAYBOOK DE ANSIBLE
# ------------------------------------------------------------
cat > "$TEMP_WORK_DIR/nmap-cleanup.yml" <<'EOF'
---
- name: Borrado completo de la suite Nmap y herramientas de red
  hosts: target
  become: true
  tasks:
    - name: 1. Eliminar paquetes especificos de la suite Nmap
      apt:
        name: 
          - nmap
          - ncat
          - ndiff
        state: absent
        purge: true
      register: apt_result

    - name: 2. Limpiar dependencias y paquetes huerfanos residuales
      apt:
        autoremove: true
        purge: true

    - name: 3. Limpiar cache de APT para liberar espacio
      apt:
        autoclean: true

    - name: 4. Eliminar configuraciones de usuario para nmap (si existen)
      file:
        path: "/home/{{ ansible_user }}/.nmap"
        state: absent

    - name: 5. Eliminar rastros de permisos temporales de Ansible
      file:
        path: /etc/sudoers.d/ansible_nopasswd
        state: absent
EOF

# 5. EJECUCION DEL PROCESO DE PURGA
# ------------------------------------------------------------
echo "Ejecutando purga de paquetes via Ansible..."
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/nmap-cleanup.yml" \
    --ssh-common-args='-o StrictHostKeyChecking=no -o ConnectTimeout=10'

# 6. LIMPIEZA DE ARCHIVOS TEMPORALES LOCALES
# ------------------------------------------------------------
rm -rf "$TEMP_WORK_DIR"

echo "Proceso finalizado: Nmap ha sido eliminado de $INSTANCE_NAME"