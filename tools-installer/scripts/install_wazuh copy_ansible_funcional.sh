#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH AIO DYNAMIC DEPLOYER (INDEXER + MANAGER + DASHBOARD)
#  Filosofía: Basado en IP, sin dependencia estricta de nombre
# ============================================================

# --- 1. PROCESAMIENTO DE ARGUMENTOS ---
# El Master envía: $1=IP, $2=User
TARGET_IP="${1:-}"
SSH_USER="${2:-ubuntu}"

# Configuraciones fijas o derivadas
SSH_KEY="$HOME/.ssh/my_key"
ADMIN_PASS="admin" 

# Validamos que al menos tengamos la IP
if [[ -z "$TARGET_IP" ]]; then
    echo " ERROR: No se proporcionó la IP de destino."
    exit 1
fi

# Si no recibimos nombre de instancia, creamos uno a partir de la IP
# Ejemplo: 10.0.2.23 -> wazuh_10_0_2_23
INSTANCE_ID="wazuh_$(echo "$TARGET_IP" | tr '.' '_')"

# --- 2. PREPARACIÓN DE ENTORNO TEMPORAL ---
BASE_DIR="/tmp/wazuh_deploy_$INSTANCE_ID"
mkdir -p "$BASE_DIR"

echo "===================================================="
echo " [1/5] CONFIGURANDO ACCESO SSH: $TARGET_IP"
echo "===================================================="

# Configurar sudo sin contraseña para el despliegue
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_IP" << EOF
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/ansible_nopasswd
EOF

echo "[2/5] CLONANDO REPOSITORIO WAZUH-ANSIBLE"
cd "$BASE_DIR"
if [ ! -d "wazuh-ansible" ]; then
    git clone --depth 1 -b v4.7.3 https://github.com/wazuh/wazuh-ansible.git
fi
cd wazuh-ansible



echo "[3/5] GENERANDO CONFIGURACIÓN DINÁMICA"
mkdir -p vars inventories/production

# Variables para el despliegue
cat > vars/repo_vars.yml <<EOF
wazuh_manager_install: true
wazuh_indexer_install: true
wazuh_dashboard_install: true
wazuh_api_user: admin
wazuh_api_password: $ADMIN_PASS
wazuh_indexer_admin_user: admin
wazuh_indexer_admin_password: $ADMIN_PASS
EOF

# Inventario basado exclusivamente en la IP recibida
cat > inventories/production/hosts <<EOF
[aio]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'

[wazuh-manager:children]
aio
[wazuh-indexer:children]
aio
[wazuh-dashboard:children]
aio
EOF

echo "[4/5] EJECUTANDO ANSIBLE PLAYBOOK (PROCESO PESADO)"
export ANSIBLE_ROLES_PATH="./roles"
export ANSIBLE_BECOME_TIMEOUT=60
export ANSIBLE_HOST_KEY_CHECKING=False

ansible-playbook -i inventories/production/hosts playbooks/wazuh-single.yml

echo "[5/5] POST-CONFIGURACIÓN DE SEGURIDAD (INDEXER)"

ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << EOF
    set -e
    echo ">>> Generando Hash de seguridad..."
    HASH=\$(sudo /usr/share/wazuh-indexer/jdk/bin/java -cp "/usr/share/wazuh-indexer/plugins/opensearch-security/*:/usr/share/wazuh-indexer/lib/*" org.opensearch.security.tools.Hasher -p "$ADMIN_PASS" | tail -n 1)
    
    echo ">>> Inyectando Hash en internal_users.yml..."
    sudo sed -i "/admin:/,/hash:/ s|hash:.*|hash: \"\$HASH\"|" /etc/wazuh-indexer/opensearch-security/internal_users.yml

    echo ">>> Aplicando cambios con securityadmin.sh..."
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    sudo -E /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      -cd /etc/wazuh-indexer/opensearch-security/ \
      -icl -nhnv \
      -cacert /etc/wazuh-indexer/certs/root-ca.pem \
      -cert /etc/wazuh-indexer/certs/admin.pem \
      -key /etc/wazuh-indexer/certs/admin-key.pem \
      -h 127.0.0.1
EOF

# --- 3. LIMPIEZA ---
rm -rf "$BASE_DIR"

echo "===================================================="
echo "  WAZUH DESPLEGADO EN: $TARGET_IP"
echo " Acceso: https://$TARGET_IP (admin / $ADMIN_PASS)"
echo "===================================================="