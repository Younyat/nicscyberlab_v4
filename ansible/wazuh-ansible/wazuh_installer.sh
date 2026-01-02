#!/usr/bin/env bash
set -euo pipefail

# --- CONFIGURACIÓN ÚNICA ---
INSTANCE_NAME="Wazuh-Server-Single"
SSH_USER="ubuntu"
SSH_KEY="$HOME/.ssh/my_key"

# La única contraseña que usaremos para todo
ADMIN_PASS="admin" 

BASE_DIR="$HOME/ansible/wazuh-auto"

echo "===================================================="
echo " DETECTANDO ENTORNO OPENSTACK"
echo "===================================================="

# Obtener la IP Flotante automáticamente
TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [ -z "$TARGET_IP" ]; then
    echo "ERROR: No se pudo encontrar la IP flotante para $INSTANCE_NAME"
    exit 1
fi

echo "IP de despliegue: $TARGET_IP"

# 1. Preparación de privilegios y SSH
echo "[1/5] Configurando privilegios sudo y verificando SSH..."
# Esto soluciona el error de "Timeout waiting for privilege escalation prompt"
ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$SSH_USER@$TARGET_IP" << EOF
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/ansible_nopasswd
    echo "SSH_READY"
EOF

# 2. Preparar repositorio
echo "[2/5] Configurando repositorio Wazuh v4.7.3..."
mkdir -p "$BASE_DIR"
cd "$BASE_DIR"
if [ ! -d "wazuh-ansible" ]; then
    git clone https://github.com/wazuh/wazuh-ansible.git
fi
cd wazuh-ansible
git checkout v4.7.3 --quiet

# 3. Generar Inventario y Variables
echo "[3/5] Generando configuración de Ansible..."
mkdir -p vars inventories/production

cat > vars/repo_vars.yml <<EOF
wazuh_manager_install: true
wazuh_indexer_install: true
wazuh_dashboard_install: true
wazuh_api_user: admin
wazuh_api_password: $ADMIN_PASS
wazuh_indexer_admin_user: admin
wazuh_indexer_admin_password: $ADMIN_PASS
EOF

cat > inventories/production/hosts <<EOF
[aio]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY

[wazuh-manager:children]
aio
[wazuh-indexer:children]
aio
[wazuh-dashboard:children]
aio
EOF

# 4. Ejecución de Ansible
echo "[4/5] Instalando Wazuh (Playbook)..."
export ANSIBLE_ROLES_PATH="./roles"
# Aumentamos el timeout para evitar cortes en tareas pesadas como Filebeat
export ANSIBLE_BECOME_TIMEOUT=30

ansible-playbook -i inventories/production/hosts playbooks/wazuh-single.yml

# 5. APLICAR SEGURIDAD EN INDEXER (Hash y SecurityAdmin)
echo "[5/5] Aplicando configuración de seguridad profesional..."



ssh -i "$SSH_KEY" "$SSH_USER@$TARGET_IP" << EOF
    set -e
    echo ">>> Generando Hash del password..."
    # Ejecutamos el Hasher de Java de OpenSearch/Wazuh
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

echo "===================================================="
echo " ✅ PROCESO COMPLETADO EXITOSAMENTE"
echo "===================================================="
echo " URL      : https://$TARGET_IP"
echo " USUARIO  : admin"
echo " PASSWORD : $ADMIN_PASS"
echo "===================================================="