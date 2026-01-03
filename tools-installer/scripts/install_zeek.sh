#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# CONFIGURACIÓN
# ============================================================================
TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="zeek_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "❌ ERROR: No se proporcionó la IP de destino."
    echo "Uso: $0 <IP_DESTINO> [SSH_USER]"
    exit 1
fi

BASE_DIR="/tmp/ansible_zeek_$INSTANCE_ID"
mkdir -p "$BASE_DIR"/{inventory,playbooks}

# ============================================================================
# CREAR INVENTARIO
# ============================================================================
cat > "$BASE_DIR/inventory/hosts.ini" <<EOF
[zeek_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

# ============================================================================
# CREAR PLAYBOOK CORREGIDO
# ============================================================================
cat > "$BASE_DIR/playbooks/zeek-install.yml" <<'EOF'
---
- name: Zeek Source Installation (Robust)
  hosts: zeek_host
  become: true
  vars:
    zeek_version: "6.0.5"
    install_prefix: "/opt/zeek"
    
  tasks:
    # ------------------------------------------------------------------------
    # PASO 1: LIMPIEZA DE REPOSITORIOS PROBLEMÁTICOS
    # ------------------------------------------------------------------------
    - name: 1️⃣ Limpiar repositorios de Zeek previos
      shell: |
        rm -f /etc/apt/sources.list.d/network:zeek.list
        rm -f /etc/apt/sources.list.d/zeek.list
        rm -f /etc/apt/trusted.gpg.d/network_zeek.gpg
        rm -f /usr/share/keyrings/zeek-archive-keyring.gpg
      ignore_errors: true
      
    - name: 1️⃣.1 Limpiar repositorio problemático de Wazuh (opcional)
      shell: |
        # Comentar o eliminar repo de Wazuh si causa problemas
        if [ -f /etc/apt/sources.list.d/wazuh.list ]; then
          mv /etc/apt/sources.list.d/wazuh.list /etc/apt/sources.list.d/wazuh.list.bak
        fi
      ignore_errors: true
    
    # ------------------------------------------------------------------------
    # PASO 2: INSTALAR DEPENDENCIAS PARA COMPILACIÓN
    # ------------------------------------------------------------------------
    - name: 2️⃣ Actualizar cache de apt (limpio)
      apt:
        update_cache: yes
        cache_valid_time: 3600
      retries: 3
      delay: 5
      
    - name: 2️⃣.1 Instalar dependencias de compilación
      apt:
        name:
          - cmake
          - make
          - gcc
          - g++
          - flex
          - bison
          - libpcap-dev
          - libssl-dev
          - python3
          - python3-dev
          - swig
          - zlib1g-dev
          - libmaxminddb-dev
          - libjemalloc-dev
          - git
          - curl
          - wget
        state: present
        update_cache: no
      retries: 3
      delay: 5
    
    # ------------------------------------------------------------------------
    # PASO 3: DESCARGAR Y COMPILAR ZEEK DESDE FUENTE
    # ------------------------------------------------------------------------
    - name: 3️⃣ Verificar si Zeek ya está instalado
      stat:
        path: "{{ install_prefix }}/bin/zeek"
      register: zeek_binary
      
    - name: 3️⃣.1 Descargar código fuente de Zeek
      get_url:
        url: "https://download.zeek.org/zeek-{{ zeek_version }}.tar.gz"
        dest: "/tmp/zeek-{{ zeek_version }}.tar.gz"
        timeout: 300
      when: not zeek_binary.stat.exists
      
    - name: 3️⃣.2 Extraer código fuente
      unarchive:
        src: "/tmp/zeek-{{ zeek_version }}.tar.gz"
        dest: /tmp/
        remote_src: yes
      when: not zeek_binary.stat.exists
      
    - name: 3️⃣.3 Configurar compilación
      command: >
        ./configure 
        --prefix={{ install_prefix }}
        --enable-jemalloc
      args:
        chdir: "/tmp/zeek-{{ zeek_version }}"
        creates: "/tmp/zeek-{{ zeek_version }}/build/Makefile"
      when: not zeek_binary.stat.exists
      
    - name: 3️⃣.4 Compilar Zeek (esto puede tardar 10-30 min)
      command: make -j{{ ansible_processor_vcpus }}
      args:
        chdir: "/tmp/zeek-{{ zeek_version }}/build"
      when: not zeek_binary.stat.exists
      async: 3600
      poll: 30
      
    - name: 3️⃣.5 Instalar Zeek
      command: make install
      args:
        chdir: "/tmp/zeek-{{ zeek_version }}/build"
      when: not zeek_binary.stat.exists
      
    # ------------------------------------------------------------------------
    # PASO 4: CONFIGURAR ZEEK
    # ------------------------------------------------------------------------
    - name: 4️⃣ Detectar interfaz de red principal
      shell: |
        ip -4 route show default | awk '{print $5}' | head -n1
      register: network_interface
      changed_when: false
      
    - name: 4️⃣.1 Configurar interfaz en node.cfg
      lineinfile:
        path: "{{ install_prefix }}/etc/node.cfg"
        regexp: '^interface='
        line: "interface={{ network_interface.stdout }}"
        
    - name: 4️⃣.2 Agregar Zeek al PATH del sistema
      lineinfile:
        path: /etc/profile.d/zeek.sh
        line: 'export PATH={{ install_prefix }}/bin:$PATH'
        create: yes
        mode: '0644'
        
    - name: 4️⃣.3 Desplegar configuración con zeekctl
      shell: |
        {{ install_prefix }}/bin/zeekctl install
      args:
        executable: /bin/bash
        
    # ------------------------------------------------------------------------
    # PASO 5: INICIAR ZEEK
    # ------------------------------------------------------------------------
    - name: 5️⃣ Iniciar Zeek
      shell: |
        {{ install_prefix }}/bin/zeekctl start
      args:
        executable: /bin/bash
      register: zeek_start
      
    - name: 5️⃣.1 Verificar estado de Zeek
      shell: |
        {{ install_prefix }}/bin/zeekctl status
      register: zeek_status
      changed_when: false
      
    # ------------------------------------------------------------------------
    # PASO 6: VERIFICACIÓN Y LIMPIEZA
    # ------------------------------------------------------------------------
    - name: 6️⃣ Verificar versión instalada
      command: "{{ install_prefix }}/bin/zeek --version"
      register: zeek_version_output
      changed_when: false
      
    - name: 6️⃣.1 Limpiar archivos temporales
      file:
        path: "/tmp/zeek-{{ zeek_version }}"
        state: absent
      ignore_errors: true
      
    - name: 6️⃣.2 Limpiar tarball
      file:
        path: "/tmp/zeek-{{ zeek_version }}.tar.gz"
        state: absent
      ignore_errors: true
      
    # ------------------------------------------------------------------------
    # PASO 7: MOSTRAR RESULTADOS
    # ------------------------------------------------------------------------
    - name: ✅ Resumen de instalación
      debug:
        msg:
          - "=========================================="
          - "ZEEK INSTALADO CORRECTAMENTE"
          - "=========================================="
          - "Versión: {{ zeek_version_output.stdout }}"
          - "Ruta: {{ install_prefix }}"
          - "Interfaz: {{ network_interface.stdout }}"
          - "Estado: {{ zeek_status.stdout_lines }}"
          - "=========================================="
          - "Comandos útiles:"
          - "  zeekctl status    - Ver estado"
          - "  zeekctl restart   - Reiniciar"
          - "  zeekctl stop      - Detener"
          - "  zeek --version    - Ver versión"
          - "=========================================="
EOF

# ============================================================================
# EJECUTAR DESPLIEGUE
# ============================================================================
echo "===================================================="
echo " 🧠 ZEEK FULL AUTO DEPLOY (SOURCE BUILD)"
echo "===================================================="
echo " Target : $SSH_USER@$TARGET_IP"
echo "===================================================="
echo "[1/1] 🚀 Ejecutando instalación Zeek"
echo ""

export ANSIBLE_HOST_KEY_CHECKING=False
export ANSIBLE_STDOUT_CALLBACK=yaml

if ansible-playbook \
    -i "$BASE_DIR/inventory/hosts.ini" \
    "$BASE_DIR/playbooks/zeek-install.yml" \
    -v; then
    
    echo ""
    echo "===================================================="
    echo " ✅ ZEEK DESPLEGADO EXITOSAMENTE"
    echo "===================================================="
    echo ""
    echo "Para verificar en el servidor remoto:"
    echo "  ssh $SSH_USER@$TARGET_IP 'sudo /opt/zeek/bin/zeekctl status'"
    echo ""
    echo "Para ver logs:"
    echo "  ssh $SSH_USER@$TARGET_IP 'sudo tail -f /opt/zeek/logs/current/*.log'"
    echo ""
    
else
    echo ""
    echo "===================================================="
    echo " ❌ FALLO EN EL DESPLIEGUE"
    echo "===================================================="
    echo ""
    echo "Para diagnóstico manual, conecta al servidor:"
    echo "  ssh $SSH_USER@$TARGET_IP"
    echo ""
    echo "Y verifica:"
    echo "  - sudo journalctl -xe"
    echo "  - sudo apt update"
    echo "  - ping -c 3 download.zeek.org"
    echo ""
    exit 1
fi

# ============================================================================
# LIMPIEZA
# ============================================================================
rm -rf "$BASE_DIR"