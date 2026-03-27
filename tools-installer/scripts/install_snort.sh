#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  SNORT 3 + LIBDAQ + PCRE2 DEPLOYER (ANSIBLE)
#  Resuelve dependencias de compilacion para Debian 12
# ============================================================

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="snort3_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No se proporciono la IP de destino."
    exit 1
fi

BASE_DIR="/tmp/ansible_snort_$INSTANCE_ID"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[snort_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/snort-install.yml" <<'EOF'
---
- name: Instalacion Definitiva de Snort 3
  hosts: snort_host
  become: true
  vars:
    src_root: "/opt/snort_build"
    daq_dir: "{{ src_root }}/libdaq"
    snort_dir: "{{ src_root }}/snort3"
  tasks:
    - name: 1. Instalar todas las dependencias (incluyendo PCRE2 y UUID)
      apt:
        update_cache: true
        name:
          - build-essential
          - cmake
          - git
          - flex
          - bison
          - libpcap-dev
          - libpcre2-dev
          - libdumbnet-dev
          - zlib1g-dev
          - luajit
          - libluajit-5.1-dev
          - libssl-dev
          - pkg-config
          - libhwloc-dev
          - libhyperscan-dev
          - libtirpc-dev
          - libnghttp2-dev
          - liblzma-dev
          - autoconf
          - libtool
          - uuid-dev
        state: present

    - name: 2. Preparar directorios
      file:
        path: "{{ src_root }}"
        state: directory

    - name: 3. Compilar LibDAQ (Si no existe)
      shell: |
        git clone https://github.com/snort3/libdaq.git {{ daq_dir }} || cd {{ daq_dir }}
        cd {{ daq_dir }}
        ./bootstrap
        ./configure
        make -j$(nproc)
        make install
      args:
        creates: /usr/local/lib/libdaq.so

    - name: 4. Actualizar enlaces de librerias
      command: ldconfig

    - name: 5. Compilar Snort 3
      shell: |
        git clone https://github.com/snort3/snort3.git {{ snort_dir }} || cd {{ snort_dir }}
        cd {{ snort_dir }}
        mkdir -p build && cd build
        cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
        make -j$(nproc)
        make install
      args:
        creates: /usr/local/bin/snort

    - name: 6. Configurar entorno Snort 3
      file:
        path: "{{ item }}"
        state: directory
      loop:
        - /etc/snort
        - /etc/snort/rules
        - /etc/snort/builtin_rules
        - /var/log/snort

    - name: 7. Crear regla local de prueba
      copy:
        dest: /etc/snort/rules/local.rules
        content: 'alert icmp any any -> any any (msg:"ALERTA SNORT: ICMP Detectado"; sid:10001; rev:1;)'

    - name: 8. Validar binario final
      command: /usr/local/bin/snort --version
      register: snort_version

    - debug:
        msg: "Exito: {{ snort_version.stdout_lines[0] }}"
EOF



echo "===================================================="
echo " REINTENTANDO COMPILACION CON PCRE2"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/snort-install.yml"; then
    echo "----------------------------------------------------"
    echo "  SNORT 3 INSTALADO CON EXITO"
    echo "----------------------------------------------------"
else
    echo "  Fallo critico. Revisa los logs de CMake."
    exit 1
fi

rm -rf "$BASE_DIR"