#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  CALDERA SERVER INSTALLER - ROBUST VERSION (No emojis)
#  Integra: Fix de Magma (npm), Health Checks y PEP 668
# ============================================================

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="caldera_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No se proporciono la IP de destino."
    exit 1
fi

TEMP_WORK_DIR="/tmp/ansible_caldera_$INSTANCE_ID"
mkdir -p "$TEMP_WORK_DIR"

# --- 1. GENERACION DE INVENTARIO ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[caldera_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no -o IdentitiesOnly=yes'
EOF

# --- 2. PLAYBOOK MEJORADO CON TU LOGICA ---
cat > "$TEMP_WORK_DIR/caldera-install.yml" <<'EOF'
---
- name: Instalacion Robusta de MITRE Caldera
  hosts: caldera_host
  become: true
  tasks:
    - name: 1. Instalar dependencias base y Node.js 20
      shell: |
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get -o DPkg::Lock::Timeout=120 install -y python3 python3-pip git build-essential nodejs libmagic-dev jq
      args:
        executable: /bin/bash

    # 2026-09-02: replaced Ansible's `git:` module (recursive clone, 17
    # submodules) with plain HTTPS tarball downloads via codeload.github.com.
    # Root cause: github.com's git-upload-pack smart-HTTP endpoint was found
    # to fail intermittently ("could not read Username ... HTTP 401") on
    # roughly half of all requests -- confirmed via direct repeated testing
    # from both the orchestrator host and a lab VM, ruling out network/DNS/
    # protocol-version as the cause. A `recursive: yes` clone needs ~18
    # separate git-upload-pack round-trips (1 main repo + 17 submodules) to
    # all succeed, which at ~50% per-request reliability explains why this
    # task specifically was timing out (900s) rather than failing fast like
    # a single-repo clone (see tools-installer/README.md 2026-09-02 for the
    # wazuh-ansible incident this was first found in). Tarball downloads
    # bypass git-upload-pack entirely and were 48/48 reliable across 3 full
    # end-to-end runs (main repo + all 16 currently-tracked submodules) in
    # verification testing. Submodule commits are read from one GitHub Trees
    # API call (mode 160000 entries), not 17 separate calls, to stay well
    # inside the unauthenticated API's 60/hour rate limit. Any submodule
    # listed in .gitmodules but no longer present in the tree (e.g.
    # `caltack` at write time) is skipped -- exactly what a real
    # `git clone --recursive` would also do, not a regression.
    - name: 2. Descargar Caldera y submodulos (sin protocolo git)
      shell: |
        set -e
        rm -rf /opt/caldera
        mkdir -p /opt/caldera
        cd /tmp
        for attempt in 1 2 3; do
          rm -f caldera.tar.gz
          if curl -fsSL --max-time 120 -o caldera.tar.gz \
              "https://codeload.github.com/mitre/caldera/tar.gz/refs/heads/master" \
            && tar xzf caldera.tar.gz -C /opt/caldera --strip-components=1; then
            break
          fi
          echo "[WARN] main repo download failed (attempt ${attempt}/3)."
          rm -rf /opt/caldera && mkdir -p /opt/caldera
          if [ "$attempt" -eq 3 ]; then
            echo "[ERROR] main repo download failed after 3 attempts."
            exit 1
          fi
          sleep 10
        done

        echo "aW1wb3J0IGpzb24sIHJlLCBzdWJwcm9jZXNzLCBvcywgc3lzLCB1cmxsaWIucmVxdWVzdAoKZGVmIGdldCh1cmwpOgogICAgcmVxID0gdXJsbGliLnJlcXVlc3QuUmVxdWVzdCh1cmwsIGhlYWRlcnM9eyJVc2VyLUFnZW50IjogIm5pY3MtY3liZXJsYWIifSkKICAgIHdpdGggdXJsbGliLnJlcXVlc3QudXJsb3BlbihyZXEsIHRpbWVvdXQ9MzApIGFzIHI6CiAgICAgICAgcmV0dXJuIHIucmVhZCgpCgpnbSA9IG9wZW4oIi9vcHQvY2FsZGVyYS8uZ2l0bW9kdWxlcyIpLnJlYWQoKQplbnRyaWVzID0gcmUuZmluZGFsbChyJ1xbc3VibW9kdWxlICIoW14iXSspIlxdXHMqXG5ccypwYXRoXHMqPVxzKihcUyspXHMqXG5ccyp1cmxccyo9XHMqKFxTKyknLCBnbSkKcGF0aF90b191cmwgPSB7cGF0aDogdXJsIGZvciBfLCBwYXRoLCB1cmwgaW4gZW50cmllc30KCnRyZWUgPSBqc29uLmxvYWRzKGdldCgiaHR0cHM6Ly9hcGkuZ2l0aHViLmNvbS9yZXBvcy9taXRyZS9jYWxkZXJhL2dpdC90cmVlcy9tYXN0ZXI/cmVjdXJzaXZlPTEiKSkKc3VicyA9IFt0IGZvciB0IGluIHRyZWUuZ2V0KCJ0cmVlIiwgW10pIGlmIHQuZ2V0KCJtb2RlIikgPT0gIjE2MDAwMCJdCgpmYWlsZWQgPSBbXQpmb3IgdCBpbiBzdWJzOgogICAgcGF0aCwgc2hhID0gdFsicGF0aCJdLCB0WyJzaGEiXQogICAgdXJsID0gcGF0aF90b191cmwuZ2V0KHBhdGgpCiAgICBtID0gcmUubWF0Y2gocidodHRwczovL2dpdGh1YlwuY29tLyhbXi9dKykvKFteLy5dKykoPzpcLmdpdCk/JCcsIHVybCkgaWYgdXJsIGVsc2UgTm9uZQogICAgaWYgbm90IG06CiAgICAgICAgcHJpbnQoZiJbV0FSTl0ge3BhdGh9OiBubyBtYXRjaGluZyAuZ2l0bW9kdWxlcyBlbnRyeSAtLSB0cmVhdGluZyBhcyBmYWlsZWQuIikKICAgICAgICBmYWlsZWQuYXBwZW5kKHBhdGgpCiAgICAgICAgY29udGludWUKICAgIG93bmVyLCByZXBvID0gbS5ncm91cCgxKSwgbS5ncm91cCgyKQogICAgb2sgPSBGYWxzZQogICAgZm9yIGF0dGVtcHQgaW4gcmFuZ2UoMyk6CiAgICAgICAgdGd6ID0gZiIvdG1wL3tyZXBvfS50YXIuZ3oiCiAgICAgICAgcmMgPSBzdWJwcm9jZXNzLnJ1bihbImN1cmwiLCAiLWZzU0wiLCAiLS1tYXgtdGltZSIsICI2MCIsICItbyIsIHRneiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZiJodHRwczovL2NvZGVsb2FkLmdpdGh1Yi5jb20ve293bmVyfS97cmVwb30vdGFyLmd6L3tzaGF9Il0pLnJldHVybmNvZGUKICAgICAgICBpZiByYyA9PSAwOgogICAgICAgICAgICBkZXN0ID0gb3MucGF0aC5qb2luKCIvb3B0L2NhbGRlcmEiLCBwYXRoKQogICAgICAgICAgICBzdWJwcm9jZXNzLnJ1bihbInJtIiwgIi1yZiIsIGRlc3RdKQogICAgICAgICAgICBvcy5tYWtlZGlycyhkZXN0LCBleGlzdF9vaz1UcnVlKQogICAgICAgICAgICByYzIgPSBzdWJwcm9jZXNzLnJ1bihbInRhciIsICJ4emYiLCB0Z3osICItQyIsIGRlc3QsICItLXN0cmlwLWNvbXBvbmVudHM9MSJdKS5yZXR1cm5jb2RlCiAgICAgICAgICAgIG9zLnJlbW92ZSh0Z3opCiAgICAgICAgICAgIGlmIHJjMiA9PSAwOgogICAgICAgICAgICAgICAgb2sgPSBUcnVlCiAgICAgICAgICAgICAgICBicmVhawogICAgICAgIHByaW50KGYiW1dBUk5dIHtwYXRofTogc3VibW9kdWxlIGRvd25sb2FkIGZhaWxlZCAoYXR0ZW1wdCB7YXR0ZW1wdCsxfS8zKS4iKQogICAgaWYgbm90IG9rOgogICAgICAgIGZhaWxlZC5hcHBlbmQocGF0aCkKCnByaW50KGYiU3VibW9kdWxlczoge2xlbihzdWJzKSAtIGxlbihmYWlsZWQpfS97bGVuKHN1YnMpfSBvay4iKQppZiBmYWlsZWQ6CiAgICBwcmludCgiRkFJTEVEIHN1Ym1vZHVsZXM6IiwgZmFpbGVkKQogICAgc3lzLmV4aXQoMSkK" | base64 -d | python3 -
      args:
        executable: /bin/bash

    - name: 3. Corregir dependencias de Magma (npm)
      shell: |
        cd /opt/caldera/plugins/magma
        npm install vite@2.9.15 @vitejs/plugin-vue@2.3.4 vue@3.2.45 --legacy-peer-deps
      args:
        executable: /bin/bash

    - name: 4. Instalar requisitos Python (Fix PEP 668)
      pip:
        requirements: /opt/caldera/requirements.txt
        executable: pip3
        extra_args: --break-system-packages

    - name: 5. Configurar Servicio con Health Check
      copy:
        dest: /etc/systemd/system/caldera.service
        content: |
          [Unit]
          Description=MITRE Caldera (Robust Mode)
          After=network.target

          [Service]
          User=root
          WorkingDirectory=/opt/caldera
          ExecStart=/usr/bin/python3 server.py --insecure --build
          Restart=always
          RestartSec=10

          [Install]
          WantedBy=multi-user.target

    - name: 6. Iniciar y esperar puerto 8888
      systemd:
        name: caldera
        state: restarted
        enabled: true
        daemon_reload: true

    - name: 7. Validacion de disponibilidad HTTP
      uri:
        url: "http://127.0.0.1:8888"
        status_code: 200
      register: result
      until: result.status == 200
      retries: 30
      delay: 10
EOF

echo "===================================================="
echo " EJECUTANDO DESPLIEGUE ROBUSTO EN: $TARGET_IP"
echo "===================================================="
export ANSIBLE_HOST_KEY_CHECKING=False
export ANSIBLE_BECOME_TIMEOUT=60

if ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/caldera-install.yml"; then
    echo "----------------------------------------------------"
    echo " CALDERA INSTALADO Y VALIDADO"
    echo " URL: http://$TARGET_IP:8888"
    echo "----------------------------------------------------"
else
    echo " ERROR critico en la instalacion."
    exit 1
fi

rm -rf "$TEMP_WORK_DIR"