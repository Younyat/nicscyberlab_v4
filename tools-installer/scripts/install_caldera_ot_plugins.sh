#!/usr/bin/env bash
set -euo pipefail

# --- 1. CONFIGURACION DE RUTAS RELATIVAS ---
TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: Se requiere la IP del objetivo."
    exit 1
fi

# --- 2. TRABAJO TEMPORAL ---
TEMP_WORK_DIR="/tmp/ansible_ot_final"
mkdir -p "$TEMP_WORK_DIR"

# --- 3. GENERACION DE INVENTARIO ---
cat > "$TEMP_WORK_DIR/hosts.ini" <<EOF
[caldera_host]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no -o IdentitiesOnly=yes'
EOF

# --- 4. GENERACION DEL PLAYBOOK DE INSTALACION ---
cat > "$TEMP_WORK_DIR/ot-install-final.yml" <<'EOF'
---
- name: Instalacion de Plugins OT Individuales
  hosts: caldera_host
  become: true
  vars:
    caldera_path: "/opt/caldera"

  tasks:
    - name: 1. Eliminar rastro del plugin 'ot' fallido
      file:
        path: "{{ caldera_path }}/plugins/ot"
        state: absent

    # 2026-09-02: same fix as install_caldera.sh (see that file and
    # tools-installer/README.md for the full root-cause writeup) -- Ansible's
    # `git:` module with recursive: yes needs github.com's git-upload-pack
    # smart-HTTP endpoint to succeed on every one of 1 main repo + 6
    # submodule requests, and that endpoint was measured as low as 1/8
    # reliable for this exact repo. Replaced with plain HTTPS tarball
    # downloads (bypasses git-upload-pack entirely), verified 3/3 full runs
    # with real, non-empty content in every submodule path Task 3 below
    # depends on (modbus/bacnet/dnp3/profinet).
    - name: 2. Descargar el repositorio contenedor y submodulos (sin protocolo git)
      shell: |
        set -e
        rm -rf /tmp/caldera-ot-repo
        mkdir -p /tmp/caldera-ot-repo
        cd /tmp
        for attempt in 1 2 3; do
          rm -f caldera-ot.tar.gz
          if curl -fsSL --max-time 120 -o caldera-ot.tar.gz \
              "https://codeload.github.com/mitre/caldera-ot/tar.gz/refs/heads/main" \
            && tar xzf caldera-ot.tar.gz -C /tmp/caldera-ot-repo --strip-components=1; then
            break
          fi
          echo "[WARN] main repo download failed (attempt ${attempt}/3)."
          rm -rf /tmp/caldera-ot-repo && mkdir -p /tmp/caldera-ot-repo
          if [ "$attempt" -eq 3 ]; then
            echo "[ERROR] main repo download failed after 3 attempts."
            exit 1
          fi
          sleep 10
        done
        echo "aW1wb3J0IGpzb24sIHJlLCBzdWJwcm9jZXNzLCBvcywgc3lzLCB1cmxsaWIucmVxdWVzdAoKZGVmIGdldCh1cmwpOgogICAgcmVxID0gdXJsbGliLnJlcXVlc3QuUmVxdWVzdCh1cmwsIGhlYWRlcnM9eyJVc2VyLUFnZW50IjogIm5pY3MtY3liZXJsYWIifSkKICAgIHdpdGggdXJsbGliLnJlcXVlc3QudXJsb3BlbihyZXEsIHRpbWVvdXQ9MzApIGFzIHI6CiAgICAgICAgcmV0dXJuIHIucmVhZCgpCgpSRVBPX0RJUiA9ICIvdG1wL2NhbGRlcmEtb3QtcmVwbyIKCmdtID0gb3BlbihmIntSRVBPX0RJUn0vLmdpdG1vZHVsZXMiKS5yZWFkKCkKZW50cmllcyA9IHJlLmZpbmRhbGwocidcW3N1Ym1vZHVsZSAiKFteIl0rKSJcXVxzKlxuXHMqcGF0aFxzKj1ccyooXFMrKVxzKlxuXHMqdXJsXHMqPVxzKihcUyspJywgZ20pCnBhdGhfdG9fdXJsID0ge3BhdGg6IHVybCBmb3IgXywgcGF0aCwgdXJsIGluIGVudHJpZXN9Cgp0cmVlID0ganNvbi5sb2FkcyhnZXQoImh0dHBzOi8vYXBpLmdpdGh1Yi5jb20vcmVwb3MvbWl0cmUvY2FsZGVyYS1vdC9naXQvdHJlZXMvbWFpbj9yZWN1cnNpdmU9MSIpKQpzdWJzID0gW3QgZm9yIHQgaW4gdHJlZS5nZXQoInRyZWUiLCBbXSkgaWYgdC5nZXQoIm1vZGUiKSA9PSAiMTYwMDAwIl0KCmZhaWxlZCA9IFtdCmZvciB0IGluIHN1YnM6CiAgICBwYXRoLCBzaGEgPSB0WyJwYXRoIl0sIHRbInNoYSJdCiAgICB1cmwgPSBwYXRoX3RvX3VybC5nZXQocGF0aCkKICAgIG0gPSByZS5tYXRjaChyJ2h0dHBzOi8vZ2l0aHViXC5jb20vKFteL10rKS8oW14vLl0rKSg/OlwuZ2l0KT8kJywgdXJsKSBpZiB1cmwgZWxzZSBOb25lCiAgICBpZiBub3QgbToKICAgICAgICBwcmludChmIltXQVJOXSB7cGF0aH06IG5vIG1hdGNoaW5nIC5naXRtb2R1bGVzIGVudHJ5IC0tIHRyZWF0aW5nIGFzIGZhaWxlZC4iKQogICAgICAgIGZhaWxlZC5hcHBlbmQocGF0aCkKICAgICAgICBjb250aW51ZQogICAgb3duZXIsIHJlcG8gPSBtLmdyb3VwKDEpLCBtLmdyb3VwKDIpCiAgICBvayA9IEZhbHNlCiAgICBmb3IgYXR0ZW1wdCBpbiByYW5nZSgzKToKICAgICAgICB0Z3ogPSBmIi90bXAve3JlcG99LnRhci5neiIKICAgICAgICByYyA9IHN1YnByb2Nlc3MucnVuKFsiY3VybCIsICItZnNTTCIsICItLW1heC10aW1lIiwgIjYwIiwgIi1vIiwgdGd6LAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICBmImh0dHBzOi8vY29kZWxvYWQuZ2l0aHViLmNvbS97b3duZXJ9L3tyZXBvfS90YXIuZ3ove3NoYX0iXSkucmV0dXJuY29kZQogICAgICAgIGlmIHJjID09IDA6CiAgICAgICAgICAgIGRlc3QgPSBvcy5wYXRoLmpvaW4oUkVQT19ESVIsIHBhdGgpCiAgICAgICAgICAgIHN1YnByb2Nlc3MucnVuKFsicm0iLCAiLXJmIiwgZGVzdF0pCiAgICAgICAgICAgIG9zLm1ha2VkaXJzKGRlc3QsIGV4aXN0X29rPVRydWUpCiAgICAgICAgICAgIHJjMiA9IHN1YnByb2Nlc3MucnVuKFsidGFyIiwgInh6ZiIsIHRneiwgIi1DIiwgZGVzdCwgIi0tc3RyaXAtY29tcG9uZW50cz0xIl0pLnJldHVybmNvZGUKICAgICAgICAgICAgb3MucmVtb3ZlKHRneikKICAgICAgICAgICAgaWYgcmMyID09IDA6CiAgICAgICAgICAgICAgICBvayA9IFRydWUKICAgICAgICAgICAgICAgIGJyZWFrCiAgICAgICAgcHJpbnQoZiJbV0FSTl0ge3BhdGh9OiBzdWJtb2R1bGUgZG93bmxvYWQgZmFpbGVkIChhdHRlbXB0IHthdHRlbXB0KzF9LzMpLiIpCiAgICBpZiBub3Qgb2s6CiAgICAgICAgZmFpbGVkLmFwcGVuZChwYXRoKQoKcHJpbnQoZiJTdWJtb2R1bGVzOiB7bGVuKHN1YnMpIC0gbGVuKGZhaWxlZCl9L3tsZW4oc3Vicyl9IG9rLiIpCmlmIGZhaWxlZDoKICAgIHByaW50KCJGQUlMRUQgc3VibW9kdWxlczoiLCBmYWlsZWQpCiAgICBzeXMuZXhpdCgxKQo=" | base64 -d | python3 -
      args:
        executable: /bin/bash

    - name: 3. Mover protocolos individuales a la carpeta de plugins de Caldera
      shell: |
        cp -r /tmp/caldera-ot-repo/modbus {{ caldera_path }}/plugins/
        cp -r /tmp/caldera-ot-repo/bacnet {{ caldera_path }}/plugins/
        cp -r /tmp/caldera-ot-repo/dnp3 {{ caldera_path }}/plugins/
        cp -r /tmp/caldera-ot-repo/profinet {{ caldera_path }}/plugins/
      args:
        executable: /bin/bash

    - name: 4. Instalar dependencias de Python para los protocolos
      pip:
        name: [pymodbus, bacpypes, scapy, cryptography]
        executable: pip3
        extra_args: --break-system-packages

    - name: 5. Habilitar plugins en default.yml (Formato correcto)
      blockinfile:
        path: "{{ caldera_path }}/conf/default.yml"
        insertafter: '^plugins:'
        block: |
          - modbus
          - bacnet
          - dnp3
          - profinet

    - name: 6. Reiniciar Caldera
      systemd:
        name: caldera
        state: restarted
        daemon_reload: true

    - name: 7. Esperar a que el servicio este disponible (Puerto 8888)
      wait_for:
        port: 8888
        host: 127.0.0.1
        state: started
        delay: 5
        timeout: 90
EOF

# --- 5. EJECUCION DE ANSIBLE ---
echo "Iniciando instalacion y despliegue en $TARGET_IP..."
export ANSIBLE_HOST_KEY_CHECKING=False
export ANSIBLE_BECOME_TIMEOUT=60

ansible-playbook -i "$TEMP_WORK_DIR/hosts.ini" "$TEMP_WORK_DIR/ot-install-final.yml"

# --- 6. LIMPIEZA FINAL ---
rm -rf "$TEMP_WORK_DIR"
echo "Proceso finalizado. Caldera deberia estar accesible en http://$TARGET_IP:8888"