#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  SURICATA TOTAL UNINSTALLER - NETEJA COMPLETA
# ============================================================

# --- CONFIGURACIÓ ---
INSTANCE_NAME="victim 3"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"
BASE_DIR="$HOME/ansible/suricata-auto"

echo "===================================================="
echo " [1/2] DETECTANT INSTÀNCIA"
echo "===================================================="

TARGET_IP=$(openstack server show "$INSTANCE_NAME" -f json | jq -r '.addresses' | grep -oE '10\.0\.2\.[0-9]+' | head -1)

if [[ -z "${TARGET_IP:-}" ]]; then
  echo "ERROR: No s'ha trobat la IP per a $INSTANCE_NAME"
  exit 1
fi

echo "Instància: $INSTANCE_NAME | IP: $TARGET_IP"

echo "[2/2] EXECUTANT DESINSTAL·LACIÓ AMB ANSIBLE"

# Creem un playbook temporal per a la desinstal·lació
cat > "$BASE_DIR/playbooks/uninstall-suricata.yml" <<'EOF'
---
- name: Desinstal·lació completa de Suricata
  hosts: suricata
  become: true
  tasks:
    - name: Aturar el servei Suricata
      systemd:
        name: suricata
        state: stopped
        enabled: false
      ignore_errors: true

    - name: Eliminar paquets de Suricata i dependències
      apt:
        name: [suricata, suricata-update]
        state: absent
        purge: true  # Això elimina els fitxers de configuració (/etc/suricata)

    - name: Eliminar dependències no utilitzades
      apt:
        autoremove: true
        purge: true

    - name: Esborrar directoris residuals (logs i regles)
      file:
        path: "{{ item }}"
        state: absent
      loop:
        - /etc/suricata
        - /var/log/suricata
        - /var/lib/suricata
        - /run/suricata

    - name: Eliminar configuració de sudo NOPASSWD (opcional)
      file:
        path: /etc/sudoers.d/ansible_nopasswd
        state: absent

    - name: Verificar si el procés encara existeix
      shell: pkill -9 suricata
      ignore_errors: true
      changed_when: false

    - name: Confirmació
      debug:
        msg: "Suricata ha estat eliminat completament de la instància."
EOF

# Executar el playbook
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -i "$BASE_DIR/inventory/hosts.ini" "$BASE_DIR/playbooks/uninstall-suricata.yml"

echo "===================================================="
echo " ✅ NETEJA FINALITZADA"
echo " Suricata i tots els seus fitxers han estat eliminats."
echo "===================================================="