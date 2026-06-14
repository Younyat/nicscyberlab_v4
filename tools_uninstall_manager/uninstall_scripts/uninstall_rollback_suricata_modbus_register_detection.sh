#!/usr/bin/env bash
set -euo pipefail

INSTANCE_NAME="${1:-}"
SSH_KEY="${2:-}"
TARGET_IP="${3:-}"
SSH_USER="${4:-}"

if [[ -z "$INSTANCE_NAME" || -z "$SSH_KEY" || -z "$TARGET_IP" || -z "$SSH_USER" ]]; then
    echo "ERROR: Uso: $0 <INSTANCE_NAME> <SSH_KEY> <TARGET_IP> <SSH_USER>"
    exit 1
fi

INSTANCE_ID="uninstall_suricata_modbus_register_detection_$(echo "$TARGET_IP" | tr '.' '_')"
BASE_DIR="/tmp/ansible_uninstall_suricata_modbus_register_detection_${INSTANCE_ID}"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/uninstall-suricata-modbus-register-detection.yml" <<'EOF'
---
- name: Uninstall Suricata Modbus register manipulation detection rules
  hosts: target
  become: true
  vars:
    rule_file: /var/lib/suricata/rules/nics-modbus-register-manipulation.rules
    suricata_yaml: /etc/suricata/suricata.yaml
    rule_file_name: nics-modbus-register-manipulation.rules

  tasks:
    - name: Report target metadata
      debug:
        msg:
          - "Target IP: {{ inventory_hostname }}"
          - "SSH user: {{ ansible_user }}"
          - "Rule file to remove: {{ rule_file }}"
          - "Suricata YAML path: {{ suricata_yaml }}"

    - name: Verify that Suricata is installed
      shell: command -v suricata
      args:
        executable: /bin/bash
      register: suricata_bin
      changed_when: false
      failed_when: false

    - name: Fail with explicit message when Suricata is missing
      fail:
        msg: "ERROR: Suricata is not installed on this node. Nothing to uninstall safely."
      when: suricata_bin.rc != 0

    - name: Verify that suricata.yaml exists
      stat:
        path: "{{ suricata_yaml }}"
      register: suricata_yaml_stat

    - name: Fail if suricata.yaml does not exist
      fail:
        msg: "ERROR: suricata.yaml not found at {{ suricata_yaml }}"
      when: not suricata_yaml_stat.stat.exists

    - name: Generate backup timestamp
      command: date +%Y%m%d%H%M%S
      register: backup_ts
      changed_when: false

    - name: Backup suricata.yaml before cleanup
      copy:
        src: "{{ suricata_yaml }}"
        dest: "{{ suricata_yaml }}.nics-modbus-backup-{{ backup_ts.stdout }}"
        remote_src: true
        owner: root
        group: root
        mode: '0644'

    - name: Check whether custom Modbus rule file exists
      stat:
        path: "{{ rule_file }}"
      register: rule_file_stat

    - name: Remove only the custom Modbus rule file
      file:
        path: "{{ rule_file }}"
        state: absent
      when: rule_file_stat.stat.exists

    - name: Remove only the custom Modbus rule entry from suricata.yaml
      lineinfile:
        path: "{{ suricata_yaml }}"
        regexp: '^\s*-\s*nics-modbus-register-manipulation\.rules\s*$'
        state: absent
      register: yaml_line_removed

    - name: Validate Suricata configuration after cleanup
      command: suricata -T -c "{{ suricata_yaml }}"
      register: suricata_test
      changed_when: false
      failed_when: false

    - name: Restore suricata.yaml backup if validation failed
      copy:
        src: "{{ suricata_yaml }}.nics-modbus-backup-{{ backup_ts.stdout }}"
        dest: "{{ suricata_yaml }}"
        remote_src: true
        owner: root
        group: root
        mode: '0644'
      when: suricata_test.rc != 0

    - name: Restart Suricata after restoring backup
      systemd:
        name: suricata
        state: restarted
      when: suricata_test.rc != 0
      failed_when: false

    - name: Fail clearly if validation failed and backup was restored
      fail:
        msg:
          - "ERROR: Suricata validation failed after removing Modbus rules."
          - "The previous suricata.yaml backup has been restored."
          - "Validation stdout: {{ (suricata_test.stdout | default(''))[:600] }}"
          - "Validation stderr: {{ (suricata_test.stderr | default(''))[:600] }}"
      when: suricata_test.rc != 0

    - name: Show validation result
      debug:
        msg:
          - "Validation result: rc={{ suricata_test.rc }}"
          - "Validation stdout: {{ (suricata_test.stdout | default(''))[:400] }}"
          - "Validation stderr: {{ (suricata_test.stderr | default(''))[:400] }}"

    - name: Restart Suricata after successful cleanup
      systemd:
        name: suricata
        state: restarted
      register: suricata_restart

    - name: Verify Suricata active state
      command: systemctl is-active suricata
      register: suricata_status
      changed_when: false
      failed_when: suricata_status.stdout.strip() != "active"

    - name: Show final status
      debug:
        msg:
          - "OK: Modbus register manipulation detection rules removed successfully."
          - "Removed rule file if present: {{ rule_file }}"
          - "Removed only this rule entry from suricata.yaml: {{ rule_file_name }}"
          - "Suricata active state: {{ suricata_status.stdout.strip() }}"
          - "Wazuh integration was not modified."
EOF

echo "===================================================="
echo " UNINSTALLING SURICATA MODBUS REGISTER DETECTION"
echo "===================================================="
echo "Instance         : $INSTANCE_NAME"
echo "Target IP        : $TARGET_IP"
echo "SSH user         : $SSH_USER"
echo "Rule file path   : /var/lib/suricata/rules/nics-modbus-register-manipulation.rules"
echo "Suricata YAML    : /etc/suricata/suricata.yaml"
echo "Wazuh            : not modified"
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/uninstall-suricata-modbus-register-detection.yml"; then
    echo "----------------------------------------------------"
    echo "  SURICATA MODBUS REGISTER DETECTION UNINSTALLED"
    echo "----------------------------------------------------"
else
    echo "  Failed to uninstall Suricata Modbus detection safely"
    rm -rf "$BASE_DIR"
    exit 1
fi

rm -rf "$BASE_DIR"
echo "Process completed for $INSTANCE_NAME"
