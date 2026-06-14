#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="suricata_modbus_register_detection_$(echo "$TARGET_IP" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No target IP provided."
    exit 1
fi

BASE_DIR="/tmp/ansible_suricata_modbus_register_detection_${INSTANCE_ID}"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/suricata-modbus-register-detection.yml" <<'EOF'
---
- name: Configure Suricata Modbus register manipulation detection
  hosts: target
  become: true
  vars:
    rules_dir: /var/lib/suricata/rules
    rule_file: /var/lib/suricata/rules/nics-modbus-register-manipulation.rules
    suricata_yaml: /etc/suricata/suricata.yaml
    rule_entry: '  - nics-modbus-register-manipulation.rules'
    rule_content: |
      alert modbus any any -> any 502 (msg:"NICS CyberLab ICS T0836 Modbus write single register"; modbus:function write_single_register; classtype:attempted-admin; sid:910836001; rev:1; metadata:mitre_ics T0836, mitre_ics T1692.001, attack_stage control_manipulation;)
      alert modbus any any -> any 502 (msg:"NICS CyberLab ICS T0836 Modbus write multiple registers"; modbus:function write_multiple_registers; classtype:attempted-admin; sid:910836002; rev:1; metadata:mitre_ics T0836, mitre_ics T1692.001, attack_stage control_manipulation;)
      alert modbus any any -> any 502 (msg:"NICS CyberLab ICS Modbus write single coil"; modbus:function write_single_coil; classtype:attempted-admin; sid:910836003; rev:1; metadata:mitre_ics T0836, mitre_ics T1692.001, attack_stage control_manipulation;)
      alert modbus any any -> any 502 (msg:"NICS CyberLab ICS Modbus write multiple coils"; modbus:function write_multiple_coils; classtype:attempted-admin; sid:910836004; rev:1; metadata:mitre_ics T0836, mitre_ics T1692.001, attack_stage control_manipulation;)
      alert modbus any any -> any 502 (msg:"NICS CyberLab ICS T0861/T0802 Modbus holding register read"; modbus:function read_holding_registers; threshold:type both, track by_src, count 10, seconds 15; classtype:protocol-command-decode; sid:910861001; rev:1; metadata:mitre_ics T0861, mitre_ics T0802, attack_stage collection;)
      alert modbus any any -> any 502 (msg:"NICS CyberLab ICS T0877 Modbus coil read"; modbus:function read_coils; threshold:type both, track by_src, count 10, seconds 15; classtype:protocol-command-decode; sid:910877001; rev:1; metadata:mitre_ics T0877, attack_stage collection;)
      alert modbus any any -> any 502 (msg:"NICS CyberLab ICS T0877 Modbus input register read"; modbus:function read_input_registers; threshold:type both, track by_src, count 10, seconds 15; classtype:protocol-command-decode; sid:910877002; rev:1; metadata:mitre_ics T0877, attack_stage collection;)

  tasks:
    - name: Report target metadata
      debug:
        msg:
          - "Target IP: {{ inventory_hostname }}"
          - "SSH user: {{ ansible_user }}"
          - "Rule file path: {{ rule_file }}"
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
        msg: "ERROR: Suricata is not installed on this node. Install Suricata first."
      when: suricata_bin.rc != 0

    - name: Verify that suricata.yaml exists
      stat:
        path: "{{ suricata_yaml }}"
      register: suricata_yaml_stat

    - name: Fail if suricata.yaml does not exist
      fail:
        msg: "ERROR: suricata.yaml not found at {{ suricata_yaml }}"
      when: not suricata_yaml_stat.stat.exists

    - name: Ensure Suricata rules directory exists
      file:
        path: "{{ rules_dir }}"
        state: directory
        owner: root
        group: root
        mode: '0755'

    - name: Install NICS Modbus register manipulation rules
      copy:
        dest: "{{ rule_file }}"
        content: "{{ rule_content }}"
        owner: root
        group: root
        mode: '0640'

    - name: Verify whether the rule file is already registered in suricata.yaml
      shell: grep -q 'nics-modbus-register-manipulation.rules' "{{ suricata_yaml }}"
      args:
        executable: /bin/bash
      register: rule_registered
      changed_when: false
      failed_when: false

    - name: Ensure rule-files section exists
      lineinfile:
        path: "{{ suricata_yaml }}"
        line: "rule-files:"
        state: present
      when: rule_registered.rc != 0

    - name: Register nics-modbus-register-manipulation.rules in suricata.yaml
      lineinfile:
        path: "{{ suricata_yaml }}"
        insertafter: '^rule-files:'
        line: "{{ rule_entry }}"
        state: present
      when: rule_registered.rc != 0

    - name: Validate Suricata configuration
      command: suricata -T -c "{{ suricata_yaml }}"
      register: suricata_test
      changed_when: false
      failed_when: suricata_test.rc != 0

    - name: Show validation result
      debug:
        msg:
          - "Validation result: rc={{ suricata_test.rc }}"
          - "Validation stdout: {{ (suricata_test.stdout | default(''))[:400] }}"
          - "Validation stderr: {{ (suricata_test.stderr | default(''))[:400] }}"

    - name: Restart Suricata
      systemd:
        name: suricata
        state: restarted
      register: suricata_restart

    - name: Verify Suricata active state
      command: systemctl is-active suricata
      register: suricata_status
      changed_when: false
      failed_when: suricata_status.stdout.strip() != "active"

    - name: Show restart result
      debug:
        msg:
          - "Restart result: {{ suricata_restart.state | default('restarted') }}"
          - "Active state: {{ suricata_status.stdout.strip() }}"

    - name: Show final status
      debug:
        msg: "OK: Modbus register manipulation detection rules deployed successfully."
EOF

echo "===================================================="
echo " CONFIGURING SURICATA MODBUS REGISTER DETECTION"
echo "===================================================="
echo "Target IP        : $TARGET_IP"
echo "SSH user         : $SSH_USER"
echo "Rule file path   : /var/lib/suricata/rules/nics-modbus-register-manipulation.rules"
echo "Suricata YAML    : /etc/suricata/suricata.yaml"
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/suricata-modbus-register-detection.yml"; then
    echo "----------------------------------------------------"
    echo "  SURICATA MODBUS REGISTER DETECTION CONFIGURED"
    echo "----------------------------------------------------"
else
    echo "  Failed to configure Suricata Modbus detection"
    rm -rf "$BASE_DIR"
    exit 1
fi

rm -rf "$BASE_DIR"
