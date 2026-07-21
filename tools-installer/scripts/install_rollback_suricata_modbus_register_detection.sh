#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="suricata_modbus_register_detection_$(echo "${TARGET_IP:-no_ip}" | tr '.' '_')"

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
    rule_file_name: nics-modbus-register-manipulation.rules
    suricata_yaml: /etc/suricata/suricata.yaml
    rule_entry: '  - nics-modbus-register-manipulation.rules'
    rule_content: |
      # ============================================================
      # NICS CyberLab Suricata Modbus Register Manipulation Detection
      # Production profile
      # High-confidence alerts only
      # Detects Modbus write operations only
      # No TCP/502 visibility alerts
      # No normal read/polling alerts
      # ============================================================

      alert tcp any any -> any 502 (msg:"NICS CyberLab ICS Modbus write single register"; dsize:>7; byte_test:2,=,0x0000,2,big; byte_test:1,=,0x06,7; classtype:attempted-admin; sid:910836101; rev:3; metadata:mitre_ics T0836, mitre_ics T1692.001, modbus_function 06, attack_stage control_manipulation, confidence high;)

      alert tcp any any -> any 502 (msg:"NICS CyberLab ICS Modbus write multiple registers"; dsize:>7; byte_test:2,=,0x0000,2,big; byte_test:1,=,0x10,7; classtype:attempted-admin; sid:910836102; rev:3; metadata:mitre_ics T0836, mitre_ics T1692.001, modbus_function 16, attack_stage control_manipulation, confidence high;)

      alert tcp any any -> any 502 (msg:"NICS CyberLab ICS Modbus write single coil"; dsize:>7; byte_test:2,=,0x0000,2,big; byte_test:1,=,0x05,7; classtype:attempted-admin; sid:910836103; rev:3; metadata:mitre_ics T0836, mitre_ics T1692.001, modbus_function 05, attack_stage control_manipulation, confidence high;)

      alert tcp any any -> any 502 (msg:"NICS CyberLab ICS Modbus write multiple coils"; dsize:>7; byte_test:2,=,0x0000,2,big; byte_test:1,=,0x0f,7; classtype:attempted-admin; sid:910836104; rev:3; metadata:mitre_ics T0836, mitre_ics T1692.001, modbus_function 15, attack_stage control_manipulation, confidence high;)

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

    - name: Generate backup timestamp
      command: date +%Y%m%d%H%M%S
      register: backup_ts
      changed_when: false

    - name: Backup suricata.yaml before modification
      copy:
        src: "{{ suricata_yaml }}"
        dest: "{{ suricata_yaml }}.nics-modbus-backup-{{ backup_ts.stdout }}"
        remote_src: true
        owner: root
        group: root
        mode: '0644'

    - name: Check whether previous custom rule file exists
      stat:
        path: "{{ rule_file }}"
      register: previous_rule_file_stat

    - name: Backup previous custom rule file if it exists
      copy:
        src: "{{ rule_file }}"
        dest: "{{ rule_file }}.nics-modbus-backup-{{ backup_ts.stdout }}"
        remote_src: true
        owner: root
        group: root
        mode: '0644'
      when: previous_rule_file_stat.stat.exists

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
        mode: '0644'

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

    - name: Restore previous custom rule file if validation failed and previous file existed
      copy:
        src: "{{ rule_file }}.nics-modbus-backup-{{ backup_ts.stdout }}"
        dest: "{{ rule_file }}"
        remote_src: true
        owner: root
        group: root
        mode: '0644'
      when: suricata_test.rc != 0 and previous_rule_file_stat.stat.exists

    - name: Remove custom rule file if validation failed and no previous file existed
      file:
        path: "{{ rule_file }}"
        state: absent
      when: suricata_test.rc != 0 and not previous_rule_file_stat.stat.exists

    - name: Restart Suricata after restoring previous configuration
      systemd:
        name: suricata
        state: restarted
      when: suricata_test.rc != 0
      failed_when: false

    - name: Fail clearly if Suricata validation failed
      fail:
        msg:
          - "ERROR: Suricata validation failed after installing Modbus register manipulation rules."
          - "Previous configuration has been restored."
          - "Validation stdout: {{ (suricata_test.stdout | default(''))[:600] }}"
          - "Validation stderr: {{ (suricata_test.stderr | default(''))[:600] }}"
      when: suricata_test.rc != 0

    - name: Show validation result
      debug:
        msg:
          - "Validation result: rc={{ suricata_test.rc }}"
          - "Validation stdout: {{ (suricata_test.stdout | default(''))[:400] }}"
          - "Validation stderr: {{ (suricata_test.stderr | default(''))[:400] }}"

    - name: Diagnostic - Suricata build info Modbus
      shell: suricata --build-info | grep -i modbus || true
      args:
        executable: /bin/bash
      register: diag_build_info
      changed_when: false
      failed_when: false

    - name: Diagnostic - modbus references in suricata.yaml
      shell: grep -n "modbus:" "{{ suricata_yaml }}" || true
      args:
        executable: /bin/bash
      register: diag_modbus_yaml
      changed_when: false
      failed_when: false

    - name: Diagnostic - stream-depth in suricata.yaml
      shell: grep -n "stream-depth" "{{ suricata_yaml }}" || true
      args:
        executable: /bin/bash
      register: diag_stream_depth
      changed_when: false
      failed_when: false

    - name: Diagnostic - running Suricata processes
      shell: ps aux | grep '[s]uricata' || true
      args:
        executable: /bin/bash
      register: diag_suricata_ps
      changed_when: false
      failed_when: false

    - name: Diagnostic - AF_PACKET or interface config
      shell: grep -n "af-packet\\|interface:" "{{ suricata_yaml }}" || true
      args:
        executable: /bin/bash
      register: diag_interfaces
      changed_when: false
      failed_when: false

    - name: Diagnostic - host interfaces
      shell: ip -br a || true
      args:
        executable: /bin/bash
      register: diag_ip_brief
      changed_when: false
      failed_when: false

    - name: Show diagnostics
      debug:
        msg:
          - "Build info modbus: {{ (diag_build_info.stdout | default(''))[:800] }}"
          - "suricata.yaml modbus refs: {{ (diag_modbus_yaml.stdout | default(''))[:800] }}"
          - "suricata.yaml stream-depth refs: {{ (diag_stream_depth.stdout | default(''))[:800] }}"
          - "Suricata processes: {{ (diag_suricata_ps.stdout | default(''))[:800] }}"
          - "Suricata interface config: {{ (diag_interfaces.stdout | default(''))[:800] }}"
          - "Host interfaces: {{ (diag_ip_brief.stdout | default(''))[:800] }}"

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
        msg:
          - "OK: Modbus register manipulation detection rules deployed successfully."
          - "Rule file installed: {{ rule_file }}"
          - "Rule entry registered: {{ rule_file_name }}"
          - "Wazuh integration was not modified."
EOF

echo "===================================================="
echo " CONFIGURING SURICATA MODBUS REGISTER DETECTION"
echo "===================================================="
echo "Target IP        : $TARGET_IP"
echo "SSH user         : $SSH_USER"
echo "Rule file path   : /var/lib/suricata/rules/nics-modbus-register-manipulation.rules"
echo "Suricata YAML    : /etc/suricata/suricata.yaml"
echo "Wazuh            : not modified"
export ANSIBLE_HOST_KEY_CHECKING=False
export ANSIBLE_BECOME_TIMEOUT=60

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/suricata-modbus-register-detection.yml"; then
    echo "----------------------------------------------------"
    echo "  SURICATA MODBUS REGISTER DETECTION CONFIGURED"
    echo "----------------------------------------------------"
else
    echo "  Failed to configure Suricata Modbus detection safely"
    rm -rf "$BASE_DIR"
    exit 1
fi

rm -rf "$BASE_DIR"
