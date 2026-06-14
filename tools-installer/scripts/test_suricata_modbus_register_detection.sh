#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
SSH_USER="${2:-debian}"
SSH_KEY="$HOME/.ssh/my_key"
INSTANCE_ID="test_suricata_modbus_register_detection_$(echo "${TARGET_IP:-no_ip}" | tr '.' '_')"

if [[ -z "$TARGET_IP" ]]; then
    echo "ERROR: No target IP provided."
    exit 1
fi

BASE_DIR="/tmp/ansible_test_suricata_modbus_register_detection_${INSTANCE_ID}"
mkdir -p "$BASE_DIR"

cat > "$BASE_DIR/hosts.ini" <<EOF
[target]
$TARGET_IP ansible_user=$SSH_USER ansible_ssh_private_key_file=$SSH_KEY ansible_ssh_common_args='-o StrictHostKeyChecking=no'
EOF

cat > "$BASE_DIR/test-suricata-modbus-register-detection.yml" <<'EOF'
---
- name: Test Suricata Modbus register manipulation detection
  hosts: target
  become: true
  vars:
    suricata_yaml: /etc/suricata/suricata.yaml
    pcap_path: /tmp/nics_modbus_test.pcap
    replay_dir: /tmp/nics_suricata_modbus_test

  tasks:
    - name: Verify that Suricata is installed
      shell: command -v suricata
      args:
        executable: /bin/bash
      register: suricata_bin
      changed_when: false
      failed_when: suricata_bin.rc != 0

    - name: Verify that tcpdump is installed
      shell: command -v tcpdump
      args:
        executable: /bin/bash
      register: tcpdump_bin
      changed_when: false
      failed_when: tcpdump_bin.rc != 0

    - name: Verify that suricata.yaml exists
      stat:
        path: "{{ suricata_yaml }}"
      register: suricata_yaml_stat

    - name: Fail if suricata.yaml does not exist
      fail:
        msg: "ERROR: suricata.yaml not found at {{ suricata_yaml }}"
      when: not suricata_yaml_stat.stat.exists

    - name: Capture tcp port 502 traffic for 20 seconds
      shell: timeout 20 tcpdump -ni any -s 0 -w "{{ pcap_path }}" 'tcp port 502'
      args:
        executable: /bin/bash
      register: tcpdump_capture
      changed_when: true
      failed_when: false

    - name: Reset replay directory
      file:
        path: "{{ replay_dir }}"
        state: absent

    - name: Recreate replay directory
      file:
        path: "{{ replay_dir }}"
        state: directory
        owner: root
        group: root
        mode: '0755'

    - name: Replay pcap offline through Suricata
      shell: suricata -r "{{ pcap_path }}" -c "{{ suricata_yaml }}" -l "{{ replay_dir }}" -k none
      args:
        executable: /bin/bash
      register: suricata_replay
      changed_when: true
      failed_when: false

    - name: Extract NICS CyberLab alerts from replay eve.json
      shell: grep "NICS CyberLab" "{{ replay_dir }}/eve.json" || true
      args:
        executable: /bin/bash
      register: replay_alerts
      changed_when: false
      failed_when: false

    - name: Show replay interpretation
      debug:
        msg:
          - "tcpdump rc: {{ tcpdump_capture.rc }}"
          - "suricata replay rc: {{ suricata_replay.rc }}"
          - "Replay alerts: {{ (replay_alerts.stdout | default(''))[:1500] }}"
          - "Interpretation: if the pcap has no tcp/502 traffic, Suricata is not in the traffic path."
          - "Interpretation: if the pcap has tcp/502 traffic and replay triggers alerts, rules work and live capture is the issue."
          - "Interpretation: if the pcap has tcp/502 traffic and replay does not trigger alerts, the issue is the rule logic or the attack traffic format."
EOF

echo "===================================================="
echo " TESTING SURICATA MODBUS REGISTER DETECTION"
echo "===================================================="
echo "Target IP        : $TARGET_IP"
echo "SSH user         : $SSH_USER"
echo "PCAP path        : /tmp/nics_modbus_test.pcap"
echo "Replay output    : /tmp/nics_suricata_modbus_test"
export ANSIBLE_HOST_KEY_CHECKING=False

if ansible-playbook -i "$BASE_DIR/hosts.ini" "$BASE_DIR/test-suricata-modbus-register-detection.yml"; then
    echo "----------------------------------------------------"
    echo "  SURICATA MODBUS DETECTION TEST COMPLETED"
    echo "----------------------------------------------------"
else
    echo "  Failed to execute Suricata Modbus detection test"
    rm -rf "$BASE_DIR"
    exit 1
fi

rm -rf "$BASE_DIR"
