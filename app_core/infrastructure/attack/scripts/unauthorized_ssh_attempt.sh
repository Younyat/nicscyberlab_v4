#!/usr/bin/env bash

TARGET_IP=$1
VICTIM_USER=$2

echo "==========================================="
echo "PHASE 1 - PREPARING UNAUTHORIZED ACCESS"
echo "==========================================="

echo "[INFO] Target IP: $TARGET_IP"
echo "[INFO] Attempting unauthorized SSH login"

echo "==========================================="
echo "PHASE 2 - SSH BRUTE ATTEMPT"
echo "==========================================="

# usuario incorrecto
BAD_USER="debian"

# clave incorrecta
FAKE_KEY="/tmp/fake_key"

echo "[INFO] Generating fake SSH key"
ssh-keygen -t rsa -b 2048 -f $FAKE_KEY -N "" >/dev/null 2>&1

echo "[INFO] Launching unauthorized SSH attempts..."

for i in {1..5}; do
    echo "[ATTEMPT $i] Connecting to $TARGET_IP with invalid credentials"

    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        -i $FAKE_KEY \
        ${BAD_USER}@${TARGET_IP} "echo test" 2>&1 | while read line
    do
        echo "[SSH] $line"
    done

    sleep 1
done

rm -f $FAKE_KEY
rm -f $FAKE_KEY.pub

echo "==========================================="
echo "UNAUTHORIZED ACCESS ATTACK FINISHED"
echo "==========================================="