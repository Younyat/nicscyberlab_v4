#!/usr/bin/env bash
set -euo pipefail

# -------------------------------
# DEFAULTS
# -------------------------------
SSH_PORT=22
WAZUH_VERSION="4.7"

# -------------------------------
# PARSE ARGUMENTS
# -------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip)        TARGET_IP="$2"; shift 2 ;;
    --user)      TARGET_USER="$2"; shift 2 ;;
    --key)       SSH_KEY="$2"; shift 2 ;;
    --manager)   WAZUH_MANAGER="$2"; shift 2 ;;
    --port)      SSH_PORT="$2"; shift 2 ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

# -------------------------------
# VALIDATION
# -------------------------------
if [[ -z "${TARGET_IP:-}" || -z "${TARGET_USER:-}" || -z "${SSH_KEY:-}" || -z "${WAZUH_MANAGER:-}" ]]; then
  echo "[FATAL] Missing required arguments"
  echo "Usage:"
  echo "  $0 --ip <IP> --user <USER> --key <SSH_KEY> --manager <MANAGER_IP>"
  exit 1
fi

if [[ ! -f "$SSH_KEY" ]]; then
  echo "[FATAL] SSH key not found: $SSH_KEY"
  exit 1
fi

chmod 600 "$SSH_KEY"

SSH="ssh -o StrictHostKeyChecking=no -i $SSH_KEY -p $SSH_PORT $TARGET_USER@$TARGET_IP"

echo "[INFO] Installing Wazuh Agent on $TARGET_USER@$TARGET_IP"
echo "[INFO] Wazuh Manager: $WAZUH_MANAGER"

# -------------------------------
# OS DETECTION
# -------------------------------
OS_ID=$($SSH "source /etc/os-release && echo \$ID")

if [[ "$OS_ID" != "ubuntu" && "$OS_ID" != "debian" ]]; then
  echo "[FATAL] Unsupported OS: $OS_ID"
  exit 1
fi

# -------------------------------
# INSTALL AGENT
# -------------------------------
$SSH <<EOF
set -e

echo "[REMOTE] Installing dependencies"
sudo apt update -y
sudo apt install -y curl apt-transport-https lsb-release gnupg

echo "[REMOTE] Ensuring Wazuh GPG key"

if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    sudo gpg --batch --no-tty --dearmor -o /usr/share/keyrings/wazuh.gpg
else
  echo "[REMOTE] Wazuh GPG key already exists, skipping"
fi



echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update -y

echo "[REMOTE] Installing wazuh-agent"
sudo WAZUH_MANAGER="$WAZUH_MANAGER" apt install -y wazuh-agent

echo "[REMOTE] Enabling and starting agent"
sudo systemctl daemon-reexec
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent

sleep 3

echo "[REMOTE] Agent status:"
sudo systemctl --no-pager status wazuh-agent || true
EOF

# -------------------------------
# FINAL CHECK
# -------------------------------
echo "[OK] Wazuh Agent installation finished on $TARGET_IP"
