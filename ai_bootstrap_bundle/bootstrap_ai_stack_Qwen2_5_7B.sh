#!/usr/bin/env bash
set -euo pipefail

echo "[+] === UNIVERSAL AI BOOTSTRAP (Qwen2.5-7B GGUF + llama.cpp server + Open-WebUI) ==="

# =====================================================
# Detect OS
# =====================================================
. /etc/os-release
echo "[+] Detected OS: $ID $VERSION_ID"

# =====================================================
# APT prep
# =====================================================
if [[ "$ID" == "ubuntu" ]]; then
  sudo apt-get update -y
  sudo apt-get install -y software-properties-common
  sudo add-apt-repository universe -y || true
  sudo apt-get update -y
elif [[ "$ID" == "debian" ]]; then
  sudo apt-get update -y || true
  if grep -qE '^(deb|deb-src)\s+http' /etc/apt/sources.list; then
    sudo sed -i -E 's/^(deb(-src)?\s+http[^ ]+\s+[^ ]+\s+)(main)(.*)$/\1main contrib non-free non-free-firmware/' /etc/apt/sources.list
  fi
  sudo apt-get update -y
else
  echo "[ERROR] Unsupported OS: $ID"
  exit 1
fi

# =====================================================
# Dependencies
# =====================================================
sudo apt-get install -y \
  build-essential \
  cmake \
  git \
  curl \
  wget \
  ca-certificates \
  libcurl4-openssl-dev \
  pkg-config \
  docker.io

sudo systemctl enable --now docker

# =====================================================
# Swap (2G safe)
# =====================================================
if ! swapon --show | grep -q "/swapfile"; then
  sudo fallocate -l 2G /swapfile 2>/dev/null || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  if ! grep -q '^/swapfile ' /etc/fstab; then
    echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
  fi
fi

# =====================================================
# Model
# =====================================================
MODEL_DIR="/opt/models"
MODEL_FILE="Qwen2.5-7B-Instruct-Q4_K_M.gguf"
MODEL_URL="https://huggingface.co/Bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/${MODEL_FILE}"

sudo mkdir -p "$MODEL_DIR"

if [[ ! -f "${MODEL_DIR}/${MODEL_FILE}" ]]; then
  echo "[+] Downloading model: ${MODEL_FILE}"
  if [[ -n "${HF_TOKEN:-}" ]]; then
    sudo wget \
      --header="Authorization: Bearer ${HF_TOKEN}" \
      --content-disposition \
      --show-progress \
      -O "${MODEL_DIR}/${MODEL_FILE}" \
      "$MODEL_URL"
  else
    echo "[ERROR] HF_TOKEN not set"
    exit 1
  fi
else
  echo "[OK] Model already present"
fi

# =====================================================
# llama.cpp
# =====================================================
LLAMA_DIR="/opt/llama.cpp"

if [[ ! -d "$LLAMA_DIR" ]]; then
  sudo git clone https://github.com/ggerganov/llama.cpp "$LLAMA_DIR"
fi

sudo cmake -S "$LLAMA_DIR" -B "$LLAMA_DIR/build"
sudo cmake --build "$LLAMA_DIR/build" --target llama-server -j"$(nproc)"

# =====================================================
# THREADS (RESUELTO EN BASH)
# =====================================================
LLAMA_THREADS="$(nproc)"
echo "[+] Using $LLAMA_THREADS CPU threads for llama.cpp"

# =====================================================
# systemd service (CORRECTO)
# =====================================================
SERVICE="/etc/systemd/system/llama-api.service"

sudo tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=llama.cpp API (Qwen2.5-7B)
After=network.target

[Service]
Type=simple
WorkingDirectory=${LLAMA_DIR}/build
ExecStart=${LLAMA_DIR}/build/bin/llama-server \\
  -m ${MODEL_DIR}/${MODEL_FILE} \\
  -c 4096 \\
  -t ${LLAMA_THREADS} \\
  --host 0.0.0.0 \\
  --port 8000
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now llama-api

# =====================================================
# Wait for API
# =====================================================
echo "[+] Waiting for LLM API to be ready..."
for i in {1..30}; do
  if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1 || \
     curl -fsS http://127.0.0.1:8000/v1/models >/dev/null 2>&1; then
    echo "[OK] LLM API is responding"
    break
  fi
  echo "[-] Still waiting... ($i/30)"
  sleep 5
done

# =====================================================
# Open-WebUI
# =====================================================
echo "[+] Starting Open-WebUI..."
sudo docker rm -f open-webui >/dev/null 2>&1 || true

sudo docker run -d \
  --name open-webui \
  -p 3000:8080 \
  --add-host=host.docker.internal:host-gateway \
  -e OPENAI_API_BASE_URL=http://host.docker.internal:8000/v1 \
  -e OPENAI_API_KEY=dummy \
  --restart always \
  ghcr.io/open-webui/open-webui:main

echo
echo "[OK] === BOOTSTRAP COMPLETE ==="
echo "[OK] Web UI: http://localhost:3000"
echo "[OK] API:    http://localhost:8000/v1/chat/completions"
