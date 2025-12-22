#!/usr/bin/env bash
set -euo pipefail

echo "[+] === UNIVERSAL AI BOOTSTRAP ==="

# =====================================================
# Detect OS
# =====================================================
. /etc/os-release
echo "[+] Detected OS: $ID $VERSION_ID"

# =====================================================
# Fix APT sources
# =====================================================
if [[ "$ID" == "ubuntu" ]]; then
  echo "[+] Fixing Ubuntu repositories"
  sudo apt-get update -y || true
  sudo apt-get install -y software-properties-common || true
  sudo add-apt-repository universe -y || true
  sudo apt-get update -y
elif [[ "$ID" == "debian" ]]; then
  echo "[+] Fixing Debian repositories"
  sudo sed -i 's/^deb /deb contrib non-free /' /etc/apt/sources.list || true
  sudo apt-get update -y
else
  echo "[✗] Unsupported OS: $ID"
  exit 1
fi

# =====================================================
# Install dependencies
# =====================================================
echo "[+] Installing base build dependencies"

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

echo "[✓] Dependencies installed"

sudo systemctl enable --now docker

# =====================================================
# Swap (safe)
# =====================================================
if ! swapon --show | grep -q swapfile; then
  echo "[+] Enabling swap (2G)"
  sudo fallocate -l 2G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
else
  echo "[✓] Swap already enabled"
fi

# =====================================================
# Hugging Face authentication
# =====================================================
export HF_TOKEN="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"

if [[ -z "${HF_TOKEN:-}" ]]; then
  echo "[✗] HF_TOKEN is not defined"
  exit 1
fi

# =====================================================
# Model configuration (TinyLlama)
# =====================================================
MODEL_DIR="/opt/models"
MODEL_FILE="tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
MODEL_URL="https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/${MODEL_FILE}"

sudo mkdir -p "$MODEL_DIR"

if [[ ! -f "${MODEL_DIR}/${MODEL_FILE}" ]]; then
  echo "[+] Downloading model"
  sudo wget \
    --header="Authorization: Bearer ${HF_TOKEN}" \
    --content-disposition \
    --show-progress \
    -O "${MODEL_DIR}/${MODEL_FILE}" \
    "$MODEL_URL"
else
  echo "[✓] Model already present"
fi

# =====================================================
# llama.cpp
# =====================================================
LLAMA_DIR="/opt/llama.cpp"

if [[ ! -d "$LLAMA_DIR" ]]; then
  echo "[+] Cloning llama.cpp"
  sudo git clone https://github.com/ggerganov/llama.cpp "$LLAMA_DIR"
  sudo cmake -S "$LLAMA_DIR" -B "$LLAMA_DIR/build"
  sudo cmake --build "$LLAMA_DIR/build" -j"$(nproc)"
else
  echo "[✓] llama.cpp already present"
fi

# =====================================================
# systemd service
# =====================================================
SERVICE="/etc/systemd/system/llama-api.service"

if [[ ! -f "$SERVICE" ]]; then
sudo tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=llama.cpp API
After=network.target

[Service]
Type=simple
WorkingDirectory=${LLAMA_DIR}/build
ExecStart=${LLAMA_DIR}/build/bin/server \
  -m ${MODEL_DIR}/${MODEL_FILE} \
  -c 2048 \
  -t $(nproc) \
  --host 0.0.0.0 \
  --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
fi

sudo systemctl daemon-reload
sudo systemctl enable --now llama-api

# =====================================================
# Wait API
# =====================================================
echo "[+] Waiting for LLM to answer"
for i in {1..20}; do
  if curl -s http://127.0.0.1:8000/v1/chat/completions \
    -H "Content-Type: application/json" \
    -d '{"model":"local","messages":[{"role":"user","content":"ping"}]}' \
    | grep -q choices; then
      echo "[✓] API is UP and responding"
      break
  fi
  sleep 3
done

# =====================================================
# Open WebUI
# =====================================================
echo "[+] Waiting for Docker"
for i in {1..10}; do
  sudo docker info >/dev/null 2>&1 && break
  sleep 2
done

if ! sudo docker ps --format '{{.Names}}' | grep -q '^open-webui$'; then
  sudo docker rm -f open-webui >/dev/null 2>&1 || true
  sudo docker run -d \
    --name open-webui \
    -p 3000:8080 \
    -e OPENAI_API_BASE_URL=http://127.0.0.1:8000/v1 \
    -e OPENAI_API_KEY=dummy \
    ghcr.io/open-webui/open-webui:main
fi

echo "[✓] Web UI running at http://localhost:3000"
echo "[✓] === BOOTSTRAP COMPLETE ==="
