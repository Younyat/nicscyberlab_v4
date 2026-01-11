#!/usr/bin/env bash
set -euo pipefail

echo "[+] === UNIVERSAL AI BOOTSTRAP (Qwen2.5-7B) ==="

# =====================================================
# Detect OS
# =====================================================
. /etc/os-release
echo "[+] Detected OS: $ID $VERSION_ID"

# =====================================================
# Fix APT sources
# =====================================================
if [[ "$ID" == "ubuntu" ]]; then
  sudo apt-get update -y
  sudo apt-get install -y software-properties-common
  sudo add-apt-repository universe -y
  sudo apt-get update -y
elif [[ "$ID" == "debian" ]]; then
  sudo sed -i 's/^deb /deb contrib non-free /' /etc/apt/sources.list
  sudo apt-get update -y
else
  echo "[✗] Unsupported OS"
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
if ! swapon --show | grep -q swapfile; then
  sudo fallocate -l 2G /swapfile || sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo "/swapfile none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
fi

# =====================================================
# 🔐 Hugging Face TOKEN (INCLUIDO)
# =====================================================
HF_TOKEN="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"

# =====================================================
# Model: Qwen2.5-7B-Instruct (GGUF)
# =====================================================
MODEL_DIR="/opt/models"

MODEL_FILE="Qwen2.5-7B-Instruct-Q4_K_M.gguf"
MODEL_URL="https://huggingface.co/Bartowski/Qwen2.5-7B-Instruct-GGUF/resolve/main/${MODEL_FILE}"







sudo mkdir -p "$MODEL_DIR"

if [[ ! -f "${MODEL_DIR}/${MODEL_FILE}" ]]; then
  echo "[+] Downloading Qwen2.5-7B model (this may take a while)"
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
  sudo git clone https://github.com/ggerganov/llama.cpp "$LLAMA_DIR"
fi

sudo cmake -S "$LLAMA_DIR" -B "$LLAMA_DIR/build"
sudo cmake --build "$LLAMA_DIR/build" --target llama-server -j"$(nproc)"

## =====================================================
# systemd service (Qwen-ready) - OPTIMIZADO PARA RAM
# =====================================================
SERVICE="/etc/systemd/system/llama-api.service"

sudo tee "$SERVICE" >/dev/null <<EOF
[Unit]
Description=llama.cpp API (Qwen2.5-7B)
After=network.target

[Service]
Type=simple
WorkingDirectory=${LLAMA_DIR}/build
# Se reduce contexto a 4096 y se quita f32 para evitar fallos de memoria
ExecStart=${LLAMA_DIR}/build/bin/llama-server \\
  -m ${MODEL_DIR}/${MODEL_FILE} \\
  -c 4096 \\
  -t \$(nproc) \\
  --host 0.0.0.0 \\
  --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now llama-api

# =====================================================
# Wait for API (Verificación de salud mejorada)
# =====================================================
echo "[+] Waiting for LLM API to load model..."
for i in {1..30}; do
  # Intentamos obtener la lista de modelos, que es una petición más ligera
  if curl -s http://127.0.0.1:8000/v1/models | grep -q "Qwen"; then
      echo "[✓] LLM API is responding and model is loaded"
      break
  fi
  echo "[-] Still waiting... (attempt \$i/30)"
  sleep 5
done

# =====================================================
# Open-WebUI
# =====================================================
echo "[+] Starting Open-WebUI Container..."
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
echo "[✓] === BOOTSTRAP COMPLETE ==="
echo "[✓] Web UI: http://localhost:3000"
echo "[✓] API:    http://localhost:8000/v1/chat/completions"