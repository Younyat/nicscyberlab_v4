#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# ICS TRAFFIC ANALYSIS – INSTALLER (HOST LEVEL)
# Forensics + IDS + IPS + Frontend
# ============================================================

PROJECT_NAME="ics_traffic_forensics"
INSTALL_DIR="/opt/${PROJECT_NAME}"
VENV_DIR="${INSTALL_DIR}/venv"

echo "[+] Instalando dependencias del sistema..."
sudo apt update
sudo apt install -y \
  tcpdump \
  tshark \
  python3 \
  python3-venv \
  python3-pip \
  iptables \
  curl

echo "[+] Configurando tshark para capturas sin root..."
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo dpkg-reconfigure -f noninteractive wireshark-common

echo "[+] Ajustando capabilities para tcpdump y tshark..."
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump || true
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/tshark || true

echo "[+] Creando estructura del proyecto..."
sudo mkdir -p "${INSTALL_DIR}"/{analysis,api,web,captures,logs}
sudo chown -R "$USER":"$USER" "${INSTALL_DIR}"

echo "[+] Creando entorno virtual Python..."
python3 -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

echo "[+] Instalando dependencias Python..."
pip install --upgrade pip
pip install flask

deactivate

echo "[+] Generando archivo requirements.txt..."
cat <<EOF > "${INSTALL_DIR}/requirements.txt"
flask
EOF

echo "[+] Verificando herramientas..."
command -v tcpdump >/dev/null || { echo "tcpdump NO instalado"; exit 1; }
command -v tshark  >/dev/null || { echo "tshark NO instalado"; exit 1; }
python3 --version  >/dev/null || { echo "Python NO disponible"; exit 1; }

echo "[OK] Instalación completada correctamente"
echo
echo "============================================================"
echo " INSTALACIÓN FINALIZADA"
echo " Proyecto: ${INSTALL_DIR}"
echo " Backend:  Python + Flask (venv)"
echo " Frontend: HTML/JS servido por Flask"
echo " Captura:  tcpdump / tshark"
echo "============================================================"
echo
echo "Siguiente paso:"
echo "1) Copiar tu backend.py en ${INSTALL_DIR}/api/"
echo "2) Copiar analysis/ en ${INSTALL_DIR}/analysis/"
echo "3) Copiar index.html y app.js en ${INSTALL_DIR}/web/"
echo "4) Activar entorno: source ${VENV_DIR}/bin/activate"
echo "5) Lanzar backend: python api/backend.py"
echo
