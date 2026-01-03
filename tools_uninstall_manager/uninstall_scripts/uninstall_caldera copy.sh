#!/usr/bin/env bash
set -euo pipefail

INSTANCE="$1"
IP_PRIV="$2"
IP_FLOAT="$3"
USER="$4"

IP="${IP_FLOAT:-$IP_PRIV}"

echo " Desinstalando MITRE Caldera en $INSTANCE ($IP)"

# ------------------------------------------
# Detectar llave SSH válida
# ------------------------------------------
SSH_KEY=""
for K in "$HOME/.ssh/"*; do
    [[ -f "$K" ]] && grep -q "PRIVATE KEY" "$K" && SSH_KEY="$K" && break
done

if [[ -z "$SSH_KEY" ]]; then
    echo " ERROR: No se encontró clave privada SSH"
    exit 2
fi

echo " Key usada: $SSH_KEY"
chmod 600 "$SSH_KEY"

# ------------------------------------------
# Lista de rutas posibles de Caldera
# ------------------------------------------
CALDERA_DIRS="
/opt/caldera
/etc/caldera
/tmp/caldera
/usr/local/caldera
/var/log/caldera
"

CALDERA_PORTS="8888 8443"

# ------------------------------------------
# Comandos remotos
# ------------------------------------------
ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" bash << 'EOF'
set -euo pipefail

echo " Eliminando servicios Caldera..."

# Intento de detener servicio si existe
sudo systemctl stop caldera.service 2>/dev/null || true
sudo systemctl disable caldera.service 2>/dev/null || true

echo " Matando procesos python relacionados..."
sudo pkill -f "caldera" 2>/dev/null || true
sudo pkill -f "server.py" 2>/dev/null || true

echo " Eliminando directorios..."
rm -rf /opt/caldera 2>/dev/null || true
rm -rf /etc/caldera 2>/dev/null || true
rm -rf /tmp/caldera 2>/dev/null || true
rm -rf /usr/local/caldera 2>/dev/null || true
rm -rf /var/log/caldera 2>/dev/null || true

echo " Eliminando systemd service si existe..."
sudo rm -f /etc/systemd/system/caldera.service 2>/dev/null || true

sudo systemctl daemon-reload || true

echo " Validando eliminación..."
EOF

# ------------------------------------------
# Validación EN HOST
# ------------------------------------------
OUT=$(ssh -o ControlMaster=no -o StrictHostKeyChecking=no -i "$SSH_KEY" "$USER@$IP" bash << 'EOF'
FOUND=""

# procesos
pgrep -f caldera >/dev/null && FOUND="$FOUND PROC"

# carpetas
for D in /opt/caldera /etc/caldera /tmp/caldera /usr/local/caldera /var/log/caldera; do
    [[ -d "$D" ]] && FOUND="$FOUND DIR"
done

# puertos
ss -tunlp | grep -E ":8888|:8443" >/dev/null && FOUND="$FOUND PORT"

# servicio
systemctl list-unit-files | grep -q caldera.service && FOUND="$FOUND SERVICE"

echo "$FOUND"
EOF
)

if [[ -z "$OUT" ]]; then
    echo " LIMPIEZA OK: No queda rastro de Caldera"
    exit 0
else
    echo " RASTROS DETECTADOS: $OUT"
    exit 3
fi
