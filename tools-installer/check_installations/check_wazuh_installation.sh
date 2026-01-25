#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH AIO INSTALLATION CHECKER (FINAL / ROBUST)
# ============================================================

TARGET_IP="${1:-}"
SSH_USER="${2:-ubuntu}"
SSH_KEY="$HOME/.ssh/my_key"
WAZUH_VERSION="4.7.3"

if [[ -z "$TARGET_IP" ]]; then
    echo " [ERROR] No se proporcionó la IP del nodo Wazuh."
    exit 1
fi

echo "===================================================="
echo " [INFO] Checking instalación Wazuh AIO en $TARGET_IP"
echo "===================================================="

ssh_exec() {
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "$SSH_USER@$TARGET_IP" "$1"
}

# ------------------------------------------------------------
# [1/8] Acceso SSH
# ------------------------------------------------------------
echo "[1/8] Verificando acceso SSH..."
ssh_exec "echo SSH_OK" >/dev/null
echo " [OK] Acceso SSH correcto"

# ------------------------------------------------------------
# [2/8] Servicios
# ------------------------------------------------------------
echo "[2/8] Verificando servicios Wazuh..."

SERVICES=(wazuh-manager wazuh-indexer wazuh-dashboard)
for svc in "${SERVICES[@]}"; do
    if ssh_exec "systemctl is-active --quiet $svc"; then
        echo " [OK] Servicio activo: $svc"
    else
        echo " [ERROR] Servicio NO activo: $svc"
        exit 1
    fi
done

# ------------------------------------------------------------
# [3/8] Puertos (topología real)
# ------------------------------------------------------------
echo "[3/8] Verificando puertos..."

MANDATORY_PORTS=(1514 1515 55000)
for port in "${MANDATORY_PORTS[@]}"; do
    if ssh_exec "ss -lnt | grep -q ':$port '"; then
        echo " [OK] Puerto escuchando: $port"
    else
        echo " [ERROR] Puerto NO escuchando: $port"
        exit 1
    fi
done

# Indexer solo local (IPv4 / IPv6-mapped)
if ssh_exec "ss -lnt | grep -Eq '(:|\\])9200\\s'"; then
    echo " [OK] Indexer escuchando localmente en 9200"
else
    echo " [ERROR] Indexer NO escuchando en 9200 (local)"
    exit 1
fi

# Dashboard HTTPS
if ssh_exec "ss -lnt | grep -q ':443 '"; then
    echo " [OK] Dashboard expuesto vía HTTPS (443)"
else
    echo " [ERROR] Dashboard NO expuesto en 443"
    exit 1
fi

# ------------------------------------------------------------
# [4/8] Versiones
# ------------------------------------------------------------
echo "[4/8] Verificando versiones instaladas..."

for pkg in wazuh-manager wazuh-indexer wazuh-dashboard; do
    VER=$(ssh_exec "dpkg -l | awk '/^ii/ && /$pkg/ {print \$3}' || true")
    if [[ "$VER" == "$WAZUH_VERSION"* ]]; then
        echo " [OK] $pkg versión $VER"
    else
        echo " [ERROR] $pkg versión incorrecta o ausente: '$VER'"
        exit 1
    fi
done

# ------------------------------------------------------------
# [5/8] API Wazuh (estructura)
# ------------------------------------------------------------
echo "[5/8] Verificando API Wazuh (estructura)..."

if ssh_exec "ss -lnt | grep -q ':55000 '"; then
    echo " [OK] API Wazuh escuchando en 55000"
else
    echo " [ERROR] API Wazuh NO escuchando en 55000"
    exit 1
fi

# ------------------------------------------------------------
# [6/8] Dashboard (estado HTTP, SSL tolerado)
# ------------------------------------------------------------
echo "[6/8] Verificando Wazuh Dashboard (estado HTTP)..."

HTTP_CODE=$(curl -sk \
    --connect-timeout 3 \
    --max-time 5 \
    -o /dev/null \
    -w "%{http_code}" \
    "https://${TARGET_IP}")

if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "302" || "$HTTP_CODE" == "401" ]]; then
    echo " [OK] Dashboard responde correctamente (HTTP $HTTP_CODE)"
else
    echo " [ERROR] Dashboard no responde correctamente (HTTP $HTTP_CODE)"
    exit 1
fi

# ------------------------------------------------------------
# [7/8] Logs críticos (con sudo)
# ------------------------------------------------------------
echo "[7/8] Analizando logs del Manager..."

ERRORS=$(ssh_exec "sudo grep -iE 'error|critical|fatal' /var/ossec/logs/ossec.log | tail -n 5 || true")

if [[ -z "$ERRORS" ]]; then
    echo " [OK] Sin errores críticos recientes"
else
    echo " [WARN] Errores detectados:"
    echo "$ERRORS"
fi

# ------------------------------------------------------------
# [8/8] Huella AIO
# ------------------------------------------------------------
echo "[8/8] Verificando huella AIO..."

if ssh_exec "test -d /var/ossec && test -d /etc/wazuh-indexer && test -d /etc/wazuh-dashboard"; then
    echo " [OK] Estructura AIO completa"
else
    echo " [ERROR] Estructura AIO incompleta"
    exit 1
fi

echo "===================================================="
echo " [SUCCESS] Instalación Wazuh AIO verificada correctamente"
echo "===================================================="
exit 0
