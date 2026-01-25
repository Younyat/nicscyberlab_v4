#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH SERVER CONFIGURATION DETECTOR (MANAGER SIDE)
# ============================================================

TARGET_IP="${1:-}" # IP Flotante del monitor-1
SSH_USER="${2:-ubuntu}"
SSH_KEY="$HOME/.ssh/my_key"

if [[ -z "$TARGET_IP" ]]; then
    echo " [ERROR] Uso: $0 <IP_FLOTANTE_MANAGER> <USUARIO>"
    exit 1
fi

ssh_exec() {
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "$SSH_USER@$TARGET_IP" "$1"
}

echo "===================================================="
echo " [INFO] AUDITANDO CONFIGURACIÓN DEL MANAGER: $TARGET_IP"
echo "===================================================="

# --- 1. DETECCIÓN DE VULNERABILIDADES ---
echo "[1/4] Motor de Vulnerabilidades..."
VULS_ENABLED=$(ssh_exec "sudo grep -A 1 '<vulnerability-detector>' /var/ossec/etc/ossec.conf | grep '<enabled>' | sed 's/[^a-z]//g' || echo 'not_found'")

if [[ "$VULS_ENABLED" == *"yes"* ]]; then
    echo " [OK] Vulnerability Detector: ACTIVADO"
else
    echo " [CRITICAL] Vulnerability Detector: APAGADO"
fi

# --- 2. DETECCIÓN DE PROVIDERS (DEBIAN/UBUNTU) ---
echo "[2/4] Providers de SO activos..."
DEBIAN_PROV=$(ssh_exec "sudo grep -A 1 '<provider name=\"debian\">' /var/ossec/etc/ossec.conf | grep '<enabled>' | sed 's/[^a-z]//g' || echo 'no'")

if [[ "$DEBIAN_PROV" == *"yes"* ]]; then
    echo " [OK] Provider Debian: ACTIVADO"
else
    echo " [WARN] Provider Debian: DESACTIVADO (No detectará fallos en víctimas Debian)"
fi

# --- 3. DETECCIÓN DE INTEGRIDAD (FIM) ---
echo "[3/4] Motor de Integridad (Syscheck)..."
FIM_DISABLED=$(ssh_exec "sudo grep -A 1 '<syscheck>' /var/ossec/etc/ossec.conf | grep '<disabled>' | sed 's/[^a-z]//g' || echo 'no'")

if [[ "$FIM_DISABLED" == *"no"* ]]; then
    echo " [OK] Integrity Monitoring: ACTIVADO"
else
    echo " [CRITICAL] Integrity Monitoring: DESACTIVADO"
fi

# --- 4. DETECCIÓN DE TIEMPO REAL (REAL-TIME) ---
echo "[4/4] Verificando modo Live-Time (Real-time)..."
RT_CHECK=$(ssh_exec "sudo grep 'realtime=\"yes\"' /var/ossec/etc/ossec.conf || true")

if [[ -n "$RT_CHECK" ]]; then
    echo " [OK] Real-time configurado en directorios: "
    echo "$RT_CHECK" | awk -F'>' '{print $2}' | awk -F'<' '{print "      - "$1}'
else
    echo " [WARN] No se detectan directorios en modo Real-time (Usa escaneo programado)"
fi

echo "===================================================="
echo " [DONE] Auditoría de Servidor completada"
echo "===================================================="