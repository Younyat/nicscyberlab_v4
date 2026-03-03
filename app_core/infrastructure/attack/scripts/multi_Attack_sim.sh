#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# NICS CyberLab – Victim Event Trigger (Deterministic)
# ============================================================

VICTIM_IP="${1:-10.0.2.172}"
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"

if [[ -z "$VICTIM_IP" ]]; then
    echo " [ERROR] Uso: $0 <VICTIM_IP>"
    exit 1
fi

ssh_exec() {
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "$SSH_USER@$VICTIM_IP" "$1"
}

echo "===================================================="
echo " [INFO] Generando eventos de seguridad en $VICTIM_IP"
echo "===================================================="

# 1. Simulación de Modificación de Archivos (FIM/Integridad)
echo "[1/3] Modificando archivos críticos..."
ssh_exec "sudo touch /etc/shadow_backup && sudo chmod 777 /etc/shadow_backup"
echo " [OK] Evento de integridad generado en /etc"

# 2. Simulación de Ataque de Autenticación (Fuerza Bruta)
echo "[2/3] Generando intentos de acceso fallidos..."
# Provocamos fallos de SSH internos en la víctima
ssh_exec "for i in {1..3}; do ssh -o ConnectTimeout=1 no-existe@localhost 2>/dev/null || true; done"
echo " [OK] Eventos de autenticación generados"

# 3. Simulación de Actividad de Red (Suricata)
echo "[3/3] Ejecutando peticiones sospechosas..."
ssh_exec "curl -s -A 'SQLMAP' http://google.com > /dev/null || true"
ssh_exec "curl -s http://testmyids.com > /dev/null || true"
echo " [OK] Tráfico de red (User-Agent malicioso) generado"

echo "===================================================="
echo " [SUCCESS] Eventos enviados. Revisa tu monitor remoto."
echo "===================================================="