#!/usr/bin/env bash
set -euo pipefail

# ============================================================
#  WAZUH AGENT CHECKER + INSPECTOR (FIXED PERMISSIONS)
# ============================================================

VICTIM_IP="${1:-}"
MODE="${2:-check}"        # check | inspect | full
SSH_USER="debian"
SSH_KEY="$HOME/.ssh/my_key"
WAZUH_VERSION="4.7.3"

if [[ -z "$VICTIM_IP" ]]; then
    echo " [ERROR] Uso: $0 <VICTIM_IP> [check|inspect|full]"
    exit 1
fi

ssh_exec() {
    ssh -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 \
        "$SSH_USER@$VICTIM_IP" "$1"
}

# ============================================================
# CHECKER
# ============================================================

run_checker() {
    echo "===================================================="
    echo " [INFO] Checking instalación Wazuh Agent en $VICTIM_IP"
    echo "===================================================="

    echo "[1/5] Verificando acceso SSH..."
    ssh_exec "echo SSH_OK" >/dev/null
    echo " [OK] Acceso SSH correcto"

    echo "[2/5] Verificando paquete wazuh-agent..."
    AGENT_VER=$(ssh_exec "dpkg -l | awk '/^ii/ && /wazuh-agent/ {print \$3}' || true")

    if [[ "$AGENT_VER" == "$WAZUH_VERSION"* ]]; then
        echo " [OK] wazuh-agent instalado (versión $AGENT_VER)"
    else
        echo " [ERROR] wazuh-agent no instalado o versión incorrecta: '$AGENT_VER'"
        exit 1
    fi

    echo "[3/5] Verificando servicio wazuh-agent..."
    ssh_exec "systemctl is-active --quiet wazuh-agent"
    echo " [OK] Servicio wazuh-agent activo"

    echo "[4/5] Verificando unidad systemd..."
    ssh_exec "systemctl status wazuh-agent >/dev/null"
    echo " [OK] Unidad systemd wazuh-agent presente"

    echo "[5/5] Verificando logs del agente..."
    # Se añade sudo para evitar el [WARN] de permisos
    if ssh_exec "sudo test -d /var/ossec/logs"; then
        echo " [OK] Directorio de logs presente (/var/ossec/logs)"
    else
        echo " [WARN] Directorio de logs no encontrado (no crítico)"
    fi

    echo "===================================================="
    echo " [SUCCESS] Wazuh Agent correctamente instalado"
    echo "===================================================="
}

# ============================================================
# INSPECTOR
# ============================================================

run_inspector() {
    echo
    echo "===================================================="
    echo " [INFO] Inspeccionando layout Wazuh Agent en $VICTIM_IP"
    echo "===================================================="

    echo "=== [1] systemd unit ==="
    ssh_exec "systemctl cat wazuh-agent"

    echo
    echo "=== [2] Procesos en ejecución ==="
    ssh_exec "ps aux | grep wazuh | grep -v grep || true"

    echo
    echo "=== [3] Configuración detectada (FIM/Real-time) ==="
    # Auditoría directa de las rutas con realtime activo
    ssh_exec "sudo grep -E '<directories.*realtime=\"yes\"' /var/ossec/etc/ossec.conf || echo 'No se detectó Real-time'"

    echo
    echo "=== [4] Contenido del directorio de logs ==="
    ssh_exec "sudo ls -lah /var/ossec/logs 2>/dev/null || true"

    echo
    echo "=== [5] Colas internas de comunicación ==="
    ssh_exec "sudo find /var/ossec -maxdepth 2 -type d -name queue 2>/dev/null || true"

    echo
    echo "=== [6] Manager IP configurado ==="
    ssh_exec "sudo grep -R '<address>' /var/ossec/etc/ossec.conf 2>/dev/null || true"

    echo
    echo "=== [7] Conexiones de red activas (Agente -> Manager) ==="
    ssh_exec "sudo ss -tpn | grep wazuh || echo 'Sin conexiones activas'"

    echo
    echo "===================================================="
    echo " [DONE] Inspección completada"
    echo "===================================================="
}

# ============================================================
# MAIN
# ============================================================

case "$MODE" in
    check)
        run_checker
        ;;
    inspect)
        run_inspector
        ;;
    full)
        run_checker
        run_inspector
        ;;
    *)
        echo " [ERROR] Modo inválido: $MODE (usa check | inspect | full)"
        exit 1
        ;;
esac

exit 0