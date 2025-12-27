#!/usr/bin/env bash
# ============================================================
#   Wazuh Single-Node Installer (Clean-Aware)
#   Ubuntu 22.04 - OpenStack VM
#   Limpieza dpkg real + Eliminación usuarios/grupos
#   Instalación oficial con --overwrite
#   Idempotente, sin prompts y sin errores dpkg/apt
# ============================================================
set -euo pipefail

START_TIME=$(date +%s)
ADMIN_PASS_FILE="/tmp/wazuh-admin-password"
LOG_FILE="/tmp/wazuh-install.log"
PASS=""

ok()   { echo "[OK] $1"; }
warn() { echo "[WARN] $1"; }
err()  { echo "[ERROR] $1"; }

# ------------------------------------------------------------
# Comprobar sudo sin contraseña
# ------------------------------------------------------------
if ! sudo -n true 2>/dev/null; then
    err "El usuario actual requiere contraseña sudo"
    exit 1
fi

# ------------------------------------------------------------
# Floating IP
# ------------------------------------------------------------
FINAL_IP="${1:-}"
if [[ -z "$FINAL_IP" ]]; then
    FINAL_IP=$(hostname -I | awk '{print $1}')
fi

echo "IP final para Dashboard: $FINAL_IP"
echo "URL prevista: https://$FINAL_IP"


# ------------------------------------------------------------
# Limpieza dpkg y usuarios/grupos antes de instalar
# ------------------------------------------------------------
clean_preinstall() {
    echo "[0/6] Validando estado del sistema APT/DPKG..."

    RESIDUAL=$(dpkg -l 2>/dev/null | awk '/wazuh|filebeat|opensearch/ {print $2}')
    HALF=$(sudo dpkg --audit 2>/dev/null | grep wazuh || true)

    if [[ -z "$RESIDUAL" && -z "$HALF" ]]; then
        ok "No hay restos dpkg relevantes"
    else
        warn "Se detectaron paquetes residuales en dpkg:"
        echo "$RESIDUAL$HALF"

        echo "Aplicando purga agresiva..."
        sudo dpkg --purge wazuh-dashboard wazuh-manager filebeat opensearch >/dev/null 2>&1 || true

        sudo rm -f /var/lib/dpkg/info/wazuh-dashboard.* >/dev/null 2>&1 || true
        sudo rm -f /var/lib/dpkg/info/wazuh-manager.* >/dev/null 2>&1 || true
        sudo rm -f /var/lib/dpkg/info/filebeat.*   >/dev/null 2>&1 || true
        sudo rm -f /var/lib/dpkg/info/opensearch.* >/dev/null 2>&1 || true

        sudo dpkg --configure -a >/dev/null 2>&1 || true
        sudo apt --fix-broken install -y >/dev/null 2>&1 || true
        sudo apt autoremove -y >/dev/null 2>&1 || true

        sleep 2

        NEW_HALF=$(sudo dpkg --audit 2>/dev/null || true)
        if echo "$NEW_HALF" | grep -qi "wazuh"; then
            warn "Persisten restos dpkg (solo metadatos). No bloquearán instalación."
        fi
    fi

    echo "[Limpieza previa] Eliminando usuarios y grupos Wazuh"
    sudo deluser wazuh 2>/dev/null || true
    sudo deluser wazuh-indexer 2>/dev/null || true
    sudo deluser wazuh-dashboard 2>/dev/null || true

    sudo delgroup wazuh 2>/dev/null || true
    sudo delgroup wazuh-indexer 2>/dev/null || true
    sudo delgroup wazuh-dashboard 2>/dev/null || true

    ok "Sistema apt/dpkg listo. Continuando..."
}

clean_preinstall


# ------------------------------------------------------------
# Instalación oficial con overwrite
# ------------------------------------------------------------
echo "[1/6] Preparando sistema"
sudo apt-get update -y
sudo apt-get install -y curl lsb-release net-tools jq >/dev/null

echo "[2/6] Descargando instalador oficial Wazuh"
sudo curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh

echo "[3/6] Instalando Wazuh (forzado overwrite)"
if ! sudo bash ./wazuh-install.sh -a --overwrite > "$LOG_FILE" 2>&1; then
    err "Falló la instalación oficial de Wazuh"
    echo "Log disponible en: $LOG_FILE"
    exit 1
fi
ok "Instalación oficial completada"


# ------------------------------------------------------------
# Extracción de contraseña admin
# ------------------------------------------------------------
echo "[4/6] Extrayendo contraseña admin"
if [[ -f wazuh-install-files.tar ]]; then

    PASS=$(sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O \
        | grep -A1 "'admin'" \
        | tail -n1 \
        | awk -F"'" '{print $2}')

    if [[ -n "$PASS" ]]; then
        echo "$PASS" | sudo tee "$ADMIN_PASS_FILE" >/dev/null
        ok "Contraseña extraída correctamente"
    else
        warn "No se pudo extraer la contraseña"
    fi
else
    warn "No existe wazuh-install-files.tar. Revise log"
fi


# ------------------------------------------------------------
# Activación y arranque servicios
# ------------------------------------------------------------
echo "[5/6] Activando servicios"
sudo systemctl daemon-reload

sudo systemctl enable wazuh-indexer.service
sudo systemctl enable wazuh-manager.service
sudo systemctl enable wazuh-dashboard.service

sudo systemctl restart wazuh-indexer.service
sudo systemctl restart wazuh-manager.service
sudo systemctl restart wazuh-dashboard.service

sleep 8


# ------------------------------------------------------------
# Validación final
# ------------------------------------------------------------
echo "[6/6] Validando instalación final"

FAILED=false

systemctl is-active --quiet wazuh-indexer.service   || FAILED=true
systemctl is-active --quiet wazuh-manager.service   || FAILED=true
systemctl is-active --quiet wazuh-dashboard.service || FAILED=true

if ! curl -k --max-time 6 "https://$FINAL_IP" >/dev/null 2>&1; then
    warn "Dashboard HTTPS no respondió"
    FAILED=true
fi

if $FAILED; then
    err "Instalación incompleta o servicios no arrancaron"
    echo "Revise log: $LOG_FILE"
    exit 1
fi

ok "Wazuh está operativo!"


# ------------------------------------------------------------
# Resultados
# ------------------------------------------------------------
END_TIME=$(date +%s)
TOTAL=$((END_TIME - START_TIME))

echo
echo "===================================================="
echo " WAZUH INSTALADO CORRECTAMENTE"
echo " Tiempo total: $((TOTAL / 60))m $((TOTAL % 60))s"
echo "===================================================="
echo "Dashboard: https://$FINAL_IP"
echo "Usuario: admin"
echo "Password: $PASS"
echo "Log instalacion: $LOG_FILE"
echo "===================================================="
