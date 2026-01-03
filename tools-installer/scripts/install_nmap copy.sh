#!/usr/bin/env bash
#
# ============================================================
#   Nmap Installer (Idempotent + Validation)
#   Versión robusta para producción / auto-deploy
# ============================================================
set -euo pipefail
trap 'echo " ERROR en línea ${LINENO}" >&2' ERR

START_TIME=$(date +%s)

echo "===================================================="
echo " Instalador de Nmap"
echo "===================================================="

# ============================================================
#  FUNCIÓN: Validar estado real de Nmap
#  Parámetro opcional:
#     1 → verbose
#     0 → silencioso
# Return:
#     0 → OK
#     1 → fallo
# ============================================================
check_nmap_alive() {
    local verbose="${1:-1}"
    local rc=0

    if [[ "$verbose" == "1" ]]; then
        echo " Validando estado de Nmap..."
    fi

    # 1) Binario
    if command -v nmap >/dev/null 2>&1; then
        [[ "$verbose" == "1" ]] && echo " + Binario detectado en PATH"
    else
        [[ "$verbose" == "1" ]] && echo " - Binario de nmap NO encontrado"
        rc=1
    fi

    # 2) Versión
    if nmap --version >/dev/null 2>&1; then
        [[ "$verbose" == "1" ]] && echo " + nmap --version responde correctamente"
    else
        [[ "$verbose" == "1" ]] && echo " - nmap --version NO responde"
        rc=1
    fi

    # 3) Ejecución mínima
    if nmap -v >/dev/null 2>&1; then
        [[ "$verbose" == "1" ]] && echo " + Ejecución mínima correcta (nmap -v)"
    else
        [[ "$verbose" == "1" ]] && echo " - Problema ejecutando 'nmap -v'"
        rc=1
    fi

    return "$rc"
}

# ============================================================
#  DETECCIÓN: ¿YA ESTÁ INSTALADO?
# ============================================================
ALREADY=false

if command -v nmap >/dev/null 2>&1; then
    echo " Detectado binario nmap en el sistema"
    ALREADY=true
fi

if dpkg -l | grep -qE '^ii\s+nmap(\s|$)'; then
    echo " Paquete nmap instalado en sistema"
    ALREADY=true
fi

# ============================================================
#  SI ESTÁ INSTALADO → Validación
# ============================================================
if $ALREADY; then
    echo
    echo " Nmap detectado previamente. Validando estado..."

    if check_nmap_alive 1; then
        END_TIME=$(date +%s)
        TOTAL=$((END_TIME - START_TIME))

        echo
        echo "===================================================="
        echo " Nmap YA ESTÁ INSTALADO Y FUNCIONAL"
        echo " Tiempo total: ${TOTAL}s"
        echo "===================================================="
        echo " Ruta binario: $(command -v nmap)"
        echo " Versión:"
        nmap --version | head -n1
        echo "===================================================="
        exit 0
    else
        echo
        echo " Estado de Nmap detectado como no funcional."
        echo " Procediendo a reinstalación limpia..."
    fi
fi

# ============================================================
#  INSTALACIÓN NUEVA O REPARACIÓN
# ============================================================
echo
echo " Iniciando instalación limpia de Nmap..."
export DEBIAN_FRONTEND=noninteractive

echo "[1/3] Forzando limpieza previa..."
sudo apt-get purge -y nmap nmap-common >/dev/null 2>&1 || true
sudo apt-get autoremove -y >/dev/null 2>&1 || true

echo "[2/3] Actualizando repositorios..."
sudo apt-get update -y >/dev/null

echo "[3/3] Instalando Nmap..."
if ! sudo apt-get install -y nmap >/dev/null 2>&1; then
    echo " ERROR: No se pudo instalar nmap"
    exit 1
fi

sleep 2

# ============================================================
#  VALIDACIÓN FINAL
# ============================================================
echo
echo " Validando instalación final..."
if ! check_nmap_alive 1; then
    echo " ERROR: Nmap sigue sin funcionar correctamente."
    exit 2
fi

END_TIME=$(date +%s)
TOTAL=$((END_TIME - START_TIME))

echo
echo "===================================================="
echo " Instalación COMPLETA DE NMAP"
echo " Tiempo total: ${TOTAL}s"
echo "===================================================="
echo " Binario  : $(command -v nmap)"
echo " Versión  : $(nmap --version | head -n1)"
echo "===================================================="
exit 0
