#!/usr/bin/env bash
# =================================================================
# Iniciador Maestro: Gunicorn + Scapy + Libpcap + Port Management
# =================================================================

PORT=5001
TIMEOUT=20000
APP_PATH="$(dirname "$(realpath "$0")")"
VENV_PYTHON="/home/younes/Desktop/Openstack/myenv/bin/python3.12"

echo "============================================="
echo " [1/6] Preparando entorno y dependencias..."
echo "============================================="

if [ -f "$APP_PATH/free_port.sh" ]; then
    chmod +x "$APP_PATH/free_port.sh"
    echo " OK: Script de limpieza de puertos listo."
else
    echo " Error: No se encuentra $APP_PATH/free_port.sh"
    exit 1
fi

echo
echo "============================================="
echo " [2/6] Verificando dependencias del sistema..."
echo "============================================="

# Instalación automática de libpcap para evitar el error de 'interface any'
if ! dpkg -s libpcap-dev >/dev/null 2>&1; then
    echo " libpcap-dev no detectado. Instalando (requiere sudo)..."
    sudo apt-get update && sudo apt-get install -y libpcap-dev
else
    echo " [OK] libpcap-dev ya está instalado."
fi

echo
echo "============================================="
echo " [3/6] Configurando privilegios de red (Scapy)..."
echo "============================================="

if [ -f "$VENV_PYTHON" ]; then
    REAL_PYTHON=$(readlink -f "$VENV_PYTHON")
    echo " Binario detectado: $REAL_PYTHON"
    
    HAS_CAPS=$(getcap "$REAL_PYTHON" | grep "cap_net_admin,cap_net_raw=eip")
    
    if [ -z "$HAS_CAPS" ]; then
        echo " Aplicando capacidades de red (requiere sudo)..."
        sudo setcap cap_net_raw,cap_net_admin=eip "$REAL_PYTHON"
        
        if getcap "$REAL_PYTHON" | grep -q "cap_net_admin,cap_net_raw=eip"; then
            echo " [OK] Capacidades aplicadas con éxito."
        else
            echo " [ERROR] Falló la aplicación de capacidades."
        fi
    else
        echo " [OK] Las capacidades ya estaban configuradas."
    fi
else
    echo " [ALERTA] No se encontró el binario en $VENV_PYTHON"
fi

echo
echo "============================================="
echo " [4/6] Liberando el puerto $PORT..."
echo "============================================="
bash "$APP_PATH/free_port.sh" $PORT

echo
echo "============================================="
echo " [5/6] Verificando Gunicorn y Scapy en VENV..."
echo "============================================="
# Aseguramos que scapy también esté en el venv
"$VENV_PYTHON" -m pip install gunicorn scapy --upgrade

echo
echo "============================================="
echo " [6/6] Lanzando Servidor Forense..."
echo "============================================="
cd "$APP_PATH" || exit 1

"$VENV_PYTHON" -m gunicorn \
    -w 4 \
    -b "0.0.0.0:$PORT" \
    --timeout "$TIMEOUT" \
    --log-level info \
    app:app