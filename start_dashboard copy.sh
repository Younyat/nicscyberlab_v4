#!/usr/bin/env bash
# =============================================
#  Iniciar Gunicorn limpiando el puerto antes
# bash start_dashboard.sh 2>&1 | tee nombre_del_log.log
# =============================================

PORT=5001
TIMEOUT=20000   #  Timeout de Gunicorn
APP_PATH="$(dirname "$(realpath "$0")")"

echo "============================================="
echo " Preparando entorno y scripts..."
echo "============================================="

# --- Asegurar permisos de ejecución para free_port.sh ---
if [ -f "$APP_PATH/free_port.sh" ]; then
  chmod +x "$APP_PATH/free_port.sh"
  echo " Permisos de ejecución aplicados a free_port.sh"
else
  echo " Error: No se encuentra $APP_PATH/free_port.sh"
  exit 1
fi

echo
echo "============================================="
echo " Liberando el puerto $PORT si está en uso..."
echo "============================================="
bash "$APP_PATH/free_port.sh" $PORT

# --- Verificar si gunicorn está instalado ---
echo
echo "============================================="
echo " Verificando instalación de Gunicorn..."
echo "============================================="

if ! command -v gunicorn >/dev/null 2>&1; then
  echo " Gunicorn no está instalado. Instalando..."

  if [ -n "$VIRTUAL_ENV" ]; then
    echo " Instalando Gunicorn en el entorno virtual actual..."
    pip install gunicorn
  else
    echo " Instalando Gunicorn globalmente (requiere sudo)..."
    sudo pip install gunicorn
  fi
else
  echo " Gunicorn ya está instalado."
fi

# --- Iniciar Gunicorn ---
echo
echo "============================================="
echo " Iniciando servidor Gunicorn (app:app)..."
echo "============================================="
cd "$APP_PATH" || exit 1

gunicorn -w 4 -b "localhost:$PORT" --timeout "$TIMEOUT" app:app
