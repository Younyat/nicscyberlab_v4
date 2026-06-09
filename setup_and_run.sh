#!/bin/bash

# --- Configuración de colores para la terminal ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # Sin color

echo -e "${BLUE}== Iniciando automatización de advDetection ==${NC}"

# 1. Clonar el repositorio si no existe
if [ ! -d "advDetection" ]; then
    echo -e "${GREEN}[1/5] Clonando el repositorio...${NC}"
    git clone https://github.com/nicslabdev/advDetection.git
    cd advDetection
else
    echo -e "${BLUE}[1/5] El directorio advDetection ya existe. Saltando clonación.${NC}"
    cd advDetection
fi

# 2. Crear entorno virtual
echo -e "${GREEN}[2/5] Configurando entorno virtual Python...${NC}"
python3 -m venv venv
source venv/bin/activate

# 3. Instalar dependencias
echo -e "${GREEN}[3/5] Instalando dependencias (esto puede tardar)...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# 4. Crear estructura de carpetas necesaria
echo -e "${GREEN}[4/5] Creando estructura de directorios...${NC}"
mkdir -p data/raw data/processed models results

# 5. Verificación de CUDA
echo -e "${GREEN}[5/5] Verificando disponibilidad de GPU...${NC}"
python3 -c "import torch; print('CUDA disponible: ', torch.cuda.is_available()); import tensorflow as tf; print('GPUs detectadas:', tf.config.list_physical_devices('GPU'))"

echo -e "${BLUE}== Configuración completada ==${NC}"
echo -e "Instrucciones siguientes:"
echo -e "1. Coloca tus archivos CSV (SWaT/WADI) en la carpeta 'data/'."
echo -e "2. Ejecuta 'source venv/bin/activate' para usar el entorno."
echo -e "3. Lanza el entrenamiento con: python train_model.py"
