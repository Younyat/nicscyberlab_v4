#!/bin/bash

# 1. Preparar carpetas
mkdir -p ~/autopsy_pro && cd ~/autopsy_pro

# 2. Instalar dependencias necesarias
sudo apt update
sudo apt install -y openjdk-17-jdk openjdk-17-jre testdisk libafflib-dev libewf-dev build-essential wget unzip

# 3. Configurar variables de entorno para la sesión actual
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$JAVA_HOME/bin:$PATH

# 4. Instalar Sleuth Kit Java
if [ ! -f "sleuthkit-java_4.14.0-1_amd64.deb" ]; then
    wget https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.14.0/sleuthkit-java_4.14.0-1_amd64.deb
fi
sudo apt install ./sleuthkit-java_4.14.0-1_amd64.deb -y

# Engañar al script de Autopsy para que acepte la versión 4.14 como la 4.12
sudo ln -sf /usr/share/java/sleuthkit-4.14.0.jar /usr/share/java/sleuthkit-4.12.1.jar

# 5. Descargar Autopsy
if [ ! -f "autopsy.zip" ]; then
    wget -O autopsy.zip https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.21.0/autopsy-4.21.0.zip
fi

# 6. Extraer y Configurar
unzip -q -o autopsy.zip
cd autopsy-4.21.0
TSK_JAVA_LIB_PATH=/usr/share/java bash unix_setup.sh

# 7. CORRECCIÓN DEL LANZADOR (Usando rutas absolutas)
# Esto permite que escribas 'autopsy' desde CUALQUIER sitio
AUTOPSY_BIN_PATH=$(pwd)/bin/autopsy
echo "#!/bin/bash
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export TSK_JAVA_LIB_PATH=/usr/share/java
$AUTOPSY_BIN_PATH --nosplash \"\$@\"" | sudo tee /usr/local/bin/autopsy > /dev/null

sudo chmod +x /usr/local/bin/autopsy

# 8. Variables permanentes
if ! grep -q "JAVA_HOME" ~/.bashrc; then
    echo "export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64" >> ~/.bashrc
    echo "export TSK_JAVA_LIB_PATH=/usr/share/java" >> ~/.bashrc
fi

echo "===================================================="
echo "LISTO: Ahora solo escribe 'autopsy' para empezar"
echo "===================================================="