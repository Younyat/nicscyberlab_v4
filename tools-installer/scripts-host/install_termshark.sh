#!/usr/bin/env bash
set -euo pipefail

if [[ -f "/usr/local/bin/termshark" ]]; then
    echo "[!] Termshark ya existe."
    echo "data: [FIN]"
    exit 0
fi

echo "[*] Descargando e instalando Termshark..."
VERSION=$(curl -s https://api.github.com/repos/gcla/termshark/releases/latest | grep -Po '"tag_name": "v\K[^"]*')
curl -L "https://github.com/gcla/termshark/releases/download/v${VERSION}/termshark_${VERSION}_linux_x64.tar.gz" -o ts.tgz
tar -zxvf ts.tgz
sudo mv "termshark_${VERSION}_linux_x64/termshark" /usr/local/bin/
chmod +x /usr/local/bin/termshark
rm -rf ts.tgz "termshark_${VERSION}_linux_x64"

# Verificación
if /usr/local/bin/termshark --version &> /dev/null; then
    echo "[OK] Termshark instalado y verificado."
else
    echo "[ERROR] Fallo al validar el binario de Termshark."
    exit 1
fi

echo "data: [FIN]"