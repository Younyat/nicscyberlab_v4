#!/bin/bash

# Configuración
URL="http://10.0.2.231:8000/v1/chat/completions"

# Validar entrada
if [ -z "$1" ]; then
    echo "Uso: ./preguntar.sh \"Tu mensaje aquí\""
    exit 1
fi

# Petición y extracción limpia de la respuesta
curl -s -X POST "$URL" \
     -H "Content-Type: application/json" \
     -d "{\"model\": \"qwen\", \"messages\": [{\"role\": \"user\", \"content\": \"$1\"}]}" \
     | python3 -c "import sys, json; print(json.load(sys.stdin)['choices'][0]['message']['content'])"