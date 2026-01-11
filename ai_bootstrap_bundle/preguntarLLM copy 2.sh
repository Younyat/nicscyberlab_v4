#!/usr/bin/env bash
# Ubicación: ai_bootstrap_bundle/preguntarLLM.sh

# 1. Cargar credenciales de OpenStack
# Ajusta esta ruta si el archivo admin-openrc.sh está en otro sitio
SOURCE_RC="$(dirname "$0")/../admin-openrc.sh"

if [ -f "$SOURCE_RC" ]; then
    source "$SOURCE_RC"
else
    echo "Error: No se encontró admin-openrc.sh en $SOURCE_RC" >&2
    exit 1
fi

VM_NAME="AI"

# 2. Obtener la IP Flotante de forma dinámica
# Redirigimos stderr a /dev/null para que los logs de auth no ensucien la respuesta
FIP=$(openstack server show "$VM_NAME" -f json 2>/dev/null | jq -r '.addresses' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -n 1)

if [ -z "$FIP" ]; then
    echo "Error: No se encontró IP para $VM_NAME. Verifica que la instancia esté ACTIVE." >&2
    exit 1
fi

# 3. Realizar la consulta al modelo Qwen (Puerto 8000)
RESPONSE=$(curl -s -X POST "http://$FIP:8000/v1/chat/completions" \
     -H "Content-Type: application/json" \
     -d "{
       \"model\": \"qwen\",
       \"messages\": [
         {\"role\": \"system\", \"content\": \"Eres un asistente forense experto. Responde brevemente.\"},
         {\"role\": \"user\", \"content\": \"$1\"}
       ]
     }")

# 4. Extraer el contenido
CLEAN_RESP=$(echo "$RESPONSE" | jq -r '.choices[0].message.content')

if [ "$CLEAN_RESP" == "null" ]; then
    echo "Error: La IA no devolvió una respuesta válida."
else
    echo "$CLEAN_RESP"
fi