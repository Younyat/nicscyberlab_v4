#!/usr/bin/env bash
set -euo pipefail   # -u también ayuda a detectar variables no definidas

echo "============================================"
echo " MODBUS UNAUTHORIZED WRITE – FORENSIC CHAIN "
echo "============================================"

for script in 01_capture.sh 02_attack.sh 03_analyze.sh; do
    if [[ ! -f "$script" ]]; then
        echo "ERROR: no existe $script" >&2
        exit 1
    fi
    chmod +x "$script" 2>/dev/null || true
    if [[ ! -x "$script" ]]; then
        echo "ERROR: no puedo hacer ejecutable $script" >&2
        exit 1
    fi
done

# ── Captura en background
echo "→ Lanzando captura..."
./01_capture.sh &> capture.log &
CAPTURE_PID=$!
sleep 1    # pequeña espera para que tcpdump realmente arranque

if ! ps -p $CAPTURE_PID >/dev/null; then
    echo "ERROR: 01_capture.sh no está corriendo (pid $CAPTURE_PID)"
    exit 1
fi

# ── Espera baseline
echo "→ Esperando 5s de tráfico limpio..."
sleep 5

# ── Ataque
echo "→ Ejecutando ataque..."
if ! ./02_attack.sh; then
    echo "⚠️  02_attack.sh terminó con error (código $?) → se para la cadena"
    kill $CAPTURE_PID 2>/dev/null || true
    exit 1
fi

# ── Esperar captura
echo "→ Esperando que termine tcpdump..."
wait $CAPTURE_PID 2>/dev/null || echo "tcpdump ya había terminado"

# ── Análisis
echo "→ Lanzando análisis..."
./03_analyze.sh

echo
echo "[DONE] Full forensic chain completed"