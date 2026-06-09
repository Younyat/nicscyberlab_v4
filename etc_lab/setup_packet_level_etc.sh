#!/usr/bin/env bash
set -Eeuo pipefail

trap 'echo "[ERROR] Fallo en línea ${LINENO}" >&2' ERR

# ============================================================
# packet-level-etc Linux bootstrap idempotente
#
# Ejemplos:
#   CAPTURE_IFACE=ens33 CAPTURE_SECONDS=120 ./setup_packet_level_etc.sh
#   CAPTURE_IFACE=eth0 TCPDUMP_FILTER="tcp" ./setup_packet_level_etc.sh
#   CAPTURE_IFACE=eth0 TCPDUMP_FILTER="host 192.168.1.10" ./setup_packet_level_etc.sh
#   FORCE_EXTRACT=1 FORCE_TRAIN=1 ./setup_packet_level_etc.sh
#    cd /home/younes/nicscyberlab_v3/etc_lab
#    BASE_DIR=/home/younes/nicscyberlab_v3/etc_lab/runtime CAPTURE_IFACE=ens33 CAPTURE_SECONDS=120 FORCE_EXTRACT=1 FORCE_TRAIN=1 ./setup_packet_level_etc.sh
# Qué hace:
# - Clona repo si falta
# - Crea venv si falta
# - Instala dependencias si faltan
# - Captura tráfico si no hay PCAP y se configura interfaz
# - Extrae features si hay PCAP
# - Entrena modelos si hay features
# - Corrige dash_app.py para usar los artefactos generados
# - Ejecuta predict si hay modelo
# - Lanza el dashboard si se solicita y el entorno está listo
#   
# Importante:
# - Los PCAP deben ir en: <repo_clonado>/pcaps
# - Si no hay PCAP todavía, la instalación NO falla
# ============================================================

# =========================
# CONFIGURACIÓN
# =========================
REPO_URL="${REPO_URL:-https://github.com/nicslabdev/packet-level-etc.git}"
BASE_DIR="${BASE_DIR:-$HOME/integracion_packet_level_etc}"
REPO_DIR="${REPO_DIR:-$BASE_DIR/packet-level-etc}"

VENV_DIR="${VENV_DIR:-$REPO_DIR/.venv}"

DATASET_NAME="${DATASET_NAME:-nics_etc}"
N_BYTES="${N_BYTES:-100}"
BIT_TYPE="${BIT_TYPE:-8}"
MODEL_NAME="${MODEL_NAME:-randomforest}"

PCAP_DIR="${PCAP_DIR:-$REPO_DIR/pcaps}"
FEATURES_DIR="${FEATURES_DIR:-$REPO_DIR/features}"
MODELS_DIR="${MODELS_DIR:-$REPO_DIR/models}"

PCAP_FILE="${PCAP_FILE:-$PCAP_DIR/${DATASET_NAME}.pcap}"
FEATURES_FILE="${FEATURES_FILE:-$FEATURES_DIR/${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.npz}"

MODEL_FILE="${MODEL_FILE:-$MODELS_DIR/${MODEL_NAME}_${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.joblib}"
XGBOOST_FILE="${XGBOOST_FILE:-$MODELS_DIR/xgboost_${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.joblib}"
SCALER_FILE="${SCALER_FILE:-$MODELS_DIR/scaler_${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.joblib}"
ENCODER_FILE="${ENCODER_FILE:-$MODELS_DIR/le_${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.joblib}"
MODEL_JSON="${MODEL_JSON:-$MODELS_DIR/${MODEL_NAME}_${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.json}"

# Captura
CAPTURE_IFACE="${CAPTURE_IFACE:-}"
CAPTURE_SECONDS="${CAPTURE_SECONDS:-60}"
TCPDUMP_FILTER="${TCPDUMP_FILTER:-}"

# Control de ejecución
LAUNCH_DASH="${LAUNCH_DASH:-1}"
FORCE_EXTRACT="${FORCE_EXTRACT:-0}"
FORCE_TRAIN="${FORCE_TRAIN:-0}"
FORCE_PATCH_DASH="${FORCE_PATCH_DASH:-1}"
RUN_PREDICT_CHECK="${RUN_PREDICT_CHECK:-1}"

# Dependencias Python
PY_PACKAGES=(
  numpy
  pandas
  scikit-learn
  joblib
  tabulate
  tqdm
  scapy
  dash
  plotly
  cryptography
  xgboost
  lightgbm
)

# =========================
# UTILIDADES
# =========================
log()  { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "No se encontró el comando requerido: $1"
}

file_exists_nonempty() {
  [[ -f "$1" && -s "$1" ]]
}

dir_has_pcaps() {
  find "$1" -maxdepth 1 \( -iname "*.pcap" -o -iname "*.pcapng" \) | grep -q .
}

activate_venv() {
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
}

pip_pkg_installed() {
  python -m pip show "$1" >/dev/null 2>&1
}

install_missing_packages() {
  local missing=()
  for pkg in "${PY_PACKAGES[@]}"; do
    if ! pip_pkg_installed "$pkg"; then
      missing+=("$pkg")
    fi
  done

  if [[ ${#missing[@]} -eq 0 ]]; then
    log "Todas las dependencias Python ya están instaladas."
    return 0
  fi

  log "Instalando dependencias faltantes: ${missing[*]}"
  python -m pip install --upgrade pip
  python -m pip install "${missing[@]}"
  return 0
}

clone_or_update_repo() {
  mkdir -p "$BASE_DIR"

  if [[ ! -d "$REPO_DIR/.git" ]]; then
    log "Clonando repositorio en $REPO_DIR"
    git clone "$REPO_URL" "$REPO_DIR"
  else
    log "El repositorio ya existe. Se omite clonación."
  fi
}

create_venv_if_needed() {
  if [[ ! -d "$VENV_DIR" ]]; then
    log "Creando entorno virtual en $VENV_DIR"
    python3 -m venv "$VENV_DIR"
  else
    log "El entorno virtual ya existe. Se omite creación."
  fi
}

prepare_dirs() {
  mkdir -p "$PCAP_DIR" "$FEATURES_DIR" "$MODELS_DIR"
  log "Directorio PCAP preparado en: $PCAP_DIR"
}

capture_if_needed() {
  if dir_has_pcaps "$PCAP_DIR"; then
    log "Ya existen PCAP en $PCAP_DIR. Se omite captura."
    return 0
  fi

  if [[ -z "$CAPTURE_IFACE" ]]; then
    warn "No hay PCAP y no se ha definido CAPTURE_IFACE. Se omite captura."
    warn "Define CAPTURE_IFACE=eth0 o similar si quieres capturar automáticamente."
    return 0
  fi

  require_cmd tcpdump
  require_cmd timeout
  require_cmd sudo

  log "No hay PCAP. Iniciando captura en interfaz '$CAPTURE_IFACE' durante ${CAPTURE_SECONDS}s"

  local rc=0

  if [[ -n "$TCPDUMP_FILTER" ]]; then
    log "Filtro tcpdump: $TCPDUMP_FILTER"
    set +e
    sudo timeout "$CAPTURE_SECONDS" tcpdump -i "$CAPTURE_IFACE" $TCPDUMP_FILTER -w "$PCAP_FILE"
    rc=$?
    set -e
  else
    set +e
    sudo timeout "$CAPTURE_SECONDS" tcpdump -i "$CAPTURE_IFACE" -w "$PCAP_FILE"
    rc=$?
    set -e
  fi

  # timeout devuelve 124 al expirar el tiempo, y a veces 143 por SIGTERM.
  if [[ "$rc" != "0" && "$rc" != "124" && "$rc" != "143" ]]; then
    die "La captura tcpdump falló con código $rc"
  fi

  if file_exists_nonempty "$PCAP_FILE"; then
    log "Captura completada: $PCAP_FILE"
  else
    warn "La captura terminó pero no generó un fichero válido."
  fi

  return 0
}

extract_features_if_needed() {
  if [[ "$FORCE_EXTRACT" == "1" ]]; then
    log "FORCE_EXTRACT=1. Reextrayendo features."
  elif file_exists_nonempty "$FEATURES_FILE"; then
    log "El fichero de features ya existe. Se omite extracción: $FEATURES_FILE"
    return 0
  fi

  if ! dir_has_pcaps "$PCAP_DIR"; then
    warn "No hay PCAP en $PCAP_DIR. Se omite extracción de features."
    return 0
  fi

  log "Extrayendo features desde $PCAP_DIR"
  (
    cd "$REPO_DIR"
    python extract_features.py "$PCAP_DIR" --dataset "$DATASET_NAME" --N "$N_BYTES" --bit_type "$BIT_TYPE"
  )

  if file_exists_nonempty "$FEATURES_FILE"; then
    log "Features generadas correctamente: $FEATURES_FILE"
    return 0
  fi

  warn "No se generó el fichero de features esperado: $FEATURES_FILE"
  return 0
}

train_if_needed() {
  local need_train=0

  if [[ "$FORCE_TRAIN" == "1" ]]; then
    need_train=1
    log "FORCE_TRAIN=1. Reentrenando modelos."
  else
    [[ -f "$MODEL_FILE" ]]   || need_train=1
    [[ -f "$SCALER_FILE" ]]  || need_train=1
    [[ -f "$ENCODER_FILE" ]] || need_train=1
    [[ -f "$MODEL_JSON" ]]   || need_train=1
  fi

  if [[ "$need_train" == "0" ]]; then
    log "Los artefactos del modelo ya existen. Se omite entrenamiento."
    return 0
  fi

  if ! file_exists_nonempty "$FEATURES_FILE"; then
    warn "No existe el fichero de features: $FEATURES_FILE. Se omite entrenamiento."
    return 0
  fi

  log "Entrenando modelos y exportando artefactos"
  (
    cd "$REPO_DIR"
    python ml_train_models.py --input "$FEATURES_FILE" --models randomforest xgboost --export
  )

  if [[ -f "$MODEL_FILE" && -f "$SCALER_FILE" && -f "$ENCODER_FILE" && -f "$MODEL_JSON" ]]; then
    log "Entrenamiento completado."
    return 0
  fi

  warn "El entrenamiento no generó todos los artefactos esperados."
  return 0
}

patch_dash_app() {
  local dash_file="$REPO_DIR/dash_app.py"

  if [[ ! -f "$dash_file" ]]; then
    warn "No existe dash_app.py en $REPO_DIR. Se omite parche."
    return 0
  fi

  if [[ "$FORCE_PATCH_DASH" != "1" ]]; then
    log "FORCE_PATCH_DASH=0. Se omite parche de dash_app.py"
    return 0
  fi

  if [[ ! -f "$MODEL_FILE" || ! -f "$SCALER_FILE" || ! -f "$ENCODER_FILE" ]]; then
    warn "No existen todavía todos los artefactos del modelo. Se omite parche de dash_app.py"
    return 0
  fi

  log "Ajustando dash_app.py para usar los artefactos generados"

  python <<PY
from pathlib import Path
import re

dash_file = Path(r"$dash_file")
text = dash_file.read_text(encoding="utf-8")

model_path = "models/${MODEL_NAME}_${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.joblib"
scaler_path = "models/scaler_${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.joblib"
encoder_path = "models/le_${DATASET_NAME}_N${N_BYTES}_BIT${BIT_TYPE}.joblib"

patterns = {
    r'^MODEL_PATH\\s*=\\s*.*$': f'MODEL_PATH = "{model_path}"',
    r'^SCALER_PATH\\s*=\\s*.*$': f'SCALER_PATH = "{scaler_path}"',
    r'^ENCODER_PATH\\s*=\\s*.*$': f'ENCODER_PATH = "{encoder_path}"',
}

for pattern, repl in patterns.items():
    if re.search(pattern, text, flags=re.MULTILINE):
        text = re.sub(pattern, repl, text, flags=re.MULTILINE)
    else:
        text = repl + "\\n" + text

text = re.sub(
    r'label_encoder\\s*=\\s*load\\([^\\)]*\\)',
    'label_encoder = load(ENCODER_PATH)',
    text
)

dash_file.write_text(text, encoding="utf-8")
print("[INFO] dash_app.py parcheado correctamente")
PY

  return 0
}

predict_check() {
  if [[ "$RUN_PREDICT_CHECK" != "1" ]]; then
    log "RUN_PREDICT_CHECK=0. Se omite predict."
    return 0
  fi

  if ! file_exists_nonempty "$FEATURES_FILE"; then
    warn "No hay features. Se omite predict."
    return 0
  fi

  if [[ ! -f "$MODEL_JSON" ]]; then
    warn "No hay JSON de modelo. Se omite predict."
    return 0
  fi

  log "Ejecutando predicción de comprobación"
  (
    cd "$REPO_DIR"
    python predict.py --features "$FEATURES_FILE" --config "$MODEL_JSON" --weights_dir "$MODELS_DIR"
  ) || warn "Predict falló. Se continúa sin abortar."

  return 0
}

can_launch_dash() {
  [[ -f "$REPO_DIR/dash_app.py" ]] &&
  [[ -f "$MODEL_FILE" ]] &&
  [[ -f "$SCALER_FILE" ]] &&
  [[ -f "$ENCODER_FILE" ]]
}

launch_dash() {
  if [[ "$LAUNCH_DASH" != "1" ]]; then
    log "LAUNCH_DASH=0. Se omite arranque del dashboard."
    return 0
  fi

  if ! can_launch_dash; then
    warn "No se puede lanzar el dashboard todavía."
    warn "Faltan dash_app.py o artefactos de modelo."
    warn "Añade PCAP en $PCAP_DIR y vuelve a ejecutar el flujo."
    return 0
  fi

  log "Lanzando dashboard en http://127.0.0.1:8050/"
  log "Pulsa Ctrl+C para detenerlo."
  (
    cd "$REPO_DIR"
    python dash_app.py
  )
}

print_summary() {
  cat <<EOF

============================================================
RESUMEN
============================================================
Repo:              $REPO_DIR
Venv:              $VENV_DIR
PCAP dir:          $PCAP_DIR
Features file:     $FEATURES_FILE
Model file:        $MODEL_FILE
Scaler file:       $SCALER_FILE
Encoder file:      $ENCODER_FILE
Model JSON:        $MODEL_JSON
Dashboard URL:     http://127.0.0.1:8050/
============================================================

Estado del flujo:
- El repositorio se clona en: $REPO_DIR
- Los PCAP deben colocarse en: $PCAP_DIR
- Si no hay PCAP todavía, la instalación base termina igualmente
- La extracción, el entrenamiento y el predict solo se ejecutan si hay datos

Nota importante:
Tu validación puede dar accuracy 1.0 con una sola clase.
Eso demuestra que el pipeline funciona, pero no valida bien el modelo.
Para validar de verdad, necesitas PCAP con varias clases reales.

EOF
}

main() {
  require_cmd git
  require_cmd python3

  clone_or_update_repo
  create_venv_if_needed
  activate_venv
  install_missing_packages
  prepare_dirs
  capture_if_needed
  extract_features_if_needed
  train_if_needed
  patch_dash_app
  predict_check
  print_summary
  launch_dash
}

main "$@"