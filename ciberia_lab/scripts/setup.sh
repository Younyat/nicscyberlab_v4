#!/usr/bin/env bash
set -euo pipefail

MODULE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="${MODULE_ROOT}/external/CiberIA_O1_A1"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[1/5] Preparing directories..."
mkdir -p "${MODULE_ROOT}/external"
mkdir -p "${MODULE_ROOT}/generated"
mkdir -p "${MODULE_ROOT}/models"
mkdir -p "${MODULE_ROOT}/uploads"

echo "[2/5] Cloning or updating CiberIA_O1_A1..."
if [[ ! -d "${REPO_DIR}/.git" ]]; then
  git clone https://github.com/nicslabdev/CiberIA_O1_A1.git "${REPO_DIR}"
else
  git -C "${REPO_DIR}" fetch --all
  git -C "${REPO_DIR}" pull --ff-only || true
fi

echo "[3/5] Installing Python dependencies..."
"${PYTHON_BIN}" -m pip install --upgrade pip
"${PYTHON_BIN}" -m pip install \
  flask \
  pandas \
  numpy \
  scipy \
  scikit-learn==1.6.1 \
  lightgbm \
  xgboost \
  joblib \
  scapy \
  matplotlib

if [[ -f "${REPO_DIR}/Framework/requirements.txt" ]]; then
  "${PYTHON_BIN}" -m pip install -r "${REPO_DIR}/Framework/requirements.txt" || true
fi

echo "[4/5] Verifying default model files..."
test -f "${REPO_DIR}/Framework/stacked_model_original.pkl"
test -f "${REPO_DIR}/Framework/data_split_2017.pkl"

echo "[5/5] Setup finished."
echo "Module ready at: ${MODULE_ROOT}"
echo "Repo cloned at: ${REPO_DIR}"