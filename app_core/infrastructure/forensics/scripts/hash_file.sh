#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Uso: $0 <file>"
  exit 1
fi

FILE="$1"
[[ -f "$FILE" ]] || { echo "No existe: $FILE"; exit 1; }

sha256sum "$FILE" | awk '{print $1}'
