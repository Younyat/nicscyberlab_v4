#!/usr/bin/env bash
set -euo pipefail

JSON_FILE="${1:-}"

if [[ -z "$JSON_FILE" ]]; then
    echo "Usage: $0 <json_file>"
    exit 1
fi

if [[ ! -f "$JSON_FILE" ]]; then
    echo "ERROR: File not found: $JSON_FILE"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required"
    exit 1
fi

INSTANCE_NAME="$(jq -r '.name // "N/A"' "$JSON_FILE")"

echo "Instance: $INSTANCE_NAME"
echo "Installed tools:"

TOOLS_OUTPUT="$(jq -r '
  (.tools // {})
  | to_entries[]
  | select(.value == "installed")
  | " - \(.key)"
' "$JSON_FILE")"

if [[ -z "$TOOLS_OUTPUT" ]]; then
    echo " - None"
else
    echo "$TOOLS_OUTPUT"
fi