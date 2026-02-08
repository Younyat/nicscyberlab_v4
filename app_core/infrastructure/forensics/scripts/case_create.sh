#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="${1:-./evidence_store}"

UTC_NOW="$(date -u +%Y%m%d_%H%M%SZ)"
CASE_ID="CASE-${UTC_NOW}"
CASE_DIR="${BASE_DIR}/${CASE_ID}"

mkdir -p "${CASE_DIR}"/{network,disk,memory,industrial,metadata,logs}

cat > "${CASE_DIR}/metadata/manifest.json" <<EOF
{
  "case_id": "${CASE_ID}",
  "created_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "artifacts": []
}
EOF

: > "${CASE_DIR}/metadata/chain_of_custody.log"
chmod -R 750 "${CASE_DIR}"

echo "${CASE_DIR}"
