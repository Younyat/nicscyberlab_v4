python3 - <<'EOF'
from pathlib import Path
from analysis_layer.extraction.extract_modbus_packets import extract_modbus_packets

case_id = "CASE-20260120-111611-40d8f88c"
base_path = "/collection_layer/evidence_store"

case_path = Path(base_path) / case_id

records = extract_modbus_packets(case_path)

print(f"Total Modbus packets extracted: {len(records)}")
for r in records[:5]:
    print(r)
EOF
