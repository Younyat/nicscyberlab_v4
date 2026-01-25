python3 - <<'EOF'
from questions.question_engine import QuestionEngine

engine = QuestionEngine(
    case_id="CASE-20260120-111611-40d8f88c",
    base_path="../collection_layer/evidence_store"
)

res = engine.answer("lateral_movement")
print(res)
EOF
