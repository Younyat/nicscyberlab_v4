import pathlib
from questions.question_registry import QUESTION_REGISTRY
from extraction.extract_modbus_frames import extract_modbus_frames
from extraction.extract_system_facts import extract_system_facts
from extraction.extract_industrial_state import extract_industrial_state


class QuestionEngine:
    def __init__(self, case_id: str, base_path: str):
        self.case_path = pathlib.Path(base_path) / case_id
        self.facts = {}

    def build_facts(self):
        self.facts["modbus_frames"] = extract_modbus_frames(self.case_path)
        self.facts["system"] = extract_system_facts(self.case_path)
        self.facts["industrial"] = extract_industrial_state(self.case_path)

    def answer(self, question_id: str) -> dict:
        if question_id not in QUESTION_REGISTRY:
            raise ValueError(f"Unknown question: {question_id}")

        self.build_facts()

        question_cls = QUESTION_REGISTRY[question_id]
        question = question_cls()        # SIN argumentos
        return question.run(self.facts)  # SIEMPRE run(facts)
