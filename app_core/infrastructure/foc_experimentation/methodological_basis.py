from __future__ import annotations

import json

from .config import METHODOLOGICAL_BASIS_FILE


def load_methodological_basis() -> dict:
    try:
        return json.loads(METHODOLOGICAL_BASIS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {
            "generated_by": "foc_experimentation",
            "description": "Methodological basis file could not be loaded.",
            "references": [],
        }
