#!/usr/bin/env python3
"""Smoke test: attempt to generate symbols for the first available case.
Usage: python3 test_vol3_symbol_generation.py [case_id] [dump_id]
"""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from app_core.infrastructure.foc_reconstruction.foc_case_analysis import (
    generate_symbols_for_case,
    _list_case_entries,
)

if __name__ == '__main__':
    args = sys.argv[1:]
    case_id = args[0] if args else None
    dump_id = args[1] if len(args) > 1 else None
    if not case_id:
        cases = _list_case_entries()
        if not cases:
            print(json.dumps({"error": "no_cases_found"}))
            sys.exit(2)
        case_id = cases[0].get("case_id")
    report = generate_symbols_for_case(case_id, dump_id=dump_id)
    print(json.dumps(report, indent=2))
