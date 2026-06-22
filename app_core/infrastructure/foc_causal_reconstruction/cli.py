from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .service import _run_once


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run derived FOC causal reconstruction over a preserved forensic case.")
    parser.add_argument("--case-path", required=True, help="Path to the preserved case directory.")
    parser.add_argument("--ground-truth", required=True, help="Path to scenario_ground_truth.json.")
    parser.add_argument("--out", default="derived/reconstruction", help="Output directory relative to the case path.")
    parser.add_argument("--strict", action="store_true", help="Fail if any expected edge is missing.")
    parser.add_argument("--degraded-ok", action="store_true", help="Allow degraded or ambiguous outputs for stress or constrained runs.")
    parser.add_argument("--json", action="store_true", help="Print the final status payload as JSON.")
    args = parser.parse_args(argv)

    case_path = Path(args.case_path).expanduser()
    if not case_path.is_dir():
        return 1
    if not (case_path / "manifest.json").is_file():
        return 2
    if not (case_path / "chain_of_custody.log").is_file():
        return 3
    if not Path(args.ground_truth).expanduser().is_file():
        return 4

    try:
        payload = _run_once(
            case_id=case_path.name,
            case_path=case_path,
            strict=bool(args.strict),
            degraded_ok=bool(args.degraded_ok),
            ground_truth_path=str(Path(args.ground_truth).expanduser()),
            out_dir=args.out,
        )
    except ValueError:
        return 5
    except Exception:
        return 6

    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"status={payload.get('status')} case_id={payload.get('case_id')} reason={payload.get('reason')}")

    if args.strict and payload.get("status") == "failed":
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
