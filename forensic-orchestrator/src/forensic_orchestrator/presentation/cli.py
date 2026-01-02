import argparse
import os
from forensic_orchestrator.presentation.dtos.run_request import RunRequestDTO
from forensic_orchestrator.presentation.controllers.forensic_controller import ForensicController


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="forensic-orchestrator",
        description="Headless forensic case builder from Wazuh Manager evidence (alerts.json / archives.json).",
    )
    p.add_argument("--config", default="config/defaults.yaml", help="Path to YAML config.")
    p.add_argument("--agent", required=True, help="Wazuh agent name to filter (e.g., victim-01).")
    p.add_argument("--out", default=None, help="Override output base directory (cases/).")
    p.add_argument("--since", default=None, help="ISO8601 start time (e.g. 2025-12-27T00:00:00Z).")
    p.add_argument("--until", default=None, help="ISO8601 end time (e.g. 2025-12-27T23:59:59Z).")
    p.add_argument("--min-level", type=int, default=None, help="Minimum Wazuh rule level to include.")
    p.add_argument("--case-id", default=None, help="Optional fixed case id. If omitted, auto-generated.")
    return p.parse_args()


def main() -> None:
    args = _parse_args()

    req = RunRequestDTO(
        config_path=args.config,
        agent_name=args.agent,
        output_base_dir=args.out,
        since=args.since,
        until=args.until,
        min_level=args.min_level,
        case_id=args.case_id,
    )

    controller = ForensicController()
    result = controller.run(req)

    print("\n[OK] Forensic case created")
    print(f"Case ID: {result.case_id}")
    print(f"Case dir: {os.path.abspath(result.case_dir)}")
    print("Artifacts:")
    for a in result.artifacts:
        print(f"  - {a}")
