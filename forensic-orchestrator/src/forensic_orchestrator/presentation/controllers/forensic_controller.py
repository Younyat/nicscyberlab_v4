from dataclasses import dataclass
from typing import List

import yaml

from forensic_orchestrator.presentation.dtos.run_request import RunRequestDTO
from forensic_orchestrator.application.use_cases.build_case_from_wazuh_manager import BuildCaseFromWazuhManager
from forensic_orchestrator.application.use_cases.generate_report import GenerateReport

from forensic_orchestrator.infrastructure.evidence_sources.wazuh_manager_fs_source import WazuhManagerFSEvidenceSource
from forensic_orchestrator.infrastructure.storage.local_fs_repo import LocalFSStorageRepository
from forensic_orchestrator.infrastructure.reporting.txt_report import TxtReportRenderer
from forensic_orchestrator.infrastructure.reporting.csv_timeline import CsvTimelineWriter


@dataclass(frozen=True)
class RunResult:
    case_id: str
    case_dir: str
    artifacts: List[str]


class ForensicController:
    """
    Presentation Controller (MVC). It:
      - loads config
      - wires adapters
      - calls use cases
    """

    def run(self, req: RunRequestDTO) -> RunResult:
        with open(req.config_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

        alerts_path = cfg.get("evidence", {}).get("alerts_path", "/var/ossec/logs/alerts/alerts.json")
        archives_path = cfg.get("evidence", {}).get("archives_path", "/var/ossec/logs/archives/archives.json")

        base_dir = req.output_base_dir or cfg.get("output", {}).get("base_dir", "./cases")
        report_cfg = cfg.get("report", {}) or {}

        evidence_source = WazuhManagerFSEvidenceSource(
            alerts_path=alerts_path,
            archives_path=archives_path,
        )
        storage = LocalFSStorageRepository(base_dir=base_dir)

        build_case = BuildCaseFromWazuhManager(
            evidence_source=evidence_source,
            storage_repo=storage,
        )

        case = build_case.execute(
            agent_name=req.agent_name,
            since=req.since,
            until=req.until,
            min_level=req.min_level,
            case_id=req.case_id,
        )

        report_renderer = TxtReportRenderer(
            top_timeline_rows=int(report_cfg.get("top_timeline_rows", 50)),
            suspicious_keywords=list(report_cfg.get("suspicious_keywords", [])),
        )
        timeline_writer = CsvTimelineWriter()

        generate_report = GenerateReport(
            storage_repo=storage,
            report_renderer=report_renderer,
            timeline_writer=timeline_writer,
        )
        artifacts = generate_report.execute(case)

        return RunResult(case_id=case.case_id, case_dir=case.case_dir, artifacts=artifacts)
