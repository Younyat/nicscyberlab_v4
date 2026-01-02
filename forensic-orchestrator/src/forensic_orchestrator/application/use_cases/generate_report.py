from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

from forensic_orchestrator.application.ports.storage_repo import StorageRepository
from forensic_orchestrator.application.ports.report_renderer import ReportRenderer
from forensic_orchestrator.domain.entities.case import Case
from forensic_orchestrator.domain.entities.timeline_event import TimelineEvent
from forensic_orchestrator.domain.value_objects.hash import SHA256
from forensic_orchestrator.infrastructure.reporting.csv_timeline import CsvTimelineWriter
import json


class GenerateReport:
    def __init__(
        self,
        storage_repo: StorageRepository,
        report_renderer: ReportRenderer,
        timeline_writer: CsvTimelineWriter,
    ):
        self.storage = storage_repo
        self.renderer = report_renderer
        self.timeline_writer = timeline_writer

    def _load_timeline(self, case_dir: str) -> List[TimelineEvent]:
        # Reconstruct timeline from evidence files is possible, but we keep it simple:
        # timeline.csv will be written from the timeline we rebuild using derived stats + filtered evidence.
        # For now, we rebuild timeline by parsing filtered alerts jsonl (best-effort).
        tl: List[TimelineEvent] = []
        alerts_path = Path(case_dir) / "evidence/alerts.filtered.jsonl"
        if alerts_path.exists():
            for line in alerts_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                a_name = (ev.get("agent") or {}).get("name") or ""
                ts = ev.get("timestamp") or ""
                rule = ev.get("rule") or {}
                level = int(rule.get("level") or 0)
                tl.append(
                    TimelineEvent(
                        timestamp=ts,
                        agent_name=a_name,
                        level=level,
                        rule_id=str(rule.get("id") or ""),
                        rule_description=str(rule.get("description") or ""),
                        source="alerts",
                    )
                )

        # If archives exist, try parse them too
        arch_path = Path(case_dir) / "evidence/archives.filtered.jsonl"
        if arch_path.exists():
            for line in arch_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                a_name = (ev.get("agent") or {}).get("name") or ""
                ts = ev.get("timestamp") or ""
                rule = ev.get("rule") or {}
                level = int(rule.get("level") or 0)
                tl.append(
                    TimelineEvent(
                        timestamp=ts,
                        agent_name=a_name,
                        level=level,
                        rule_id=str(rule.get("id") or ""),
                        rule_description=str(rule.get("description") or "archive_event"),
                        source="archives",
                    )
                )

        tl.sort(key=lambda x: x.timestamp)
        return tl

    def execute(self, case: Case) -> List[str]:
        case_dir = case.case_dir
        artifacts: List[str] = []

        # Load timeline reconstructed
        timeline = self._load_timeline(case_dir)

        # Stats
        stats_path = Path(case_dir) / "derived/stats.json"
        stats: Dict[str, Any] = {}
        if stats_path.exists():
            stats = json.loads(stats_path.read_text(encoding="utf-8"))
        else:
            stats = {"timeline_events": len(timeline)}

        # Write timeline.csv
        timeline_csv_path = Path(case_dir) / "derived/timeline.csv"
        self.timeline_writer.write(str(timeline_csv_path), timeline)
        artifacts.append(str(timeline_csv_path))

        # Write report.txt
        report_txt = self.renderer.render_txt(case=case, timeline=timeline, stats=stats)
        report_path = self.storage.write_text(case_dir, "report/report.txt", report_txt)
        artifacts.append(report_path)

        # Build SHA256 manifest
        manifest_lines = []
        for file_path in sorted(self.storage.list_files_recursive(case_dir)):
            # Exclude manifest itself if present (avoid recursion); we write it last anyway
            if file_path.endswith("integrity/manifest.sha256"):
                continue
            digest = SHA256.from_file(file_path).value
            rel = str(Path(file_path).relative_to(Path(case_dir)))
            manifest_lines.append(f"{digest}  {rel}")

        manifest_content = "\n".join(manifest_lines) + "\n"
        manifest_path = self.storage.write_text(case_dir, "integrity/manifest.sha256", manifest_content)
        artifacts.append(manifest_path)

        # Chain of custody update
        now = datetime.now(timezone.utc).isoformat()
        self.storage.append_text(
            case_dir,
            "chain_of_custody.log",
            f"[{now}] REPORT_GENERATED artifacts={len(artifacts)}\n",
        )

        return artifacts
