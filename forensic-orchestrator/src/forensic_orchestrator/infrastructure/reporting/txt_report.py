from typing import List, Dict, Any
from forensic_orchestrator.application.ports.report_renderer import ReportRenderer
from forensic_orchestrator.domain.entities.case import Case
from forensic_orchestrator.domain.entities.timeline_event import TimelineEvent


class TxtReportRenderer(ReportRenderer):
    def __init__(self, top_timeline_rows: int = 50, suspicious_keywords=None):
        self.top = max(1, int(top_timeline_rows))
        self.keywords = [k.lower() for k in (suspicious_keywords or [])]

    def render_txt(self, case: Case, timeline: List[TimelineEvent], stats: Dict[str, Any]) -> str:
        lines = []
        lines.append("WAZUH FORENSIC REPORT (HEADLESS)")
        lines.append("=" * 34)
        lines.append("")
        lines.append(f"Case ID: {case.case_id}")
        lines.append(f"Agent: {case.agent_name}")
        lines.append(f"Since: {case.since or '-'}")
        lines.append(f"Until: {case.until or '-'}")
        lines.append(f"Min level: {case.min_level if case.min_level is not None else '-'}")
        lines.append("")
        lines.append("STATS")
        lines.append("-" * 5)
        for k, v in stats.items():
            lines.append(f"- {k}: {v}")
        lines.append("")

        lines.append(f"TIMELINE (top {self.top})")
        lines.append("-" * 18)
        for ev in timeline[: self.top]:
            lines.append(f"{ev.timestamp}\tL{ev.level}\t{ev.agent_name}\t{ev.rule_description} [{ev.source}]")
        lines.append("")

        # Critical
        critical = [e for e in timeline if e.level >= 10]
        lines.append("CRITICAL EVENTS (level >= 10)")
        lines.append("-" * 27)
        if critical:
            for ev in critical[: 50]:
                lines.append(f"{ev.timestamp}\tL{ev.level}\t{ev.rule_description} [{ev.source}]")
        else:
            lines.append("(none)")
        lines.append("")

        # Suspicious keyword hits
        if self.keywords:
            hits = []
            for ev in timeline:
                d = (ev.rule_description or "").lower()
                if any(k in d for k in self.keywords):
                    hits.append(ev)
            lines.append("SUSPICIOUS KEYWORD HITS")
            lines.append("-" * 22)
            if hits:
                for ev in hits[: 50]:
                    lines.append(f"{ev.timestamp}\tL{ev.level}\t{ev.rule_description} [{ev.source}]")
            else:
                lines.append("(none)")
            lines.append("")

        lines.append("NOTES")
        lines.append("-" * 5)
        lines.append("Evidence source: Wazuh Manager JSON logs (alerts/archives).")
        lines.append("This report is generated offline and does not require Wazuh Dashboard.")
        lines.append("")
        return "\n".join(lines)
