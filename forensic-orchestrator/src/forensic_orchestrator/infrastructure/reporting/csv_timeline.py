import csv
from typing import List
from forensic_orchestrator.domain.entities.timeline_event import TimelineEvent


class CsvTimelineWriter:
    def write(self, csv_path: str, timeline: List[TimelineEvent]) -> None:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "agent", "level", "rule_id", "description", "source"])
            for ev in timeline:
                w.writerow([ev.timestamp, ev.agent_name, ev.level, ev.rule_id or "", ev.rule_description, ev.source])
