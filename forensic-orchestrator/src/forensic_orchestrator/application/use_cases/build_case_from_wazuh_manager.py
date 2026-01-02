from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from forensic_orchestrator.application.ports.evidence_source import EvidenceSource
from forensic_orchestrator.application.ports.storage_repo import StorageRepository
from forensic_orchestrator.domain.entities.case import Case
from forensic_orchestrator.domain.entities.timeline_event import TimelineEvent


def _iso_to_dt(s: str) -> datetime:
    # Accepts "Z" or "+00:00"
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def _safe_str(x) -> str:
    return "" if x is None else str(x)


class BuildCaseFromWazuhManager:
    def __init__(self, evidence_source: EvidenceSource, storage_repo: StorageRepository):
        self.evidence = evidence_source
        self.storage = storage_repo

    def execute(
        self,
        agent_name: str,
        since: Optional[str] = None,
        until: Optional[str] = None,
        min_level: Optional[int] = None,
        case_id: Optional[str] = None,
    ) -> Case:
        now = datetime.now(timezone.utc)
        if not case_id:
            safe_agent = agent_name.replace(" ", "_")
            case_id = f"CASE-{now.strftime('%Y%m%d-%H%M%S')}-{safe_agent}"

        case_dir = self.storage.create_case_dir(case_id=case_id, agent_name=agent_name)

        # Metadata
        meta: Dict[str, Any] = {
            "case_id": case_id,
            "agent_name": agent_name,
            "created_utc": now.isoformat(),
            "filters": {"since": since, "until": until, "min_level": min_level},
            "source_paths": self.evidence.source_paths(),
        }
        self.storage.write_json(case_dir, "metadata.json", meta)

        # Build filtered evidence + timeline
        timeline: List[TimelineEvent] = []
        alerts_out_lines: List[str] = []
        archives_out_lines: List[str] = []

        dt_since = _iso_to_dt(since) if since else None
        dt_until = _iso_to_dt(until) if until else None

        def pass_time(ts: str) -> bool:
            if not ts:
                return False
            try:
                dt = _iso_to_dt(ts)
            except Exception:
                return False
            if dt_since and dt < dt_since:
                return False
            if dt_until and dt > dt_until:
                return False
            return True

        def pass_level(level: int) -> bool:
            if min_level is None:
                return True
            return level >= int(min_level)

        # Alerts
        total_alerts = 0
        kept_alerts = 0
        for ev in self.evidence.iter_alerts():
            total_alerts += 1
            a_name = (ev.get("agent") or {}).get("name")
            if a_name != agent_name:
                continue

            ts = ev.get("timestamp") or ""
            level = int(((ev.get("rule") or {}).get("level")) or 0)
            if not pass_time(ts) or not pass_level(level):
                continue

            kept_alerts += 1
            alerts_out_lines.append(_safe_str(ev).replace("'", '"'))  # keep simple JSON-ish
            timeline.append(
                TimelineEvent(
                    timestamp=ts,
                    agent_name=a_name,
                    level=level,
                    rule_id=_safe_str((ev.get("rule") or {}).get("id")),
                    rule_description=_safe_str((ev.get("rule") or {}).get("description")),
                    source="alerts",
                )
            )

        # Archives (optional)
        total_archives = 0
        kept_archives = 0
        if self.evidence.exists_archives():
            for ev in self.evidence.iter_archives():
                total_archives += 1
                a_name = (ev.get("agent") or {}).get("name")
                if a_name != agent_name:
                    continue
                ts = ev.get("timestamp") or ""
                # archives may not have rule/level; use 0
                level = int(((ev.get("rule") or {}).get("level")) or 0)
                if not pass_time(ts) or not pass_level(level):
                    continue

                kept_archives += 1
                archives_out_lines.append(_safe_str(ev).replace("'", '"'))
                # timeline: only include if it has timestamp
                if ts:
                    timeline.append(
                        TimelineEvent(
                            timestamp=ts,
                            agent_name=a_name,
                            level=level,
                            rule_id=_safe_str((ev.get("rule") or {}).get("id")),
                            rule_description=_safe_str((ev.get("rule") or {}).get("description")) or "archive_event",
                            source="archives",
                        )
                    )

        # Sort timeline (lexicographic ISO sort is OK for ISO timestamps)
        timeline.sort(key=lambda x: x.timestamp)

        # Persist filtered evidence as JSONL-like (one dict per line)
        # To keep robust and not depend on large JSON dumps, we write line-by-line as text.
        # Note: we store the original dict stringified; in a later iteration you can write exact json.dumps per line.
        alerts_content = "\n".join(alerts_out_lines) + ("\n" if alerts_out_lines else "")
        self.storage.write_text(case_dir, "evidence/alerts.filtered.jsonl", alerts_content)

        if self.evidence.exists_archives():
            archives_content = "\n".join(archives_out_lines) + ("\n" if archives_out_lines else "")
            self.storage.write_text(case_dir, "evidence/archives.filtered.jsonl", archives_content)

        # Stats
        stats = {
            "total_alerts_seen": total_alerts,
            "alerts_kept": kept_alerts,
            "archives_exists": self.evidence.exists_archives(),
            "total_archives_seen": total_archives,
            "archives_kept": kept_archives,
            "timeline_events": len(timeline),
            "critical_events_level>=10": sum(1 for e in timeline if e.level >= 10),
        }
        self.storage.write_json(case_dir, "derived/stats.json", stats)

        # Chain of custody entry
        self.storage.append_text(
            case_dir,
            "chain_of_custody.log",
            f"[{now.isoformat()}] EVIDENCE_COLLECTED source=wazuh_manager alerts_kept={kept_alerts} archives_kept={kept_archives}\n",
        )

        return Case(
            case_id=case_id,
            agent_name=agent_name,
            case_dir=case_dir,
            since=since,
            until=until,
            min_level=min_level,
            metadata=meta,
            stats=stats,
        )
