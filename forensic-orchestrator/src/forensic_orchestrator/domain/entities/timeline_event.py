from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: str
    agent_name: str
    level: int
    rule_id: Optional[str]
    rule_description: str
    source: str  # "alerts" or "archives"
