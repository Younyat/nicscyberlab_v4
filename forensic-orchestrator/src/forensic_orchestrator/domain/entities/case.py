from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class Case:
    case_id: str
    agent_name: str
    case_dir: str

    since: Optional[str] = None
    until: Optional[str] = None
    min_level: Optional[int] = None

    metadata: Dict[str, Any] = None
    stats: Dict[str, Any] = None
