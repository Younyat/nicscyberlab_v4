from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class RunRequestDTO:
    config_path: str
    agent_name: str
    output_base_dir: Optional[str] = None
    since: Optional[str] = None
    until: Optional[str] = None
    min_level: Optional[int] = None
    case_id: Optional[str] = None
