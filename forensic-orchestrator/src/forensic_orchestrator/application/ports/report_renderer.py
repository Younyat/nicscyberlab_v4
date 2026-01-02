from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from forensic_orchestrator.domain.entities.case import Case
from forensic_orchestrator.domain.entities.timeline_event import TimelineEvent


class ReportRenderer(ABC):
    @abstractmethod
    def render_txt(self, case: Case, timeline: List[TimelineEvent], stats: Dict[str, Any]) -> str:
        raise NotImplementedError
