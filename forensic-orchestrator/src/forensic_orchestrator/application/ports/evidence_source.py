from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterable, Dict, Any


class EvidenceSource(ABC):
    @abstractmethod
    def iter_alerts(self) -> Iterable[Dict[str, Any]]:
        """Iterate alerts.json events (JSON lines)."""
        raise NotImplementedError

    @abstractmethod
    def iter_archives(self) -> Iterable[Dict[str, Any]]:
        """Iterate archives.json events (JSON lines), may be empty if file doesn't exist."""
        raise NotImplementedError

    @abstractmethod
    def exists_archives(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def source_paths(self) -> dict:
        """Return source file paths (alerts/archives)."""
        raise NotImplementedError
