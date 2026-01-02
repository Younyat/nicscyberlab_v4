import json
from typing import Iterable, Dict, Any
from pathlib import Path

from forensic_orchestrator.application.ports.evidence_source import EvidenceSource


class WazuhManagerFSEvidenceSource(EvidenceSource):
    def __init__(self, alerts_path: str, archives_path: str):
        self._alerts_path = Path(alerts_path)
        self._archives_path = Path(archives_path)

    def iter_alerts(self) -> Iterable[Dict[str, Any]]:
        if not self._alerts_path.exists():
            raise FileNotFoundError(f"alerts.json not found: {self._alerts_path}")
        with self._alerts_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    # skip malformed lines
                    continue

    def iter_archives(self) -> Iterable[Dict[str, Any]]:
        if not self._archives_path.exists():
            return
            yield  # pragma: no cover
        with self._archives_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def exists_archives(self) -> bool:
        return self._archives_path.exists()

    def source_paths(self) -> dict:
        return {
            "alerts_path": str(self._alerts_path),
            "archives_path": str(self._archives_path),
        }
