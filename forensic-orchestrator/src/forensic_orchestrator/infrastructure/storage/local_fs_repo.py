import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Iterable

from forensic_orchestrator.application.ports.storage_repo import StorageRepository


class LocalFSStorageRepository(StorageRepository):
    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)

    def create_case_dir(self, case_id: str, agent_name: str) -> str:
        self.base_dir.mkdir(parents=True, exist_ok=True)
        case_dir = self.base_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        # Standard subdirs
        for sub in ["evidence", "derived", "report", "integrity"]:
            (case_dir / sub).mkdir(parents=True, exist_ok=True)

        # Initialize chain of custody
        coc_path = case_dir / "chain_of_custody.log"
        ts = datetime.now(timezone.utc).isoformat()
        coc_path.write_text(
            f"[{ts}] CASE_CREATED agent={agent_name} case_id={case_id}\n",
            encoding="utf-8",
        )
        return str(case_dir)

    def ensure_dir(self, case_dir: str, rel_dir: str) -> str:
        p = Path(case_dir) / rel_dir
        p.mkdir(parents=True, exist_ok=True)
        return str(p)

    def write_json(self, case_dir: str, rel_path: str, data: Dict[str, Any]) -> str:
        p = Path(case_dir) / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(p)

    def write_text(self, case_dir: str, rel_path: str, text: str) -> str:
        p = Path(case_dir) / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return str(p)

    def write_bytes(self, case_dir: str, rel_path: str, content: bytes) -> str:
        p = Path(case_dir) / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
        return str(p)

    def append_text(self, case_dir: str, rel_path: str, text: str) -> str:
        p = Path(case_dir) / rel_path
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as f:
            f.write(text)
        return str(p)

    def list_files_recursive(self, case_dir: str) -> Iterable[str]:
        root = Path(case_dir)
        for p in root.rglob("*"):
            if p.is_file():
                yield str(p)
