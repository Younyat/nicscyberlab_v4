from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, Iterable


class StorageRepository(ABC):
    @abstractmethod
    def create_case_dir(self, case_id: str, agent_name: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def write_json(self, case_dir: str, rel_path: str, data: Dict[str, Any]) -> str:
        raise NotImplementedError

    @abstractmethod
    def write_text(self, case_dir: str, rel_path: str, text: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def write_bytes(self, case_dir: str, rel_path: str, content: bytes) -> str:
        raise NotImplementedError

    @abstractmethod
    def append_text(self, case_dir: str, rel_path: str, text: str) -> str:
        raise NotImplementedError

    @abstractmethod
    def list_files_recursive(self, case_dir: str) -> Iterable[str]:
        raise NotImplementedError

    @abstractmethod
    def ensure_dir(self, case_dir: str, rel_dir: str) -> str:
        raise NotImplementedError
