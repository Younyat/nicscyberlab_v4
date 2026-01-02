import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SHA256:
    value: str

    @staticmethod
    def from_file(path: str) -> "SHA256":
        h = hashlib.sha256()
        p = Path(path)
        with p.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return SHA256(h.hexdigest())
