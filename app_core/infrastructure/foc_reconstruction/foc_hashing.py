import hashlib
from pathlib import Path

from .foc_config import HASH_ALGORITHM, HASH_REASONABLE_BINARY_MAX_BYTES, HASH_SMALL_FILE_MAX_BYTES

TEXTUAL_SUFFIXES = {
    ".json",
    ".jsonl",
    ".log",
    ".txt",
    ".md",
    ".yaml",
    ".yml",
    ".csv",
}

HEAVY_BINARY_SUFFIXES = {
    ".pcap",
    ".raw",
    ".img",
    ".dd",
    ".qcow2",
    ".vmdk",
    ".lime",
    ".dump",
}


def hash_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.new(HASH_ALGORITHM)
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def should_hash(path: Path, size: int | None) -> tuple[bool, str]:
    suffix = path.suffix.lower()
    if size is None:
        return (False, "size_not_available")
    if suffix in TEXTUAL_SUFFIXES and size <= HASH_SMALL_FILE_MAX_BYTES:
        return (True, "textual_small")
    if suffix in HEAVY_BINARY_SUFFIXES and size <= HASH_REASONABLE_BINARY_MAX_BYTES:
        return (True, "binary_reasonable")
    if suffix not in HEAVY_BINARY_SUFFIXES and size <= HASH_SMALL_FILE_MAX_BYTES:
        return (True, "generic_small")
    return (False, "too_large_or_heavy")


def safe_sha256(path: Path, size: int | None = None) -> tuple[str | None, str]:
    try:
        do_hash, reason = should_hash(path, size)
        if not do_hash:
            return (None, reason)
        return (hash_file(path), reason)
    except Exception as exc:
        return (None, f"hash_error:{exc}")
