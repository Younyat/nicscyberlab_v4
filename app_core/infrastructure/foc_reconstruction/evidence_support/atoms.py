from __future__ import annotations

import json
from pathlib import Path

SUPPORT_DIRECTIONS = {"supports", "partially_supports", "contradicts", "neutral", "not_evaluable"}
SUPPORT_STRENGTHS = {"strong", "moderate", "weak", "indirect", "unavailable"}
TIMESTAMP_STATUSES = {"precise", "approximate", "unavailable", "not_resolvable"}


def new_atom(
    *,
    atom_id: str,
    case_id: str,
    evidence_layer: str,
    source_artifact: str,
    extraction_method: str,
    relation_to_hypothesis: str,
    support_direction: str,
    support_strength: str,
    event_type: str,
    observed_entity: str = "not_available",
    observed_value: str = "not_available",
    source_artifact_hash: str | None = None,
    node: str = "not_available",
    node_role: str = "not_available",
    ip_address: str | None = None,
    timestamp: str | None = None,
    timestamp_status: str = "unavailable",
    limitation: str | None = None,
    raw_reference: list[str] | None = None,
) -> dict:
    if support_direction not in SUPPORT_DIRECTIONS:
        support_direction = "not_evaluable"
    if support_strength not in SUPPORT_STRENGTHS:
        support_strength = "unavailable"
    if timestamp_status not in TIMESTAMP_STATUSES:
        timestamp_status = "unavailable"
    return {
        "atom_id": atom_id,
        "case_id": case_id,
        "evidence_layer": evidence_layer,
        "source_artifact": source_artifact,
        "source_artifact_hash": source_artifact_hash,
        "node": node,
        "node_role": node_role,
        "ip_address": ip_address,
        "timestamp": timestamp,
        "timestamp_status": timestamp_status,
        "event_type": event_type,
        "observed_entity": observed_entity,
        "observed_value": observed_value,
        "extraction_method": extraction_method,
        "relation_to_hypothesis": relation_to_hypothesis,
        "support_direction": support_direction,
        "support_strength": support_strength,
        "limitation": limitation,
        "raw_reference": raw_reference or [],
    }


def write_atoms_jsonl(path: Path, atoms: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        for atom in atoms:
            fh.write(json.dumps(atom, ensure_ascii=False, sort_keys=False))
            fh.write("\n")
    tmp.replace(path)


def read_atoms_jsonl(path: Path, limit: int | None = None) -> list[dict]:
    if not path.is_file():
        return []
    atoms: list[dict] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                atoms.append(json.loads(line))
            except Exception:
                continue
            if limit is not None and len(atoms) >= limit:
                break
    return atoms
