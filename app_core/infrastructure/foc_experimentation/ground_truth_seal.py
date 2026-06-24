from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _sha256_path(path: Path | None) -> str:
    if path is None or not path.is_file():
        return "not_available"
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_ts(raw) -> float | None:
    from datetime import datetime

    value = str(raw or "").strip()
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def build_ground_truth_seal(
    *,
    ground_truth_id: str,
    scenario_id: str,
    execution_id: str,
    ground_truth_path: Path | None,
    scenario_profile_path: Path | None,
    attack_profile_path: Path | None,
    attack_script_path: Path | None,
    created_at: str | None,
    scenario_profile_created_at: str | None,
    attack_profile_created_at: str | None,
    attack_start_time: str | None,
    custody_reference: str | None,
    generator: str,
) -> dict:
    ground_truth_sha256 = _sha256_path(ground_truth_path)
    scenario_profile_sha256 = _sha256_path(scenario_profile_path)
    attack_profile_sha256 = _sha256_path(attack_profile_path)
    attack_script_sha256 = _sha256_path(attack_script_path)

    created_ts = _parse_ts(created_at)
    scenario_profile_ts = _parse_ts(scenario_profile_created_at)
    attack_profile_ts = _parse_ts(attack_profile_created_at)
    attack_start_ts = _parse_ts(attack_start_time)

    reasons: list[str] = []
    if attack_start_ts is None:
        reasons.append("attack_start_time_not_available")
    if created_ts is None:
        reasons.append("ground_truth_created_at_not_available")
    if scenario_profile_ts is None:
        reasons.append("scenario_profile_created_at_not_available")
    if attack_profile_ts is None:
        reasons.append("attack_profile_created_at_not_available")
    if created_ts is not None and attack_start_ts is not None and created_ts >= attack_start_ts:
        reasons.append("ground_truth_not_created_before_attack")
    if scenario_profile_ts is not None and attack_start_ts is not None and scenario_profile_ts >= attack_start_ts:
        reasons.append("scenario_profile_not_created_before_attack")
    if attack_profile_ts is not None and attack_start_ts is not None and attack_profile_ts >= attack_start_ts:
        reasons.append("attack_profile_not_created_before_attack")

    seal_valid = not reasons and all(
        value not in {"", "not_available"} for value in [ground_truth_sha256, scenario_profile_sha256, attack_profile_sha256]
    )
    if not seal_valid and not reasons:
        reasons.append("one_or_more_required_hashes_not_available")

    return {
        "ground_truth_id": ground_truth_id or "not_available",
        "scenario_id": scenario_id or "not_available",
        "execution_id": execution_id,
        "ground_truth_sha256": ground_truth_sha256,
        "scenario_profile_sha256": scenario_profile_sha256,
        "attack_profile_sha256": attack_profile_sha256,
        "attack_script_sha256": attack_script_sha256,
        "created_at": created_at or "not_available",
        "sealed_before_attack": bool(seal_valid),
        "attack_start_time": attack_start_time or "not_available",
        "seal_valid": bool(seal_valid),
        "seal_validation_reason": "seal_valid" if seal_valid else "; ".join(reasons),
        "custody_reference": custody_reference or "not_available",
        "generator": generator,
        "hash_algorithm": "sha256",
        "scenario_profile_created_at": scenario_profile_created_at or "not_available",
        "attack_profile_created_at": attack_profile_created_at or "not_available",
    }
