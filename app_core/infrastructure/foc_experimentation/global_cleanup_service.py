from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from .config import CAMPAIGNS_ROOT, EVIDENCE_STORE_ROOT, LEGACY_COMPARISON_REGISTRY_DIR, SCIENTIFIC_MEMORY_ROOT
from .job_runner import list_jobs
from ..foc_reconstruction.foc_paths import relative_path
from ..foc_reconstruction.foc_sources import utc_now

SCIENTIFIC_REPORTS_ROOT = EVIDENCE_STORE_ROOT.parent / "scientific_reports" / "level_a_repetitions"
PAPER_EVIDENCE_ROOT = EVIDENCE_STORE_ROOT.parent / "paper_evidence"
VALIDATION_REPORTS_ROOT = EVIDENCE_STORE_ROOT / "validation_reports"
GLOBAL_CLEANUP_ROOT = EVIDENCE_STORE_ROOT / "_cleanup_audit"
ACTIVE_CASE_PTR = EVIDENCE_STORE_ROOT / "_active_case.txt"


def _write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _human_bytes(size: int | None) -> str:
    if size is None:
        return "not_available"
    value = float(size)
    units = ["B", "KB", "MB", "GB", "TB"]
    unit = 0
    while value >= 1024.0 and unit < len(units) - 1:
        value /= 1024.0
        unit += 1
    return f"{value:.2f} {units[unit]}"


def _dir_size_bytes(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except Exception:
                continue
    return total


def _path_size(path: Path) -> int:
    if not path.exists():
        return 0
    if path.is_file():
        try:
            return path.stat().st_size
        except Exception:
            return 0
    return _dir_size_bytes(path)


def _active_case_path() -> Path | None:
    try:
        raw = ACTIVE_CASE_PTR.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if not raw:
        return None
    candidate = Path(raw).expanduser().resolve()
    return candidate if candidate.exists() else None


def _running_campaign_ids() -> set[str]:
    ids: set[str] = set()
    for item in list_jobs():
        status = str(item.get("status") or "").lower()
        if status not in {"queued", "running", "cancel_requested"}:
            continue
        meta = item.get("meta") or {}
        campaign_id = str(meta.get("campaign_id") or "").strip()
        if campaign_id:
            ids.add(campaign_id)
    return ids


def _item(*, item_id: str, item_type: str, label: str, path: Path, parent_id: str | None = None, deletable: bool = True, reason: str | None = None, extra: dict | None = None) -> dict:
    size_bytes = _path_size(path)
    return {
        "item_id": item_id,
        "item_type": item_type,
        "label": label,
        "path": relative_path(path),
        "absolute_path": str(path.resolve()),
        "parent_id": parent_id,
        "size_bytes": size_bytes,
        "size_human": _human_bytes(size_bytes),
        "deletable": deletable,
        "blocked_reason": reason,
        **(extra or {}),
    }


def _campaign_items() -> list[dict]:
    items: list[dict] = []
    running = _running_campaign_ids()
    for campaign_path in sorted(CAMPAIGNS_ROOT.glob("CMP-*")):
        campaign_id = campaign_path.name
        level = "unknown"
        try:
            config = json.loads((campaign_path / "campaign_config.json").read_text(encoding="utf-8"))
            level = str(config.get("level") or "unknown").upper()
        except Exception:
            level = "unknown"
        blocked = campaign_id in running
        reason = "A background job is still running for this campaign." if blocked else None
        items.append(_item(item_id=f"campaign:{campaign_id}", item_type="campaign", label=campaign_id, path=campaign_path, deletable=not blocked, reason=reason, extra={"evaluation_level": level}))
        for execution_dir in sorted(campaign_path.glob("level_*/EXEC-*")):
            items.append(
                _item(
                    item_id=f"execution:{campaign_id}:{execution_dir.name}",
                    item_type="execution",
                    label=f"{campaign_id} / {execution_dir.parent.name} / {execution_dir.name}",
                    path=execution_dir,
                    parent_id=f"campaign:{campaign_id}",
                    deletable=not blocked,
                    reason=reason,
                    extra={"campaign_id": campaign_id, "execution_id": execution_dir.name, "evaluation_level": level},
                )
            )
    return items


def _case_items() -> list[dict]:
    items: list[dict] = []
    active_case = _active_case_path()
    for case_dir in sorted(EVIDENCE_STORE_ROOT.glob("CASE-*")):
        is_active = active_case is not None and case_dir.resolve() == active_case
        items.append(
            _item(
                item_id=f"case:{case_dir.name}",
                item_type="case",
                label=case_dir.name,
                path=case_dir,
                deletable=True,
                reason="This case is currently marked as active. Cleanup will also clear the active-case pointer before deletion." if is_active else None,
                extra={"is_active_case": is_active},
            )
        )
    return items


def _scientific_report_items() -> list[dict]:
    items: list[dict] = []
    if not SCIENTIFIC_REPORTS_ROOT.exists():
        return items
    seen_dirs: set[str] = set()
    for metadata_path in sorted(SCIENTIFIC_REPORTS_ROOT.glob("**/report_metadata.json")):
        report_dir = metadata_path.parent
        seen_dirs.add(str(report_dir.resolve()))
        meta = {}
        try:
            meta = json.loads(metadata_path.read_text(encoding="utf-8"))
        except Exception:
            meta = {}
        label = f"{meta.get('campaign_id') or 'unknown_campaign'} / {meta.get('case_id') or 'unknown_case'} / {report_dir.name}"
        items.append(
            _item(
                item_id=f"scientific_report:{report_dir.as_posix()}",
                item_type="scientific_report_bundle",
                label=label,
                path=report_dir,
                extra={"campaign_id": meta.get("campaign_id"), "case_id": meta.get("case_id"), "execution_id": meta.get("execution_id")},
            )
        )
    for report_md in sorted(SCIENTIFIC_REPORTS_ROOT.glob("**/SCIENTIFIC_LEVEL_A_REPORT.md")):
        report_dir = report_md.parent
        if str(report_dir.resolve()) in seen_dirs:
            continue
        items.append(
            _item(
                item_id=f"scientific_report:{report_dir.as_posix()}",
                item_type="scientific_report_bundle",
                label=f"Level A report bundle / {report_dir.name}",
                path=report_dir,
            )
        )
    for case_root in sorted(SCIENTIFIC_REPORTS_ROOT.glob("case-*")):
        resolved = str(case_root.resolve())
        if resolved in seen_dirs:
            continue
        if any(item.get("absolute_path") == resolved for item in items):
            continue
        items.append(
            _item(
                item_id=f"scientific_report_case_root:{case_root.name}",
                item_type="scientific_report_case_root",
                label=f"Scientific reports root / {case_root.name}",
                path=case_root,
            )
        )
    return items


def _validation_report_items() -> list[dict]:
    items: list[dict] = []
    if not VALIDATION_REPORTS_ROOT.exists():
        return items
    for report_dir in sorted(VALIDATION_REPORTS_ROOT.glob("level_b_repetition_report_*")):
        items.append(
            _item(
                item_id=f"validation_report:{report_dir.name}",
                item_type="validation_report_bundle",
                label=report_dir.name,
                path=report_dir,
                extra={"evaluation_level": "B"},
            )
        )
    return items


def _paper_evidence_items() -> list[dict]:
    items: list[dict] = []
    if not PAPER_EVIDENCE_ROOT.exists():
        return items
    seen_paths: set[str] = set()
    for manifest_path in sorted(PAPER_EVIDENCE_ROOT.glob("paper-*/paper_evidence_manifest.json")):
        payload = {}
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            payload = {}
        report_dir = manifest_path.parent
        requested_level = str(payload.get("requested_level") or "unknown").upper()
        label = f"{requested_level} / {payload.get('report_id') or report_dir.name}"
        items.append(
            _item(
                item_id=f"paper_evidence:{report_dir.name}",
                item_type="paper_evidence_report_bundle",
                label=label,
                path=report_dir,
                extra={
                    "evaluation_level": requested_level,
                    "report_id": payload.get("report_id") or report_dir.name,
                    "source_case_id": payload.get("source_case_id"),
                    "source_campaign_id": payload.get("source_campaign_id"),
                },
            )
        )
        seen_paths.add(str(report_dir.resolve()))
    for report_dir in sorted(PAPER_EVIDENCE_ROOT.glob("paper-*")):
        resolved = str(report_dir.resolve())
        if resolved in seen_paths:
            continue
        if report_dir.is_dir():
            level_hint = report_dir.name.split("-", 2)[1].upper() if "-" in report_dir.name else "unknown"
            items.append(
                _item(
                    item_id=f"paper_evidence_orphan:{report_dir.name}",
                    item_type="paper_evidence_orphan_bundle",
                    label=f"{level_hint} / orphan paper evidence bundle / {report_dir.name}",
                    path=report_dir,
                    extra={"evaluation_level": level_hint, "report_id": report_dir.name},
                )
            )
        elif report_dir.is_file() and report_dir.suffix.lower() == ".zip":
            level_hint = report_dir.name.split("-", 2)[1].upper() if "-" in report_dir.name else "unknown"
            items.append(
                _item(
                    item_id=f"paper_evidence_zip:{report_dir.name}",
                    item_type="paper_evidence_zip_export",
                    label=f"{level_hint} / ZIP export / {report_dir.name}",
                    path=report_dir,
                    extra={"evaluation_level": level_hint},
                )
            )
    for zip_path in sorted(PAPER_EVIDENCE_ROOT.glob("paper-*.zip")):
        if any(item.get("absolute_path") == str(zip_path.resolve()) for item in items):
            continue
        level_hint = zip_path.name.split("-", 2)[1].upper() if "-" in zip_path.name else "unknown"
        items.append(
            _item(
                item_id=f"paper_evidence_zip:{zip_path.name}",
                item_type="paper_evidence_zip_export",
                label=f"{level_hint} / ZIP export / {zip_path.name}",
                path=zip_path,
                extra={"evaluation_level": level_hint},
            )
        )
    if PAPER_EVIDENCE_ROOT.exists() and any(PAPER_EVIDENCE_ROOT.iterdir()):
        items.append(
            _item(
                item_id="paper_evidence:root",
                item_type="paper_evidence_root",
                label="Paper evidence root",
                path=PAPER_EVIDENCE_ROOT,
                extra={"evaluation_level": "mixed"},
            )
        )
    return items


def _special_items() -> list[dict]:
    items: list[dict] = []
    if SCIENTIFIC_MEMORY_ROOT.exists():
        blocked = bool(_running_campaign_ids())
        items.append(
            _item(
                item_id="scientific_memory:root",
                item_type="scientific_memory_root",
                label="Scientific memory registries",
                path=SCIENTIFIC_MEMORY_ROOT,
                deletable=not blocked,
                reason="Scientific memory cleanup is blocked while a campaign job is still running." if blocked else None,
            )
        )
    if LEGACY_COMPARISON_REGISTRY_DIR.exists():
        items.append(
            _item(
                item_id="legacy_comparison_registry:root",
                item_type="legacy_comparison_registry_root",
                label="Legacy comparison registry",
                path=LEGACY_COMPARISON_REGISTRY_DIR,
            )
        )
    if GLOBAL_CLEANUP_ROOT.exists():
        items.append(
            _item(
                item_id="global_cleanup_manifests:root",
                item_type="global_cleanup_manifests_root",
                label="Global cleanup manifests",
                path=GLOBAL_CLEANUP_ROOT,
            )
        )
    return items


def list_cleanup_inventory() -> dict:
    items = _special_items() + _campaign_items() + _case_items() + _scientific_report_items() + _validation_report_items() + _paper_evidence_items()
    removable = [item for item in items if item.get("deletable")]
    return {
        "generated_at": utc_now(),
        "items": items,
        "summary": {
            "total_items": len(items),
            "removable_items": len(removable),
            "estimated_reclaimable_bytes": sum(int(item.get("size_bytes") or 0) for item in removable),
            "estimated_reclaimable_human": _human_bytes(sum(int(item.get("size_bytes") or 0) for item in removable)),
        },
    }


def _collapse_descendants(paths: list[Path]) -> list[Path]:
    ordered = sorted({path.resolve() for path in paths}, key=lambda item: len(item.parts))
    kept: list[Path] = []
    for candidate in ordered:
        if any(str(candidate).startswith(str(parent) + os.sep) or candidate == parent for parent in kept):
            continue
        kept.append(candidate)
    return kept


def _scrub_deleted_path_references(deleted_path: Path) -> None:
    deleted_rel = relative_path(deleted_path)
    deleted_abs = str(deleted_path.resolve())
    for manifest_path in CAMPAIGNS_ROOT.glob("CMP-*/level_*/EXEC-*/execution_manifest.json"):
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        reports = list((payload.get("scientific_reports") or {}).get("reports") or [])
        filtered = []
        changed = False
        for item in reports:
            report_output = str(item.get("report_output_path") or "")
            report_markdown = str(item.get("report_markdown_path") or "")
            if any(report_output.startswith(prefix) or report_markdown.startswith(prefix) for prefix in {deleted_rel or "", deleted_abs} if prefix):
                changed = True
                continue
            filtered.append(item)
        if changed:
            payload.setdefault("scientific_reports", {})["reports"] = filtered
            payload["scientific_reports"]["latest_level_a"] = filtered[-1] if filtered else None
            _write_json(manifest_path, payload)
    for manifest_path in CAMPAIGNS_ROOT.glob("CMP-*/campaign_manifest.json"):
        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        reports = dict(payload.get("validation_reports") or {})
        latest = dict(reports.get("latest_level_b") or {})
        latest_dir = str(latest.get("report_dir") or latest.get("main_report_path") or "")
        if latest_dir and any(latest_dir.startswith(prefix) for prefix in {deleted_rel or "", deleted_abs} if prefix):
            payload["validation_reports"] = {}
            _write_json(manifest_path, payload)


def execute_cleanup(*, selected_item_ids: list[str], confirmation: str, operator: str = "foc_experimentation_ui") -> dict:
    if confirmation != "OK":
        return {"error": "confirmation_required", "message": "Type OK to confirm cleanup."}
    inventory = list_cleanup_inventory()
    items = {str(item.get("item_id")): item for item in inventory.get("items", [])}
    selected = [items[item_id] for item_id in selected_item_ids if item_id in items]
    if not selected:
        return {"error": "no_items_selected", "message": "Select at least one removable item."}
    blocked = [item for item in selected if not item.get("deletable")]
    if blocked:
        return {
            "error": "blocked_items_selected",
            "message": "One or more selected items cannot be deleted right now.",
            "blocked_items": blocked,
        }
    selected_paths = _collapse_descendants([Path(str(item["absolute_path"])).resolve() for item in selected])
    selected_by_path = {str(Path(str(item["absolute_path"])).resolve()): item for item in selected}
    deleted_items: list[dict] = []
    warnings: list[str] = []
    estimated = 0
    actual = 0
    for path in selected_paths:
        item = selected_by_path.get(str(path))
        if item is None:
            continue
        estimated += int(item.get("size_bytes") or 0)
        size_before = _path_size(path)
        if not path.exists():
            warnings.append(f"{item['label']}: path no longer exists.")
            continue
        try:
            _scrub_deleted_path_references(path)
            active_case = _active_case_path()
            if active_case is not None and path.resolve() == active_case.resolve():
                try:
                    ACTIVE_CASE_PTR.write_text("", encoding="utf-8")
                except Exception:
                    pass
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            actual += size_before
            deleted_items.append(
                {
                    "item_id": item["item_id"],
                    "item_type": item["item_type"],
                    "label": item["label"],
                    "path": item["path"],
                    "freed_bytes": size_before,
                }
            )
        except Exception as exc:
            warnings.append(f"{item['label']}: {exc}")
    manifest = {
        "generated_at": utc_now(),
        "operator": operator,
        "selected_item_ids": selected_item_ids,
        "deleted_items": deleted_items,
        "deleted_paths": [item["path"] for item in deleted_items],
        "freed_bytes_estimated": estimated,
        "freed_bytes_actual": actual,
        "preserved_metadata": ["active scenario configuration", "attack profiles", "acquisition profiles", "source code", "dashboard files"],
        "cleanup_status": "completed" if deleted_items and not warnings else ("partial" if deleted_items else "failed"),
        "warnings": warnings,
    }
    manifest_path = GLOBAL_CLEANUP_ROOT / f"cleanup_{utc_now().replace(':', '').replace('+', '_')}.json"
    _write_json(manifest_path, manifest)
    return {
        "status": "ok",
        "message": f"Cleanup removed {len(deleted_items)} item(s) and freed approximately {_human_bytes(actual)}.",
        "cleanup_manifest_path": relative_path(manifest_path),
        **manifest,
    }
