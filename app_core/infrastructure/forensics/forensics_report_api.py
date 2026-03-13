import os
import re
import json
import hashlib
from datetime import datetime
from flask import Blueprint, request, jsonify
import openstack

forensics_report_bp = Blueprint("forensics_report", __name__)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
EVIDENCE_ROOT = os.path.join(REPO_ROOT, "app_core", "infrastructure", "forensics", "evidence_store")
ACTIVE_CASE_PTR = os.path.join(EVIDENCE_ROOT, "_active_case.txt")


def get_openstack_connection():
    return openstack.connection.Connection(
        auth_url=os.environ.get("OS_AUTH_URL"),
        project_name=os.environ.get("OS_PROJECT_NAME"),
        username=os.environ.get("OS_USERNAME"),
        password=os.environ.get("OS_PASSWORD"),
        region_name=os.environ.get("OS_REGION_NAME"),
        user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
        project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
        compute_api_version="2",
        identity_interface="public",
    )


def _is_safe_case_dir(case_dir: str) -> bool:
    if not case_dir:
        return False
    case_dir = os.path.normpath(os.path.abspath(case_dir))
    return case_dir.startswith(os.path.normpath(EVIDENCE_ROOT) + os.sep)


def _read_active_case_dir() -> str:
    try:
        if not os.path.isfile(ACTIVE_CASE_PTR):
            return ""
        with open(ACTIVE_CASE_PTR, "r", encoding="utf-8") as f:
            p = (f.readline() or "").strip()
        if not p:
            return ""
        p = os.path.abspath(p)
        return p if os.path.isdir(p) else ""
    except Exception:
        return ""


def _safe_json_load(path: str, default):
    try:
        if not os.path.isfile(path):
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _safe_jsonl_load(path: str):
    out = []
    try:
        if not os.path.isfile(path):
            return out
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = (line or "").strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        return out
    return out


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _manifest_path(case_dir: str) -> str:
    return os.path.join(case_dir, "manifest.json")


def _custody_path(case_dir: str) -> str:
    return os.path.join(case_dir, "chain_of_custody.log")


def _events_path(case_dir: str) -> str:
    return os.path.join(case_dir, "metadata", "pipeline_events.jsonl")


def _case_digest_path(case_dir: str) -> str:
    return os.path.join(case_dir, "metadata", "case_digest.json")


def _time_sync_path(case_dir: str) -> str:
    return os.path.join(case_dir, "metadata", "time_sync.json")


def _infer_case_id(case_dir: str) -> str:
    return os.path.basename(case_dir.rstrip("/\\")) if case_dir else ""


def _classify_artifact_family(a_type: str, rel_path: str) -> str:
    t = (a_type or "").lower()
    p = (rel_path or "").lower()

    if "memory" in t or p.startswith("memory/"):
        return "memory"
    if "disk" in t or p.startswith("disk/"):
        return "disk"
    if "pcap" in t or "network" in t or p.startswith("network/"):
        return "network"
    if "industrial" in t or "ot_export" in t or p.startswith("industrial/"):
        return "industrial"
    if (
        "manifest" in t
        or "custody" in t
        or "digest" in t
        or "time_sync" in t
        or "ir_" in t
        or "fsr_" in t
        or p.startswith("metadata/")
        or p == "chain_of_custody.log"
        or p == "manifest.json"
    ):
        return "metadata"
    return "other"


def _infer_target(rel_path: str) -> str:
    p = (rel_path or "").lower()

    if "plc" in p:
        return "PLC"
    if "scada" in p or "fuxa" in p:
        return "SCADA"
    if "victim" in p:
        return "Victim"
    if "per_vm/" in p:
        parts = rel_path.split("/")
        try:
            idx = parts.index("per_vm")
            if idx + 1 < len(parts):
                return parts[idx + 1]
        except ValueError:
            pass

    return "Case"


def _infer_acquisition_method(a_type: str, rel_path: str) -> str:
    t = (a_type or "").lower()
    p = (rel_path or "").lower()

    if "memory" in t or p.startswith("memory/"):
        return "LiME over SSH"
    if "disk" in t or p.startswith("disk/"):
        return "libvirt raw export"
    if "pcap" in t:
        return "packet capture"
    if "industrial_ot_export" in t:
        return "derived OT export from preserved traffic"
    if "ir_snapshot" in t:
        return "case input snapshot"
    if "time_sync" in t:
        return "time synchronization export"
    if "fsr_eval" in t:
        return "reproducibility evaluation export"
    if "case_digest" in t:
        return "case digest generation"
    if "custody" in t:
        return "custody registration"
    return "preservation workflow"


def _infer_forensic_value(a_type: str, rel_path: str) -> str:
    family = _classify_artifact_family(a_type, rel_path)

    if family == "memory":
        return "Volatile state, processes, sockets, modules, in-memory code, and transient artifacts."
    if family == "disk":
        return "Persistent filesystem state, dropped binaries, execution traces, logs, and deleted content."
    if family == "network":
        return "Network communications preserved during the incident window for flow and protocol reconstruction."
    if family == "industrial":
        return "Industrial protocol context and extracted OT interactions derived from preserved evidence."
    if family == "metadata":
        return "Integrity, provenance, reproducibility inputs, preservation context, and operational traceability."
    return "Preserved case material useful for analytical correlation."


def _read_manifest(case_dir: str) -> dict:
    return _safe_json_load(_manifest_path(case_dir), {"case_dir": case_dir, "created_at": None, "artifacts": []})


def _read_case_digest(case_dir: str) -> dict:
    return _safe_json_load(_case_digest_path(case_dir), {})


def _read_time_sync(case_dir: str) -> dict:
    return _safe_json_load(_time_sync_path(case_dir), {})


def _read_custody(case_dir: str) -> list:
    return _safe_jsonl_load(_custody_path(case_dir))


def _read_pipeline(case_dir: str) -> list:
    return _safe_jsonl_load(_events_path(case_dir))


def _collect_cases():
    out = []
    active_case = _read_active_case_dir()

    if not os.path.isdir(EVIDENCE_ROOT):
        return [], active_case

    for name in sorted(os.listdir(EVIDENCE_ROOT), reverse=True):
        if name.startswith("_"):
            continue
        case_dir = os.path.join(EVIDENCE_ROOT, name)
        if not os.path.isdir(case_dir):
            continue
        if not os.path.isfile(os.path.join(case_dir, "manifest.json")):
            continue

        out.append({
            "case_name": name,
            "case_dir": case_dir,
            "is_active": os.path.abspath(case_dir) == os.path.abspath(active_case) if active_case else False
        })

    return out, active_case


def _sort_by_ts_desc(items: list) -> list:
    def key_fn(x):
        return (
            x.get("ts_epoch")
            or x.get("ts")
            or x.get("ts_utc")
            or ""
        )
    return sorted(items, key=key_fn, reverse=True)


def _extract_acquisition_window(events: list):
    if not events:
        return "", ""

    ordered = sorted(events, key=lambda x: x.get("ts_epoch") or x.get("ts_utc") or "")
    start = ordered[0].get("ts_utc", "")
    end = ordered[-1].get("ts_utc", "")
    return start, end


def _load_openstack_instances():
    conn = None
    try:
        conn = get_openstack_connection()
        out = []

        for server in conn.compute.servers(details=True):
            ip_private = None
            ip_floating = None

            addresses = server.addresses or {}
            for _, addrs in addresses.items():
                for a in addrs:
                    addr = a.get("addr")
                    ip_type = a.get("OS-EXT-IPS:type")
                    if ip_type == "floating":
                        ip_floating = addr
                    else:
                        ip_private = addr

            out.append({
                "id": server.id,
                "name": server.name,
                "status": server.status,
                "ip_private": ip_private,
                "ip_floating": ip_floating,
            })

        return out

    except Exception:
        return []

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _infer_role_from_instance_name(name: str) -> str:
    n = (name or "").lower()

    if "plc" in n:
        return "PLC"
    if "scada" in n or "fuxa" in n:
        return "SCADA"
    if "victim" in n:
        return "Victim"
    if "hmi" in n:
        return "SCADA"

    return name or "Unknown"


def _extract_uuid_from_disk_name(filename: str) -> str:
    m = re.match(r"^([0-9a-fA-F-]{36})_", filename or "")
    return m.group(1) if m else ""


def _extract_ip_from_memory_name(filename: str) -> str:
    m = re.match(r"^memdump_(\d+\.\d+\.\d+\.\d+)_", filename or "")
    return m.group(1) if m else ""


def _build_targets_from_case_dir(case_dir: str):
    """
    Construye targets visuales a partir de evidencia real preservada
    en disk/ y memory/, resolviendo UUID e IP contra OpenStack.
    """
    instances = _load_openstack_instances()

    by_id = {}
    by_ip = {}

    for inst in instances:
        inst_id = inst.get("id")
        if inst_id:
            by_id[inst_id] = inst

        ip_private = inst.get("ip_private")
        ip_floating = inst.get("ip_floating")

        if ip_private:
            by_ip[ip_private] = inst
        if ip_floating:
            by_ip[ip_floating] = inst

    found = {}

    disk_dir = os.path.join(case_dir, "disk")
    memory_dir = os.path.join(case_dir, "memory")

    if os.path.isdir(disk_dir):
        for fn in os.listdir(disk_dir):
            vm_id = _extract_uuid_from_disk_name(fn)
            if not vm_id:
                continue

            inst = by_id.get(vm_id)
            if not inst:
                continue

            role = _infer_role_from_instance_name(inst.get("name"))
            key = role.lower()

            if key not in found:
                found[key] = {
                    "role": role.upper(),
                    "name": role,
                    "ip": inst.get("ip_private") or "--",
                    "state": "preserved"
                }

    if os.path.isdir(memory_dir):
        for fn in os.listdir(memory_dir):
            ip = _extract_ip_from_memory_name(fn)
            if not ip:
                continue

            inst = by_ip.get(ip)
            if not inst:
                continue

            role = _infer_role_from_instance_name(inst.get("name"))
            key = role.lower()

            if key not in found:
                found[key] = {
                    "role": role.upper(),
                    "name": role,
                    "ip": inst.get("ip_private") or ip,
                    "state": "preserved"
                }

    return list(found.values())


def _enrich_artifacts(case_dir: str, manifest: dict) -> list:
    raw_artifacts = manifest.get("artifacts", []) or []
    out = []

    for idx, a in enumerate(raw_artifacts, start=1):
        rel_path = a.get("rel_path") or a.get("path") or ""
        abs_path = os.path.join(case_dir, rel_path) if rel_path else ""
        family = _classify_artifact_family(a.get("type", ""), rel_path)

        out.append({
            "id": f"artifact-{idx}",
            "name": os.path.basename(rel_path) if rel_path else f"artifact-{idx}",
            "type": a.get("type", "unknown"),
            "family": family,
            "target": _infer_target(rel_path),
            "rel_path": rel_path,
            "absolute_path": abs_path,
            "sha256": a.get("sha256"),
            "size": a.get("size"),
            "ts": a.get("ts"),
            "collected_by": "preservation workflow",
            "acquisition_method": _infer_acquisition_method(a.get("type", ""), rel_path),
            "forensic_value": _infer_forensic_value(a.get("type", ""), rel_path),
        })

    return out


def _build_summary(case_dir: str):
    manifest = _read_manifest(case_dir)
    custody = _read_custody(case_dir)
    pipeline = _read_pipeline(case_dir)
    case_digest = _read_case_digest(case_dir)

    artifacts = _enrich_artifacts(case_dir, manifest)
    acquisition_start, acquisition_end = _extract_acquisition_window(pipeline)

    total_size = 0
    hashed_count = 0
    missing_hash_count = 0
    primary_count = 0
    derived_count = 0
    type_distribution = {}

    for a in artifacts:
        size = a.get("size")
        if isinstance(size, int):
            total_size += size

        if a.get("sha256"):
            hashed_count += 1
        else:
            missing_hash_count += 1

        fam = a.get("family", "other")
        type_distribution[fam] = type_distribution.get(fam, 0) + 1

        if fam in ("memory", "disk", "network", "industrial"):
            primary_count += 1
        else:
            derived_count += 1

    manifest_hash = None
    try:
        manifest_hash = _sha256_file(_manifest_path(case_dir))
    except Exception:
        manifest_hash = None

    return {
        "case_id": _infer_case_id(case_dir),
        "case_status": "active" if os.path.abspath(case_dir) == os.path.abspath(_read_active_case_dir() or "") else "stored",
        "case_dir": case_dir,
        "manifest_status": "loaded",
        "targets": _build_targets_from_case_dir(case_dir),
        "summary": {
            "artifact_count": len(artifacts),
            "total_size_bytes": total_size,
            "hashed_count": hashed_count,
            "missing_hash_count": missing_hash_count,
            "custody_entries": len(custody),
            "primary_count": primary_count,
            "derived_count": derived_count,
            "type_distribution": type_distribution
        },
        "manifest_overview": {
            "scenario_name": manifest.get("scenario_name") or manifest.get("description") or "--",
            "created_at": manifest.get("created_at") or "",
            "acquisition_start": acquisition_start,
            "acquisition_end": acquisition_end,
            "manifest_hash": manifest_hash,
            "case_digest_hash": (case_digest.get("digests") or {}).get("manifest_json_sha256"),
            "time_sync_max_offset_ms": _read_time_sync(case_dir).get("max_offset_ms")
        }
    }


@forensics_report_bp.route("/api/forensics/report/cases", methods=["GET"])
def api_forensics_report_cases():
    try:
        cases, active_case = _collect_cases()
        return jsonify({
            "active_case_dir": active_case,
            "cases": cases
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@forensics_report_bp.route("/api/forensics/report/summary", methods=["GET"])
def api_forensics_report_summary():
    case_dir = (request.args.get("case_dir") or "").strip()
    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "invalid case_dir"}), 400

    try:
        return jsonify(_build_summary(case_dir)), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@forensics_report_bp.route("/api/forensics/report/manifest", methods=["GET"])
def api_forensics_report_manifest():
    case_dir = (request.args.get("case_dir") or "").strip()
    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "invalid case_dir"}), 400

    try:
        manifest = _read_manifest(case_dir)
        artifacts = _enrich_artifacts(case_dir, manifest)
        return jsonify({
            "case_dir": case_dir,
            "artifacts": artifacts,
            "raw_manifest": manifest
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@forensics_report_bp.route("/api/forensics/report/chain-of-custody", methods=["GET"])
def api_forensics_report_chain_of_custody():
    case_dir = (request.args.get("case_dir") or "").strip()
    limit = int(request.args.get("limit") or 200)

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "invalid case_dir"}), 400

    try:
        entries = _sort_by_ts_desc(_read_custody(case_dir))
        if limit > 0:
            entries = entries[:limit]
        return jsonify({
            "case_dir": case_dir,
            "entries": entries
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@forensics_report_bp.route("/api/forensics/report/pipeline-events", methods=["GET"])
def api_forensics_report_pipeline_events():
    case_dir = (request.args.get("case_dir") or "").strip()
    limit = int(request.args.get("limit") or 300)

    if not _is_safe_case_dir(case_dir):
        return jsonify({"error": "invalid case_dir"}), 400

    try:
        events = _sort_by_ts_desc(_read_pipeline(case_dir))
        if limit > 0:
            events = events[:limit]
        return jsonify({
            "case_dir": case_dir,
            "events": events
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500