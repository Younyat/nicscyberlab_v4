#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import uuid
import shutil
import hashlib
import subprocess
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional, Any, Tuple

# =========================
# CONFIG (robusto)
# =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

BASE_EVIDENCE_DIR = os.environ.get(
    "NICS_EVIDENCE_DIR",
    os.path.join(SCRIPT_DIR, "evidence_store"),
)

HOST = os.environ.get("NICS_FORENSIC_HOST", "127.0.0.1")
PORT = int(os.environ.get("NICS_FORENSIC_PORT", "5059"))

# Prefer tools that exist in real ops
TCPDUMP_BIN = shutil.which("tcpdump")
JOURNALCTL_BIN = shutil.which("journalctl")
MBPOLL_BIN = shutil.which("mbpoll")  # common modbus polling tool (if installed)
SHA256SUM_BIN = shutil.which("sha256sum")  # optional; we hash in python anyway


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_cmd(cmd: List[str], timeout: int = 60) -> Tuple[int, str, str]:
    """
    Run command safely, capture stdout/stderr, return (rc, out, err).
    Never throws: always returns a tuple.
    """
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 999, "", f"EXCEPTION: {e}"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_dir(p: str) -> None:
    os.makedirs(p, exist_ok=True)


@dataclass
class EvidenceItem:
    eid: str
    category: str              # network | system | industrial | metadata
    source: str                # node/host identifier (string)
    path: str                  # relative to case root
    created_utc: str
    sha256: Optional[str] = None
    size_bytes: Optional[int] = None
    tool: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class CaseManifest:
    case_id: str
    experiment_id: str
    scenario_id: str
    trigger_type: str          # manual | alert
    trigger_ref: str           # alert id / text
    created_utc: str
    items: List[EvidenceItem]


class EvidenceStore:
    """
    Professional minimum:
    - structured directories
    - manifest.json
    - chain_of_custody.log (append-only)
    - deterministic hashing
    """
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        ensure_dir(self.base_dir)

    def create_case(self, experiment_id: str, scenario_id: str, trigger_type: str, trigger_ref: str) -> str:
        case_id = f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"
        case_dir = self.case_dir(case_id)
        ensure_dir(case_dir)
        ensure_dir(os.path.join(case_dir, "network"))
        ensure_dir(os.path.join(case_dir, "system"))
        ensure_dir(os.path.join(case_dir, "industrial"))
        ensure_dir(os.path.join(case_dir, "metadata"))

        manifest = CaseManifest(
            case_id=case_id,
            experiment_id=experiment_id,
            scenario_id=scenario_id,
            trigger_type=trigger_type,
            trigger_ref=trigger_ref,
            created_utc=utc_now_iso(),
            items=[]
        )
        self._write_manifest(case_id, manifest)
        self._coc_append(case_id, f"CASE_CREATED trigger_type={trigger_type} trigger_ref={trigger_ref}")
        return case_id

    def case_dir(self, case_id: str) -> str:
        return os.path.join(self.base_dir, case_id)

    def manifest_path(self, case_id: str) -> str:
        return os.path.join(self.case_dir(case_id), "manifest.json")

    def coc_path(self, case_id: str) -> str:
        return os.path.join(self.case_dir(case_id), "chain_of_custody.log")

    def _write_manifest(self, case_id: str, manifest: CaseManifest) -> None:
        p = self.manifest_path(case_id)
        data = asdict(manifest)
        data["items"] = [asdict(x) for x in manifest.items]
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_manifest(self, case_id: str) -> CaseManifest:
        with open(self.manifest_path(case_id), "r", encoding="utf-8") as f:
            d = json.load(f)
        items = [EvidenceItem(**x) for x in d.get("items", [])]
        return CaseManifest(
            case_id=d["case_id"],
            experiment_id=d["experiment_id"],
            scenario_id=d["scenario_id"],
            trigger_type=d["trigger_type"],
            trigger_ref=d["trigger_ref"],
            created_utc=d["created_utc"],
            items=items
        )

    def add_item(self, case_id: str, item: EvidenceItem) -> None:
        manifest = self.load_manifest(case_id)
        manifest.items.append(item)
        self._write_manifest(case_id, manifest)
        self._coc_append(
            case_id,
            f"EVIDENCE_REGISTERED eid={item.eid} category={item.category} path={item.path} tool={item.tool}"
        )

    def finalize_item_hash(self, case_id: str, rel_path: str) -> Tuple[str, int]:
        abs_path = os.path.join(self.case_dir(case_id), rel_path)
        digest = sha256_file(abs_path)
        size = os.path.getsize(abs_path)

        manifest = self.load_manifest(case_id)
        for it in manifest.items:
            if it.path == rel_path:
                it.sha256 = digest
                it.size_bytes = size
                break
        self._write_manifest(case_id, manifest)
        self._coc_append(case_id, f"EVIDENCE_HASHED path={rel_path} sha256={digest} size={size}")
        return digest, size

    def _coc_append(self, case_id: str, line: str) -> None:
        p = self.coc_path(case_id)
        entry = f"{utc_now_iso()} {line}\n"
        with open(p, "a", encoding="utf-8") as f:
            f.write(entry)


# =========================
# COLLECTORS
# =========================
class NetworkCollector:
    def __init__(self, iface: str = "any"):
        self.iface = iface

    def collect_pcap(
        self,
        store: EvidenceStore,
        case_id: str,
        source: str,
        seconds: int = 20,
        bpf: Optional[str] = None
    ) -> Dict[str, Any]:
        rel = f"network/pcap_{source}_{int(time.time())}.pcap"
        out_path = os.path.join(store.case_dir(case_id), rel)

        if not TCPDUMP_BIN:
            note = "tcpdump not found; pcap collection skipped"
            meta_rel = "metadata/network_collector.txt"
            meta_path = os.path.join(store.case_dir(case_id), meta_rel)
            ensure_dir(os.path.dirname(meta_path))
            with open(meta_path, "a", encoding="utf-8") as f:
                f.write(f"{utc_now_iso()} {note}\n")

            item = EvidenceItem(
                eid=uuid.uuid4().hex,
                category="metadata",
                source=source,
                path=meta_rel,
                created_utc=utc_now_iso(),
                tool="tcpdump",
                notes=note
            )
            store.add_item(case_id, item)
            store.finalize_item_hash(case_id, meta_rel)
            return {"ok": False, "reason": note}

        # Robust capture: ensure tcpdump closes and writes the file
        cmd = [
            TCPDUMP_BIN,
            "-i", self.iface,
            "-G", str(seconds),
            "-W", "1",
            "-w", out_path
        ]
        if bpf:
            cmd.append(bpf)

        rc, out, err = run_cmd(cmd, timeout=seconds + 5)

        # Critical validation before hashing
        if not os.path.exists(out_path):
            note = "tcpdump finished but pcap file not created"
            store._coc_append(case_id, f"PCAP_FAILED path={rel} rc={rc}")
            return {"ok": False, "reason": note, "rc": rc, "stderr": err[-300:]}

        item = EvidenceItem(
            eid=uuid.uuid4().hex,
            category="network",
            source=source,
            path=rel,
            created_utc=utc_now_iso(),
            tool="tcpdump",
            notes=f"iface={self.iface} seconds={seconds} rc={rc}"
        )
        store.add_item(case_id, item)
        store.finalize_item_hash(case_id, rel)
        return {"ok": True, "path": rel, "rc": rc, "stderr": err[-300:]}


class SystemCollector:
    def collect_system_snapshot(self, store: EvidenceStore, case_id: str, source: str) -> Dict[str, Any]:
        rel = f"system/snapshot_{source}_{int(time.time())}.json"
        abs_path = os.path.join(store.case_dir(case_id), rel)

        snapshot: Dict[str, Any] = {
            "created_utc": utc_now_iso(),
            "source": source,
            "commands": {}
        }

        def add_cmd(name: str, cmd: List[str], timeout: int = 30) -> None:
            rc, out, err = run_cmd(cmd, timeout=timeout)
            snapshot["commands"][name] = {
                "cmd": cmd,
                "rc": rc,
                "stdout": out[-20000:],
                "stderr": err[-20000:]
            }

        add_cmd("uname", ["uname", "-a"])
        add_cmd("whoami", ["whoami"])
        add_cmd("uptime", ["uptime"])
        add_cmd("ps", ["ps", "aux"], timeout=60)
        add_cmd("ss", ["ss", "-plant"], timeout=60)
        add_cmd("ip_addr", ["ip", "a"])
        add_cmd("ip_route", ["ip", "r"])
        add_cmd("iptables", ["iptables", "-S"], timeout=60)

        if JOURNALCTL_BIN:
            add_cmd("journalctl_recent", [JOURNALCTL_BIN, "--no-pager", "-n", "300"], timeout=60)
        else:
            snapshot["commands"]["journalctl_recent"] = {
                "cmd": ["journalctl"],
                "rc": 127,
                "stdout": "",
                "stderr": "journalctl not found"
            }

        ensure_dir(os.path.dirname(abs_path))
        with open(abs_path, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=2)

        item = EvidenceItem(
            eid=uuid.uuid4().hex,
            category="system",
            source=source,
            path=rel,
            created_utc=utc_now_iso(),
            tool="journalctl/ps/ss/ip/iptables",
            notes="system snapshot bundle"
        )
        store.add_item(case_id, item)
        store.finalize_item_hash(case_id, rel)
        return {"ok": True, "path": rel}


class OTCollector:
    """
    Minimal OT snapshot:
    - If mbpoll exists: poll a few Modbus registers
    - Otherwise: record that OT snapshot is unavailable
    """
    def collect_modbus_snapshot(
        self,
        store: EvidenceStore,
        case_id: str,
        source: str,
        host: str,
        port: int = 502,
        unit: int = 1,
        start: int = 0,
        count: int = 10
    ) -> Dict[str, Any]:
        rel = f"industrial/modbus_{source}_{int(time.time())}.txt"
        abs_path = os.path.join(store.case_dir(case_id), rel)
        ensure_dir(os.path.dirname(abs_path))

        if not MBPOLL_BIN:
            note = "mbpoll not found; Modbus snapshot skipped"
            with open(abs_path, "w", encoding="utf-8") as f:
                f.write(f"{utc_now_iso()} {note}\n")
                f.write(f"target={host}:{port} unit={unit} start={start} count={count}\n")
            item = EvidenceItem(
                eid=uuid.uuid4().hex,
                category="industrial",
                source=source,
                path=rel,
                created_utc=utc_now_iso(),
                tool="mbpoll",
                notes=note
            )
            store.add_item(case_id, item)
            store.finalize_item_hash(case_id, rel)
            return {"ok": False, "reason": note, "path": rel}

        cmd = [
            MBPOLL_BIN,
            "-m", "tcp",
            "-a", str(unit),
            "-r", str(start + 1),
            "-c", str(count),
            "-t", "3",
            "-p", str(port),
            host
        ]
        rc, out, err = run_cmd(cmd, timeout=30)

        with open(abs_path, "w", encoding="utf-8") as f:
            f.write(f"{utc_now_iso()} rc={rc}\n")
            f.write(out)
            if err:
                f.write("\n--- stderr ---\n")
                f.write(err)

        item = EvidenceItem(
            eid=uuid.uuid4().hex,
            category="industrial",
            source=source,
            path=rel,
            created_utc=utc_now_iso(),
            tool="mbpoll",
            notes=f"target={host}:{port} unit={unit} start={start} count={count} rc={rc}"
        )
        store.add_item(case_id, item)
        store.finalize_item_hash(case_id, rel)
        return {"ok": True, "path": rel, "rc": rc}


# =========================
# ORCHESTRATOR
# =========================
class ForensicOrchestrator:
    def __init__(self, store: EvidenceStore):
        self.store = store
        self.net = NetworkCollector(iface="any")
        self.sys = SystemCollector()
        self.ot = OTCollector()

    def run_collection(
        self,
        experiment_id: str,
        scenario_id: str,
        trigger_type: str,
        trigger_ref: str,
        policy: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        policy example:
        {
          "sources": [{"id":"host", "type":"local"}],
          "network": {"enabled": true, "seconds": 15, "bpf": "tcp port 502"},
          "system": {"enabled": true},
          "industrial": {"enabled": true, "modbus": {"host":"10.0.2.22","port":502,"unit":1,"start":0,"count":10}}
        }
        """
        case_id = self.store.create_case(experiment_id, scenario_id, trigger_type, trigger_ref)
        results: Dict[str, Any] = {"case_id": case_id, "created_utc": utc_now_iso(), "steps": []}

        sources = policy.get("sources", [{"id": "local", "type": "local"}])

        for src in sources:
            src_id = src.get("id", "local")

            if policy.get("network", {}).get("enabled", True):
                secs = int(policy.get("network", {}).get("seconds", 20))
                bpf = policy.get("network", {}).get("bpf")
                r = self.net.collect_pcap(self.store, case_id, source=src_id, seconds=secs, bpf=bpf)
                results["steps"].append({"collector": "network", "source": src_id, "result": r})

            if policy.get("system", {}).get("enabled", True):
                r = self.sys.collect_system_snapshot(self.store, case_id, source=src_id)
                results["steps"].append({"collector": "system", "source": src_id, "result": r})

            if policy.get("industrial", {}).get("enabled", False):
                mb = policy.get("industrial", {}).get("modbus", {})
                host = mb.get("host")
                if host:
                    r = self.ot.collect_modbus_snapshot(
                        self.store,
                        case_id,
                        source=src_id,
                        host=host,
                        port=int(mb.get("port", 502)),
                        unit=int(mb.get("unit", 1)),
                        start=int(mb.get("start", 0)),
                        count=int(mb.get("count", 10)),
                    )
                    results["steps"].append({"collector": "industrial", "source": src_id, "result": r})
                else:
                    results["steps"].append({"collector": "industrial", "source": src_id, "result": {"ok": False, "reason": "no modbus.host provided"}})

        self.store._coc_append(case_id, "CASE_COLLECTION_FINISHED")
        results["manifest"] = os.path.join(self.store.case_dir(case_id), "manifest.json")
        results["chain_of_custody"] = os.path.join(self.store.case_dir(case_id), "chain_of_custody.log")
        return results


# =========================
# HTTP API (minimal)
# =========================
class Handler(BaseHTTPRequestHandler):
    orchestrator: ForensicOrchestrator = None  # injected

    def _json(self, code: int, obj: Any) -> None:
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/collect":
            self._json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req = json.loads(raw.decode("utf-8"))
        except Exception as e:
            self._json(400, {"error": f"invalid json: {e}"})
            return

        experiment_id = req.get(
            "experiment_id",
            f"EXP-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        )
        scenario_id = req.get("scenario_id", "SCENARIO-UNKNOWN")
        trigger_type = req.get("trigger_type", "manual")
        trigger_ref = req.get("trigger_ref", "manual_request")
        policy = req.get("policy", {})

        res = self.orchestrator.run_collection(
            experiment_id,
            scenario_id,
            trigger_type,
            trigger_ref,
            policy
        )
        self._json(200, res)

    def log_message(self, format, *args):
        return


def main():
    store = EvidenceStore(BASE_EVIDENCE_DIR)
    orch = ForensicOrchestrator(store)
    Handler.orchestrator = orch

    ensure_dir(BASE_EVIDENCE_DIR)
    httpd = HTTPServer((HOST, PORT), Handler)
    print(f"[forensic-orchestrator] listening on http://{HOST}:{PORT}")
    print(f"[forensic-orchestrator] evidence dir: {os.path.abspath(BASE_EVIDENCE_DIR)}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
