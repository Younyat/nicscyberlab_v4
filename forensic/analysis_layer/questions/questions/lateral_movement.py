#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import re


# Heurística: puertos típicos de movimiento lateral / administración remota
LATERAL_PORTS = {
    22: "ssh",
    23: "telnet",
    135: "msrpc",
    139: "netbios-ssn",
    445: "smb",
    3389: "rdp",
    5985: "winrm-http",
    5986: "winrm-https",
}

# Palabras clave típicas en procesos (si aparecen en ps aux) indicando tooling lateral
SUSPICIOUS_PROC_KEYWORDS = [
    "psexec", "wmic", "winrm", "impacket", "smbclient",
    "evil-winrm", "xfreerdp", "rdesktop", "net use",
    "crackmapexec", "cme", "secretsdump", "smbexec", "atexec",
]


@dataclass
class Candidate:
    kind: str
    confidence: str
    evidence: Dict[str, Any]


class LateralMovement:
    """
    Question:
    Are there indications of lateral movement between nodes?

    Inputs:
      facts["system"] -> objective system facts (may include process_count, ports, iptables_accessible)
      facts["system_snapshots_raw"] (optional) -> list of raw snapshot dicts, if you add it later
      facts["network"] (optional) -> parsed network facts
      facts["modbus_frames"] -> list of modbus frame dicts (not lateral by itself, but good for timeline)
      facts["network_pcap_summary"] (optional) -> if you store tshark summaries later

    Output:
      A structured answer with candidates + explanation.
    """

    def run(self, facts: Dict[str, Any]) -> Dict[str, Any]:
        candidates: List[Candidate] = []

        # 1) Heurística desde snapshots del sistema (si existen en facts)
        raw_snaps = facts.get("system_snapshots_raw", [])
        if raw_snaps:
            candidates.extend(self._from_system_snapshots(raw_snaps))

        # 2) Heurística "débil" si solo tenemos facts agregados
        candidates.extend(self._from_aggregated_system_facts(facts.get("system", {})))

        # 3) Consolidación
        verdict, rationale = self._summarize(candidates)

        return {
            "question": "lateral_movement",
            "answer": verdict,
            "rationale": rationale,
            "candidates": [c.__dict__ for c in candidates],
        }

    def _from_aggregated_system_facts(self, sysfacts: Dict[str, Any]) -> List[Candidate]:
        out: List[Candidate] = []

        # Si el snapshot detectó "open ports" no significa lateral,
        # pero aumenta superficie de administración remota.
        if sysfacts.get("open_ports") is True:
            out.append(Candidate(
                kind="system_open_ports",
                confidence="low",
                evidence={
                    "detail": "Open connections detected (ss output contained ESTAB). Not conclusive by itself."
                }
            ))

        # Si iptables_accessible=False significa que NO pudimos leer reglas (faltan privilegios)
        # Eso es relevante para forense, no para lateral; lo dejamos como nota.
        if sysfacts.get("iptables_accessible") is False:
            out.append(Candidate(
                kind="forensic_visibility_limit",
                confidence="low",
                evidence={
                    "detail": "iptables rules not accessible in snapshot (likely missing root). Lateral analysis may be incomplete."
                }
            ))

        return out

    def _from_system_snapshots(self, snapshots: List[Dict[str, Any]]) -> List[Candidate]:
        out: List[Candidate] = []

        for snap in snapshots:
            commands = snap.get("commands", {})

            # --- Process inspection
            ps_stdout = commands.get("ps", {}).get("stdout", "") or ""
            hits = self._match_keywords(ps_stdout, SUSPICIOUS_PROC_KEYWORDS)
            if hits:
                out.append(Candidate(
                    kind="suspicious_process_keywords",
                    confidence="medium",
                    evidence={
                        "matched": hits,
                        "note": "Process list contains keywords often associated with lateral movement tooling."
                    }
                ))

            # --- Connections inspection
            ss_stdout = commands.get("ss", {}).get("stdout", "") or ""
            port_hits = self._find_ports_in_ss(ss_stdout, LATERAL_PORTS)
            if port_hits:
                out.append(Candidate(
                    kind="remote_admin_ports_in_connections",
                    confidence="medium",
                    evidence={
                        "ports": port_hits,
                        "note": "Established connections include ports commonly used for remote administration."
                    }
                ))

            # If you later include auth logs, you can add:
            # journalctl_recent parsing for "Accepted password", "Failed password", etc.

        return out

    @staticmethod
    def _match_keywords(text: str, keywords: List[str]) -> List[str]:
        text_l = text.lower()
        matched = []
        for kw in keywords:
            if kw.lower() in text_l:
                matched.append(kw)
        return matched

    @staticmethod
    def _find_ports_in_ss(ss_text: str, port_map: Dict[int, str]) -> List[Dict[str, Any]]:
        """
        Extracts lines from `ss -plant` which contain :<port> occurrences.
        This is heuristic; it depends on ss formatting.
        """
        hits: List[Dict[str, Any]] = []
        lines = ss_text.splitlines()
        for line in lines:
            for port, name in port_map.items():
                # Match patterns like ":22", ":3389", etc.
                if re.search(rf":{port}\b", line):
                    hits.append({"port": port, "service": name, "line": line.strip()})
        return hits

    @staticmethod
    def _summarize(candidates: List[Candidate]) -> Tuple[str, str]:
        if not candidates:
            return ("NO_EVIDENCE", "No indicators found in available evidence.")

        # If we have medium confidence indicators, raise to SUSPICIOUS
        has_medium = any(c.confidence in ("medium", "high") for c in candidates)
        if has_medium:
            return ("SUSPICIOUS", "One or more indicators suggest possible lateral movement. Review evidence lines.")
        return ("WEAK_SIGNAL", "Some weak indicators exist but are not conclusive.")
