from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd
from scapy.all import IP, IPv6, TCP, UDP, rdpcap

from .config import GENERATED_DIR
from .schema import FEATURE_COLUMNS


IDLE_THRESHOLD_SECONDS = 1.0


def _mean(values: List[float]) -> float:
    return float(sum(values) / len(values)) if values else 0.0


def _variance(values: List[float]) -> float:
    if not values:
        return 0.0
    m = _mean(values)
    return float(sum((x - m) ** 2 for x in values) / len(values))


def _std(values: List[float]) -> float:
    return float(math.sqrt(_variance(values)))


def _min(values: List[float]) -> float:
    return float(min(values)) if values else 0.0


def _max(values: List[float]) -> float:
    return float(max(values)) if values else 0.0


def _iat(times: List[float]) -> List[float]:
    if len(times) < 2:
        return []
    ordered = sorted(times)
    return [ordered[i] - ordered[i - 1] for i in range(1, len(ordered))]


@dataclass
class FlowStats:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: int
    start_ts: float
    last_ts: float

    all_times: List[float] = field(default_factory=list)
    fwd_times: List[float] = field(default_factory=list)
    bwd_times: List[float] = field(default_factory=list)

    all_lengths: List[int] = field(default_factory=list)
    bwd_lengths: List[int] = field(default_factory=list)

    fwd_count: int = 0
    bwd_count: int = 0

    fin_count: int = 0
    psh_count: int = 0
    ack_count: int = 0

    init_win_bytes_forward: int = 0
    init_window_set: bool = False

    def add_packet(self, ts: float, direction: str, pkt_len: int, tcp_flags: int | None, tcp_window: int | None):
        self.last_ts = ts
        self.all_times.append(ts)
        self.all_lengths.append(pkt_len)

        if direction == "fwd":
            self.fwd_count += 1
            self.fwd_times.append(ts)
            if not self.init_window_set and tcp_window is not None:
                self.init_win_bytes_forward = int(tcp_window)
                self.init_window_set = True
        else:
            self.bwd_count += 1
            self.bwd_times.append(ts)
            self.bwd_lengths.append(pkt_len)

        if tcp_flags is not None:
            if tcp_flags & 0x01:
                self.fin_count += 1
            if tcp_flags & 0x08:
                self.psh_count += 1
            if tcp_flags & 0x10:
                self.ack_count += 1

    def to_feature_row(self) -> Dict[str, float]:
        flow_iat = _iat(self.all_times)
        fwd_iat = _iat(self.fwd_times)
        bwd_iat = _iat(self.bwd_times)

        idle_values = [x for x in flow_iat if x > IDLE_THRESHOLD_SECONDS]

        flow_duration = max(0.0, self.last_ts - self.start_ts)

        packet_mean = _mean(self.all_lengths)
        packet_std = _std(self.all_lengths)
        packet_var = _variance(self.all_lengths)

        bwd_mean = _mean(self.bwd_lengths)
        bwd_std = _std(self.bwd_lengths)

        down_up_ratio = float(self.bwd_count / self.fwd_count) if self.fwd_count > 0 else 0.0

        row = {
            "Destination Port": float(self.dst_port),
            "Protocol": float(self.protocol),
            "Flow Duration": float(flow_duration),
            "Bwd Packet Length Max": _max(self.bwd_lengths),
            "Bwd Packet Length Min": _min(self.bwd_lengths),
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,
            "Flow IAT Mean": _mean(flow_iat),
            "Flow IAT Std": _std(flow_iat),
            "Flow IAT Max": _max(flow_iat),
            "Fwd IAT Total": float(sum(fwd_iat)) if fwd_iat else 0.0,
            "Fwd IAT Mean": _mean(fwd_iat),
            "Fwd IAT Std": _std(fwd_iat),
            "Fwd IAT Max": _max(fwd_iat),
            "Bwd IAT Std": _std(bwd_iat),
            "Bwd IAT Max": _max(bwd_iat),
            "Min Packet Length": _min(self.all_lengths),
            "Max Packet Length": _max(self.all_lengths),
            "Packet Length Mean": packet_mean,
            "Packet Length Std": packet_std,
            "Packet Length Variance": packet_var,
            "FIN Flag Count": float(self.fin_count),
            "PSH Flag Count": float(self.psh_count),
            "ACK Flag Count": float(self.ack_count),
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": packet_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Init_Win_bytes_forward": float(self.init_win_bytes_forward),
            "Idle Mean": _mean(idle_values),
            "Idle Std": _std(idle_values),
            "Idle Max": _max(idle_values),
            "Idle Min": _min(idle_values),
        }

        return row


def _extract_packet_meta(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = int(ip_layer.proto)
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = int(ip_layer.nh)
    else:
        return None

    src_port = 0
    dst_port = 0
    tcp_flags = None
    tcp_window = None

    if TCP in pkt:
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        tcp_flags = int(pkt[TCP].flags)
        tcp_window = int(pkt[TCP].window)
    elif UDP in pkt:
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto,
        "length": int(len(pkt)),
        "tcp_flags": tcp_flags,
        "tcp_window": tcp_window,
        "timestamp": float(pkt.time),
    }


def _canonical_key(src_ip, src_port, dst_ip, dst_port, proto):
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (src_ip, src_port, dst_ip, dst_port, proto), "fwd"
    return (dst_ip, dst_port, src_ip, src_port, proto), "bwd"


def pcap_to_dataframe(pcap_path: str | Path) -> pd.DataFrame:
    pcap_path = Path(pcap_path)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    packets = rdpcap(str(pcap_path))
    flows: Dict[Tuple, FlowStats] = {}

    for pkt in packets:
        meta = _extract_packet_meta(pkt)
        if meta is None:
            continue

        key, direction = _canonical_key(
            meta["src_ip"],
            meta["src_port"],
            meta["dst_ip"],
            meta["dst_port"],
            meta["protocol"],
        )

        if key not in flows:
            flows[key] = FlowStats(
                src_ip=key[0],
                src_port=key[1],
                dst_ip=key[2],
                dst_port=key[3],
                protocol=key[4],
                start_ts=meta["timestamp"],
                last_ts=meta["timestamp"],
            )

        flows[key].add_packet(
            ts=meta["timestamp"],
            direction=direction,
            pkt_len=meta["length"],
            tcp_flags=meta["tcp_flags"],
            tcp_window=meta["tcp_window"],
        )

    rows = [flow.to_feature_row() for flow in flows.values()]
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def pcap_to_csv(pcap_path: str | Path) -> dict:
    pcap_path = Path(pcap_path)
    df = pcap_to_dataframe(pcap_path)

    out_csv = GENERATED_DIR / f"{pcap_path.stem}_features.csv"
    df.to_csv(out_csv, index=False)

    return {
        "ok": True,
        "pcap_file": str(pcap_path),
        "csv_file": str(out_csv),
        "rows": int(len(df)),
        "preview": df.head(20).to_dict(orient="records"),
    }