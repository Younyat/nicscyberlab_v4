from __future__ import annotations

import math
import os
import pickle
import socket
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from .config import DATASETS_CUSTOM_DIR

PCAP_GLOBAL_HDR_LEN = 24
PCAP_REC_HDR_LEN = 16
ETHERNET_HDR_LEN = 14
ETHERTYPE_IP = 0x0800

TCP_PROTO = 6
UDP_PROTO = 17

FLAG_FIN = 0x01
FLAG_PSH = 0x08
FLAG_ACK = 0x10

FEATURE_COLUMNS = [
    "Destination Port", "Protocol", "Flow Duration",
    "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max",
    "Bwd IAT Std", "Bwd IAT Max",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Down/Up Ratio", "Average Packet Size",
    "Avg Bwd Segment Size",
    "Init_Win_bytes_forward",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


class OnlineStats:
    __slots__ = ("n", "_mean", "_M2", "min_val", "max_val", "total")

    def __init__(self):
        self.n = 0
        self._mean = 0.0
        self._M2 = 0.0
        self.min_val = float("inf")
        self.max_val = float("-inf")
        self.total = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        self.total += x
        if x < self.min_val:
            self.min_val = x
        if x > self.max_val:
            self.max_val = x
        delta = x - self._mean
        self._mean += delta / self.n
        self._M2 += delta * (x - self._mean)

    @property
    def mean(self) -> float:
        return self._mean if self.n > 0 else 0.0

    @property
    def variance(self) -> float:
        return self._M2 / self.n if self.n > 0 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    @property
    def safe_min(self) -> float:
        return self.min_val if self.n > 0 else 0.0

    @property
    def safe_max(self) -> float:
        return self.max_val if self.n > 0 else 0.0


@dataclass
class BiFlow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int

    first_ts: float = 0.0
    last_ts: float = 0.0

    fwd_lens: List[int] = field(default_factory=list)
    bwd_lens: List[int] = field(default_factory=list)

    fwd_ts: List[float] = field(default_factory=list)
    bwd_ts: List[float] = field(default_factory=list)
    all_ts: List[float] = field(default_factory=list)

    fin_count: int = 0
    psh_count: int = 0
    ack_count: int = 0

    init_win_fwd: int = -1

    activity_timeout: float = 5.0
    _active_start: float = 0.0
    _last_active: float = 0.0
    idle_times: List[float] = field(default_factory=list)

    def add_packet(self, ts: float, pkt_len: int, direction: str, flags: int = 0, win: int = -1) -> None:
        if not self.all_ts:
            self.first_ts = ts
            self._active_start = ts
            self._last_active = ts

        gap = ts - self._last_active
        if gap > self.activity_timeout:
            self.idle_times.append(gap)
        self._last_active = ts

        self.last_ts = ts
        self.all_ts.append(ts)

        if direction == "fwd":
            self.fwd_lens.append(pkt_len)
            self.fwd_ts.append(ts)
            if self.init_win_fwd == -1 and win >= 0:
                self.init_win_fwd = win
        else:
            self.bwd_lens.append(pkt_len)
            self.bwd_ts.append(ts)

        if flags & FLAG_FIN:
            self.fin_count += 1
        if flags & FLAG_PSH:
            self.psh_count += 1
        if flags & FLAG_ACK:
            self.ack_count += 1

    @staticmethod
    def _iat_series(timestamps: List[float]) -> List[float]:
        if len(timestamps) < 2:
            return []
        return [(timestamps[i] - timestamps[i - 1]) * 1e6 for i in range(1, len(timestamps))]

    def to_feature_row(self) -> Optional[List[float]]:
        n_fwd = len(self.fwd_lens)
        n_bwd = len(self.bwd_lens)
        n_all = n_fwd + n_bwd

        if n_all == 0:
            return None

        flow_duration = max((self.last_ts - self.first_ts) * 1e6, 0.0)

        bwd_stats = OnlineStats()
        for l in self.bwd_lens:
            bwd_stats.update(float(l))

        flow_iats = self._iat_series(sorted(self.all_ts))
        fiat_stats = OnlineStats()
        for v in flow_iats:
            fiat_stats.update(v)

        fwd_iats = self._iat_series(sorted(self.fwd_ts))
        fwd_iat_stats = OnlineStats()
        for v in fwd_iats:
            fwd_iat_stats.update(v)
        fwd_iat_total = sum(fwd_iats)

        bwd_iats = self._iat_series(sorted(self.bwd_ts))
        bwd_iat_stats = OnlineStats()
        for v in bwd_iats:
            bwd_iat_stats.update(v)

        all_lens = self.fwd_lens + self.bwd_lens
        pkt_stats = OnlineStats()
        for l in all_lens:
            pkt_stats.update(float(l))

        down_up = (n_bwd / n_fwd) if n_fwd > 0 else 0.0
        avg_pkt_size = pkt_stats.mean
        avg_bwd_seg = bwd_stats.mean
        init_win = float(self.init_win_fwd)

        idle_stats = OnlineStats()
        for v in self.idle_times:
            idle_stats.update(v * 1e6)

        return [
            float(self.dst_port),
            float(self.proto),
            flow_duration,
            bwd_stats.safe_max,
            bwd_stats.safe_min if n_bwd else 0.0,
            bwd_stats.mean,
            bwd_stats.std,
            fiat_stats.mean,
            fiat_stats.std,
            fiat_stats.safe_max if flow_iats else 0.0,
            fwd_iat_total,
            fwd_iat_stats.mean,
            fwd_iat_stats.std,
            fwd_iat_stats.safe_max if fwd_iats else 0.0,
            bwd_iat_stats.std,
            bwd_iat_stats.safe_max if bwd_iats else 0.0,
            pkt_stats.safe_min if all_lens else 0.0,
            pkt_stats.safe_max if all_lens else 0.0,
            pkt_stats.mean,
            pkt_stats.std,
            pkt_stats.variance,
            float(self.fin_count),
            float(self.psh_count),
            float(self.ack_count),
            down_up,
            avg_pkt_size,
            avg_bwd_seg,
            init_win,
            idle_stats.mean,
            idle_stats.std,
            idle_stats.safe_max if self.idle_times else 0.0,
            idle_stats.safe_min if self.idle_times else 0.0,
        ]


FlowKey = Tuple[str, str, int, int, int]


def _normalize_key(src_ip, dst_ip, sport, dport, proto) -> FlowKey:
    if (src_ip, sport) <= (dst_ip, dport):
        return (src_ip, dst_ip, sport, dport, proto)
    return (dst_ip, src_ip, dport, sport, proto)


def parse_pcap(
    pcap_path: str,
    flow_timeout: float = 120.0,
    activity_timeout: float = 5.0,
) -> List[BiFlow]:
    flows: Dict[FlowKey, BiFlow] = {}
    finished_flows: List[BiFlow] = []

    with open(pcap_path, "rb") as f:
        gh = f.read(PCAP_GLOBAL_HDR_LEN)
        if len(gh) < PCAP_GLOBAL_HDR_LEN:
            raise ValueError("Invalid PCAP global header")

        magic, _, _, _, _, _, linktype = struct.unpack("<IHHiIII", gh)

        if magic not in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
            raise ValueError(f"Unsupported PCAP magic number: {hex(magic)}")

        big_endian = magic in (0xD4C3B2A1, 0x4D3CB2A1)
        rec_fmt = ">IIII" if big_endian else "<IIII"

        if linktype != 1:
            raise ValueError(f"Unsupported linktype: {linktype}. Only Ethernet is supported")

        while True:
            rh = f.read(PCAP_REC_HDR_LEN)
            if not rh:
                break
            if len(rh) < PCAP_REC_HDR_LEN:
                break

            ts_sec, ts_usec, incl_len, _ = struct.unpack(rec_fmt, rh)
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break

            ts = ts_sec + ts_usec * 1e-6

            if len(raw) < ETHERNET_HDR_LEN + 20:
                continue

            ethertype = struct.unpack("!H", raw[12:14])[0]
            if ethertype != ETHERTYPE_IP:
                continue

            ip_data = raw[ETHERNET_HDR_LEN:]
            if len(ip_data) < 20:
                continue

            ip_ver = ip_data[0] >> 4
            if ip_ver != 4:
                continue

            ihl = (ip_data[0] & 0xF) * 4
            proto = ip_data[9]
            ip_total = struct.unpack("!H", ip_data[2:4])[0]

            if proto not in (TCP_PROTO, UDP_PROTO):
                continue

            try:
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])
            except Exception:
                continue

            transport = ip_data[ihl:]
            if len(transport) < 4:
                continue

            sport = struct.unpack("!H", transport[0:2])[0]
            dport = struct.unpack("!H", transport[2:4])[0]

            tcp_flags = 0
            tcp_win = -1
            if proto == TCP_PROTO and len(transport) >= 16:
                tcp_flags = transport[13]
                tcp_win = struct.unpack("!H", transport[14:16])[0]

            pkt_len = ip_total

            key = _normalize_key(src_ip, dst_ip, sport, dport, proto)
            direction = "fwd" if key == (src_ip, dst_ip, sport, dport, proto) else "bwd"

            if key in flows:
                fl = flows[key]
                if ts - fl.last_ts > flow_timeout:
                    finished_flows.append(fl)
                    del flows[key]

            if key not in flows:
                flows[key] = BiFlow(
                    src_ip=key[0],
                    dst_ip=key[1],
                    src_port=key[2],
                    dst_port=key[3],
                    proto=proto,
                    activity_timeout=activity_timeout,
                )

            flows[key].add_packet(ts, pkt_len, direction, tcp_flags, tcp_win)

            if proto == TCP_PROTO and (tcp_flags & 0x04):
                finished_flows.append(flows[key])
                del flows[key]

    finished_flows.extend(flows.values())
    return finished_flows


def auto_label_flow(flow: BiFlow) -> str:
    n_fwd = len(flow.fwd_lens)
    n_bwd = len(flow.bwd_lens)
    n_all = n_fwd + n_bwd
    duration_s = flow.last_ts - flow.first_ts

    if n_all >= 50 and n_bwd == 0 and duration_s < 10.0:
        return "DDoS"

    if flow.proto == UDP_PROTO and n_fwd > 20 and n_bwd <= 2:
        return "DDoS"

    avg_len = sum(flow.fwd_lens) / n_fwd if n_fwd else 0
    if flow.proto == TCP_PROTO and avg_len < 80 and n_fwd > 30 and n_bwd == 0:
        return "DDoS"

    return "BENIGN"


def build_dataset(flows: List[BiFlow], label: Optional[str], auto_label: bool):
    rows = []
    labels = []

    for fl in flows:
        row = fl.to_feature_row()
        if row is None:
            continue

        rows.append(row)
        labels.append(auto_label_flow(fl) if auto_label else (label or "Unknown"))

    if not rows:
        raise ValueError("No valid flows were extracted from the PCAP")

    X = pd.DataFrame(rows, columns=FEATURE_COLUMNS).astype("float32")
    y = pd.Series(labels, name="Attack Type")
    return X, y


def make_split(X: pd.DataFrame, y: pd.Series, test_size: float = 0.30, random_state: int = 42) -> dict:
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y if len(y.unique()) > 1 else None,
    )
    return {
        "X_train": X_train.reset_index(drop=True),
        "X_test": X_test.reset_index(drop=True),
        "y_train": y_train.reset_index(drop=True),
        "y_test": y_test.reset_index(drop=True),
    }


def build_split_from_pcap(
    pcap_path: str,
    dataset_id: str,
    label: Optional[str] = None,
    auto_label: bool = False,
    test_size: float = 0.30,
    flow_timeout: float = 120.0,
    activity_timeout: float = 5.0,
) -> dict:
    flows = parse_pcap(
        pcap_path=pcap_path,
        flow_timeout=flow_timeout,
        activity_timeout=activity_timeout,
    )
    X, y = build_dataset(flows, label=label, auto_label=auto_label)
    split_payload = make_split(X, y, test_size=test_size)

    target_dir = DATASETS_CUSTOM_DIR / dataset_id
    target_dir.mkdir(parents=True, exist_ok=True)

    split_path = target_dir / "data_split.pkl"
    with split_path.open("wb") as f:
        pickle.dump(split_payload, f, protocol=pickle.HIGHEST_PROTOCOL)

    return {
        "split_path": str(split_path),
        "rows_total": int(len(X)),
        "rows_train": int(len(split_payload["X_train"])),
        "rows_test": int(len(split_payload["X_test"])),
        "features": list(X.columns),
        "labels": sorted(y.unique().tolist()),
        "label_distribution": {str(k): int(v) for k, v in y.value_counts().to_dict().items()},
    }