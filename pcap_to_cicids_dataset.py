"""
pcap_to_cicids_dataset.py
=========================
Genera un dataset idéntico en estructura al CIC-IDS-2017 (data_split_2017.pkl)
a partir de un archivo PCAP capturado en una máquina bajo ataque DDoS.

FEATURES EXTRAÍDAS (32 columnas, dtype float32):
    Destination Port, Protocol, Flow Duration,
    Bwd Packet Length Max/Min/Mean/Std,
    Flow IAT Mean/Std/Max,
    Fwd IAT Total/Mean/Std/Max,
    Bwd IAT Std/Max,
    Min Packet Length, Max Packet Length,
    Packet Length Mean/Std/Variance,
    FIN Flag Count, PSH Flag Count, ACK Flag Count,
    Down/Up Ratio, Average Packet Size,
    Avg Bwd Segment Size,
    Init_Win_bytes_forward,
    Idle Mean/Std/Max/Min

DEPENDENCIAS:
    pip install pandas numpy

USO:
    python pcap_to_cicids_dataset.py \
        --pcap SAT-01-12-2018_0248 \
        --label DDoS \
        --out dataset_from_pcap.pkl \
        --flow-timeout 120 \
        --activity-timeout 5

    # Para asignar etiquetas automáticamente por heurística DDoS:
    python pcap_to_cicids_dataset.py --pcap SAT-01-12-2018_0248 --auto-label

    # Para generar un split train/test listo para usar como el pkl original:
    python pcap_to_cicids_dataset.py --pcap SAT-01-12-2018_0248 --auto-label --split

DEFINICIÓN DE FLUJO (bidireccional):
    clave = (ip_src, ip_dst, sport, dport, proto) normalizado → mín(src,dst) primero
    timeout de flujo = 120 s por defecto (igual que CICFlowMeter)
    timeout de actividad = 5 s para cómputo de Idle
"""

import argparse
import math
import os
import pickle
import socket
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# ──────────────────────────────────────────────
# CONSTANTES
# ──────────────────────────────────────────────
PCAP_GLOBAL_HDR_LEN = 24
PCAP_REC_HDR_LEN    = 16
ETHERNET_HDR_LEN    = 14
ETHERTYPE_IP        = 0x0800

TCP_PROTO  = 6
UDP_PROTO  = 17

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


# ──────────────────────────────────────────────
# ESTADÍSTICAS INCREMENTALES (Welford online)
# ──────────────────────────────────────────────
class OnlineStats:
    """Media y varianza en una sola pasada (algoritmo de Welford)."""
    __slots__ = ("n", "_mean", "_M2", "min_val", "max_val", "total")

    def __init__(self):
        self.n       = 0
        self._mean   = 0.0
        self._M2     = 0.0
        self.min_val = float("inf")
        self.max_val = float("-inf")
        self.total   = 0.0

    def update(self, x: float) -> None:
        self.n     += 1
        self.total += x
        if x < self.min_val: self.min_val = x
        if x > self.max_val: self.max_val = x
        delta      = x - self._mean
        self._mean += delta / self.n
        self._M2   += delta * (x - self._mean)

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


# ──────────────────────────────────────────────
# FLUJO BIDIRECCIONAL
# ──────────────────────────────────────────────
@dataclass
class BiFlow:
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    proto:    int

    first_ts: float = 0.0
    last_ts:  float = 0.0

    # Tamaños de payload (capa de transporte) por dirección
    fwd_lens:  List[int] = field(default_factory=list)
    bwd_lens:  List[int] = field(default_factory=list)

    # Timestamps por dirección (para IAT)
    fwd_ts: List[float] = field(default_factory=list)
    bwd_ts: List[float] = field(default_factory=list)

    # Todos los timestamps (para Flow IAT)
    all_ts: List[float] = field(default_factory=list)

    # Flags TCP
    fin_count: int = 0
    psh_count: int = 0
    ack_count: int = 0

    # Ventana TCP inicial del forward (primer paquete fwd)
    init_win_fwd: int = -1

    # Para cómputo de Idle (actividad dentro del flujo)
    activity_timeout: float = 5.0   # segundos
    _active_start: float   = 0.0
    _last_active:  float   = 0.0
    idle_times: List[float] = field(default_factory=list)


    def add_packet(self, ts: float, pkt_len: int, direction: str,
                   flags: int = 0, win: int = -1) -> None:
        """
        direction: 'fwd' | 'bwd'
        pkt_len  : longitud total del paquete IP (igual que CICFlowMeter usa el
                   tamaño del payload; aquí usamos el tamaño IP total que incluye
                   cabeceras, consistente con la implementación de referencia)
        """
        if not self.all_ts:
            self.first_ts     = ts
            self._active_start = ts
            self._last_active  = ts
        
        # ── Idle detection ───────────────────────────────────────────────
        gap = ts - self._last_active
        if gap > self.activity_timeout:
            self.idle_times.append(gap)
        self._last_active = ts
        # ─────────────────────────────────────────────────────────────────

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

        # TCP flags
        if flags & FLAG_FIN: self.fin_count += 1
        if flags & FLAG_PSH: self.psh_count += 1
        if flags & FLAG_ACK: self.ack_count += 1


    @staticmethod
    def _iat_series(timestamps: List[float]) -> List[float]:
        """Inter-arrival times from a sorted list of timestamps (microseconds)."""
        if len(timestamps) < 2:
            return []
        return [(timestamps[i] - timestamps[i-1]) * 1e6
                for i in range(1, len(timestamps))]


    def to_feature_row(self) -> Optional[List[float]]:
        """Devuelve lista de 32 floats o None si el flujo no tiene suficientes paquetes."""
        n_fwd = len(self.fwd_lens)
        n_bwd = len(self.bwd_lens)
        n_all = n_fwd + n_bwd

        if n_all == 0:
            return None

        # ── Flow Duration (µs) ───────────────────────────────────────────
        flow_duration = max((self.last_ts - self.first_ts) * 1e6, 0.0)

        # ── Bwd packet lengths ───────────────────────────────────────────
        bwd_stats = OnlineStats()
        for l in self.bwd_lens:
            bwd_stats.update(float(l))

        # ── Flow IAT ─────────────────────────────────────────────────────
        flow_iats = self._iat_series(sorted(self.all_ts))
        fiat_stats = OnlineStats()
        for v in flow_iats:
            fiat_stats.update(v)

        # ── Fwd IAT ──────────────────────────────────────────────────────
        fwd_iats = self._iat_series(sorted(self.fwd_ts))
        fwd_iat_stats = OnlineStats()
        for v in fwd_iats:
            fwd_iat_stats.update(v)
        fwd_iat_total = sum(fwd_iats)

        # ── Bwd IAT ──────────────────────────────────────────────────────
        bwd_iats = self._iat_series(sorted(self.bwd_ts))
        bwd_iat_stats = OnlineStats()
        for v in bwd_iats:
            bwd_iat_stats.update(v)

        # ── Global packet lengths ─────────────────────────────────────────
        all_lens = self.fwd_lens + self.bwd_lens
        pkt_stats = OnlineStats()
        for l in all_lens:
            pkt_stats.update(float(l))

        # ── Down/Up Ratio ─────────────────────────────────────────────────
        down_up = (n_bwd / n_fwd) if n_fwd > 0 else 0.0

        # ── Average Packet Size ───────────────────────────────────────────
        avg_pkt_size = pkt_stats.mean

        # ── Avg Bwd Segment Size (= Bwd Packet Length Mean) ───────────────
        avg_bwd_seg = bwd_stats.mean

        # ── Init_Win_bytes_forward ────────────────────────────────────────
        init_win = float(self.init_win_fwd)   # -1 si no es TCP

        # ── Idle stats (µs) ───────────────────────────────────────────────
        idle_stats = OnlineStats()
        for v in self.idle_times:
            idle_stats.update(v * 1e6)

        return [
            float(self.dst_port),           # Destination Port
            float(self.proto),              # Protocol
            flow_duration,                  # Flow Duration

            bwd_stats.safe_max,             # Bwd Packet Length Max
            bwd_stats.safe_min if n_bwd else 0.0,  # Bwd Packet Length Min
            bwd_stats.mean,                 # Bwd Packet Length Mean
            bwd_stats.std,                  # Bwd Packet Length Std

            fiat_stats.mean,                # Flow IAT Mean
            fiat_stats.std,                 # Flow IAT Std
            fiat_stats.safe_max if flow_iats else 0.0,  # Flow IAT Max

            fwd_iat_total,                  # Fwd IAT Total
            fwd_iat_stats.mean,             # Fwd IAT Mean
            fwd_iat_stats.std,              # Fwd IAT Std
            fwd_iat_stats.safe_max if fwd_iats else 0.0,  # Fwd IAT Max

            bwd_iat_stats.std,              # Bwd IAT Std
            bwd_iat_stats.safe_max if bwd_iats else 0.0,  # Bwd IAT Max

            pkt_stats.safe_min if all_lens else 0.0,  # Min Packet Length
            pkt_stats.safe_max if all_lens else 0.0,  # Max Packet Length
            pkt_stats.mean,                 # Packet Length Mean
            pkt_stats.std,                  # Packet Length Std
            pkt_stats.variance,             # Packet Length Variance

            float(self.fin_count),          # FIN Flag Count
            float(self.psh_count),          # PSH Flag Count
            float(self.ack_count),          # ACK Flag Count

            down_up,                        # Down/Up Ratio
            avg_pkt_size,                   # Average Packet Size
            avg_bwd_seg,                    # Avg Bwd Segment Size
            init_win,                       # Init_Win_bytes_forward

            idle_stats.mean,                # Idle Mean
            idle_stats.std,                 # Idle Std
            idle_stats.safe_max if self.idle_times else 0.0,  # Idle Max
            idle_stats.safe_min if self.idle_times else 0.0,  # Idle Min
        ]


# ──────────────────────────────────────────────
# PARSER DE PCAP (sin dependencias externas)
# ──────────────────────────────────────────────
FlowKey = Tuple[str, str, int, int, int]   # (ip1, ip2, port1, port2, proto)

def _normalize_key(src_ip, dst_ip, sport, dport, proto) -> FlowKey:
    """Clave bidireccional canónica (menor IP primero)."""
    if (src_ip, sport) <= (dst_ip, dport):
        return (src_ip, dst_ip, sport, dport, proto)
    return (dst_ip, src_ip, dport, sport, proto)


def parse_pcap(
    pcap_path: str,
    flow_timeout: float = 120.0,      # segundos
    activity_timeout: float = 5.0,    # segundos para Idle
    verbose: bool = True,
) -> List[BiFlow]:
    """
    Lee el PCAP paquete a paquete (sin cargar todo en memoria) y construye
    flujos bidireccionales siguiendo la misma lógica que CICFlowMeter.

    Retorna lista de BiFlow finalizados.
    """
    flows: Dict[FlowKey, BiFlow] = {}
    finished_flows: List[BiFlow] = []
    pkt_count = 0
    skipped   = 0

    with open(pcap_path, "rb") as f:
        # ── Cabecera global PCAP ─────────────────────────────────────────
        gh = f.read(PCAP_GLOBAL_HDR_LEN)
        if len(gh) < PCAP_GLOBAL_HDR_LEN:
            raise ValueError("Archivo PCAP truncado en la cabecera global.")
        magic, ver_maj, ver_min, _, _, snaplen, linktype = struct.unpack("<IHHiIII", gh)

        if magic not in (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1):
            raise ValueError(f"Magic number PCAP no reconocido: {hex(magic)}")

        # Determinar endianness a partir del magic
        big_endian = magic in (0xD4C3B2A1, 0x4D3CB2A1)
        rec_fmt    = ">IIII" if big_endian else "<IIII"

        # Offset de capa de enlace: solo Ethernet (linktype=1) soportado aquí
        if linktype != 1:
            print(f"[WARN] linktype={linktype} — solo Ethernet (1) está soportado. "
                  "Paquetes no-Ethernet serán ignorados.", file=sys.stderr)
        l2_offset = ETHERNET_HDR_LEN if linktype == 1 else 0

        while True:
            rh = f.read(PCAP_REC_HDR_LEN)
            if not rh:
                break
            if len(rh) < PCAP_REC_HDR_LEN:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(rec_fmt, rh)
            raw = f.read(incl_len)
            if len(raw) < incl_len:
                break  # PCAP truncado

            ts = ts_sec + ts_usec * 1e-6
            pkt_count += 1

            # ── Nivel Ethernet → IP ──────────────────────────────────────
            if len(raw) < l2_offset + 20:
                skipped += 1; continue

            if linktype == 1:
                ethertype = struct.unpack("!H", raw[12:14])[0]
                if ethertype != ETHERTYPE_IP:
                    skipped += 1; continue

            ip_data = raw[l2_offset:]
            if len(ip_data) < 20:
                skipped += 1; continue

            ip_ver = (ip_data[0] >> 4)
            if ip_ver != 4:          # Solo IPv4
                skipped += 1; continue

            ihl      = (ip_data[0] & 0xF) * 4
            proto    = ip_data[9]
            ip_total = struct.unpack("!H", ip_data[2:4])[0]

            if proto not in (TCP_PROTO, UDP_PROTO):
                skipped += 1; continue

            try:
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])
            except Exception:
                skipped += 1; continue

            if len(ip_data) < ihl + 4:
                skipped += 1; continue

            transport = ip_data[ihl:]
            sport = struct.unpack("!H", transport[0:2])[0]
            dport = struct.unpack("!H", transport[2:4])[0]

            # ── Flags TCP y ventana inicial ──────────────────────────────
            tcp_flags = 0
            tcp_win   = -1
            if proto == TCP_PROTO and len(transport) >= 14:
                tcp_flags = transport[13]
                tcp_win   = struct.unpack("!H", transport[14:16])[0] if len(transport) >= 16 else -1

            # ── Longitud del paquete IP (consistente con CICFlowMeter) ───
            pkt_len = ip_total

            # ── Gestión de flujos ────────────────────────────────────────
            key = _normalize_key(src_ip, dst_ip, sport, dport, proto)
            canonical_fwd = (src_ip, dst_ip, sport, dport, proto)
            direction = "fwd" if key == canonical_fwd else "bwd"
            # Si la clave normalizada pone dst primero, el sentido se invierte
            if key != (src_ip, dst_ip, sport, dport, proto):
                direction = "bwd"
            else:
                direction = "fwd"

            # Timeout: cerrar flujo si han pasado flow_timeout segundos
            if key in flows:
                fl = flows[key]
                if ts - fl.last_ts > flow_timeout:
                    finished_flows.append(fl)
                    del flows[key]

            if key not in flows:
                fl = BiFlow(
                    src_ip=key[0], dst_ip=key[1],
                    src_port=key[2], dst_port=key[3],
                    proto=proto,
                    activity_timeout=activity_timeout,
                )
                flows[key] = fl

            flows[key].add_packet(ts, pkt_len, direction, tcp_flags, tcp_win)

            # SYN+FIN o RST: cerrar flujo inmediatamente (TCP teardown)
            if proto == TCP_PROTO:
                if (tcp_flags & 0x04):  # RST
                    finished_flows.append(flows[key])
                    del flows[key]

    # Flujos que quedan activos al final del pcap → cerrarlos
    finished_flows.extend(flows.values())

    if verbose:
        print(f"[INFO] Paquetes procesados : {pkt_count:,}")
        print(f"[INFO] Paquetes ignorados  : {skipped:,}")
        print(f"[INFO] Flujos extraídos    : {len(finished_flows):,}")

    return finished_flows


# ──────────────────────────────────────────────
# HEURÍSTICA DE AUTO-ETIQUETADO DDoS
# ──────────────────────────────────────────────
_DDOS_PORTS = {80, 443, 8080, 53, 22, 23, 25, 21}

def auto_label_flow(flow: BiFlow) -> str:
    """
    Heurística simple para etiquetar flujos de un PCAP de ataque DDoS.
    Ajusta los umbrales según el tráfico específico de tu captura.
    """
    n_fwd = len(flow.fwd_lens)
    n_bwd = len(flow.bwd_lens)
    n_all = n_fwd + n_bwd
    duration_s = flow.last_ts - flow.first_ts

    # Flood: muchos paquetes pequeños en poco tiempo, sin respuesta
    if n_all >= 50 and n_bwd == 0 and duration_s < 10.0:
        return "DDoS"

    # UDP flood hacia puertos conocidos
    if flow.proto == UDP_PROTO and n_fwd > 20 and n_bwd <= 2:
        return "DDoS"

    # SYN flood: solo FIN/ACK=0 en casi todos los paquetes
    avg_len = sum(flow.fwd_lens) / n_fwd if n_fwd else 0
    if flow.proto == TCP_PROTO and avg_len < 80 and n_fwd > 30 and n_bwd == 0:
        return "DDoS"

    # Tráfico benigno residual
    return "BENIGN"


# ──────────────────────────────────────────────
# CONSTRUCCIÓN DEL DATASET
# ──────────────────────────────────────────────
def build_dataset(
    flows: List[BiFlow],
    label: Optional[str],
    auto_label: bool,
) -> pd.DataFrame:
    """Convierte la lista de BiFlow en un DataFrame con el esquema CIC-IDS-2017."""
    rows   = []
    labels = []

    for fl in flows:
        row = fl.to_feature_row()
        if row is None:
            continue
        rows.append(row)

        if auto_label:
            labels.append(auto_label_flow(fl))
        else:
            labels.append(label or "Unknown")

    if not rows:
        raise ValueError("No se extrajeron flujos del PCAP. Verifica el archivo.")

    X = pd.DataFrame(rows, columns=FEATURE_COLUMNS).astype("float32")
    y = pd.Series(labels, name="Attack Type")

    print(f"[INFO] Filas en el dataset   : {len(X):,}")
    print(f"[INFO] Distribución de clases:\n{y.value_counts().to_string()}")
    return X, y


# ──────────────────────────────────────────────
# TRAIN / TEST SPLIT
# ──────────────────────────────────────────────
def make_split(X: pd.DataFrame, y: pd.Series,
               test_size: float = 0.3,
               random_state: int = 42) -> dict:
    """Reproducir el formato exacto del pkl original: dict con X_train/X_test/y_train/y_test."""
    from sklearn.model_selection import train_test_split  # opcional; fallback manual abajo

    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
    except ImportError:
        # Fallback sin sklearn: split manual reproducible
        rng    = np.random.default_rng(random_state)
        idx    = rng.permutation(len(X))
        split  = int(len(X) * (1 - test_size))
        tr_idx = idx[:split]
        te_idx = idx[split:]
        X_train = X.iloc[tr_idx].reset_index(drop=True)
        X_test  = X.iloc[te_idx].reset_index(drop=True)
        y_train = y.iloc[tr_idx].reset_index(drop=True)
        y_test  = y.iloc[te_idx].reset_index(drop=True)

    return {
        "X_train": X_train.reset_index(drop=True),
        "X_test":  X_test.reset_index(drop=True),
        "y_train": y_train.reset_index(drop=True),
        "y_test":  y_test.reset_index(drop=True),
    }


# ──────────────────────────────────────────────
# VALIDACIÓN CONTRA EL PKL ORIGINAL
# ──────────────────────────────────────────────
def validate_against_reference(new_X: pd.DataFrame, ref_pkl: str) -> None:
    """Compara columnas, dtypes y rangos estadísticos contra el dataset de referencia."""
    print("\n[VALIDACIÓN] Comparando con el dataset de referencia...")
    with open(ref_pkl, "rb") as f:
        ref = pickle.load(f)
    ref_X = ref["X_train"]

    # Columnas
    missing = set(ref_X.columns) - set(new_X.columns)
    extra   = set(new_X.columns) - set(ref_X.columns)
    if missing: print(f"  [WARN] Columnas faltantes: {missing}")
    if extra:   print(f"  [WARN] Columnas extra    : {extra}")

    # Dtypes
    for col in ref_X.columns:
        if col in new_X.columns and new_X[col].dtype != ref_X[col].dtype:
            print(f"  [WARN] dtype distinto en '{col}': "
                  f"nuevo={new_X[col].dtype}, ref={ref_X[col].dtype}")

    # Rango (solo columnas comunes)
    common = [c for c in ref_X.columns if c in new_X.columns]
    ref_stats = ref_X[common].describe()
    new_stats = new_X[common].describe()
    print("\n  Comparación de medias (referencia vs. nuevo):")
    for col in common[:10]:
        r_mean = ref_stats.loc["mean", col]
        n_mean = new_stats.loc["mean", col]
        print(f"    {col:<35} ref={r_mean:>12.2f}  nuevo={n_mean:>12.2f}")
    print("[VALIDACIÓN] Completada.\n")


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(
        description="Genera dataset CIC-IDS-2017 a partir de un PCAP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--pcap", required=True,
                   help="Ruta al archivo .pcap o .pcapng")
    p.add_argument("--label", default=None,
                   help="Etiqueta fija para todos los flujos (ej: 'DDoS'). "
                        "Ignorado si --auto-label está activo.")
    p.add_argument("--auto-label", action="store_true",
                   help="Etiqueta automática por heurística DDoS/BENIGN.")
    p.add_argument("--out", default="dataset_from_pcap.pkl",
                   help="Nombre del archivo de salida (.pkl o .csv).")
    p.add_argument("--split", action="store_true",
                   help="Generar split train/test con el mismo formato del pkl original.")
    p.add_argument("--test-size", type=float, default=0.30,
                   help="Proporción del test set (default: 0.30).")
    p.add_argument("--flow-timeout", type=float, default=120.0,
                   help="Timeout de flujo en segundos (default: 120).")
    p.add_argument("--activity-timeout", type=float, default=5.0,
                   help="Timeout de actividad para Idle en segundos (default: 5).")
    p.add_argument("--validate", default=None, metavar="REF_PKL",
                   help="Ruta al pkl de referencia para validación estadística.")
    p.add_argument("--csv", action="store_true",
                   help="Guardar también un CSV además del pkl.")
    return p.parse_args()


def main():
    args = parse_args()

    if not os.path.isfile(args.pcap):
        print(f"[ERROR] No se encontró el archivo PCAP: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    if not args.label and not args.auto_label:
        print("[WARN] Ni --label ni --auto-label especificados. "
              "Todos los flujos serán etiquetados como 'Unknown'.")

    print(f"\n{'='*55}")
    print(f"  PCAP → CIC-IDS-2017 Dataset Builder")
    print(f"{'='*55}")
    print(f"  PCAP          : {args.pcap}")
    print(f"  Flow timeout  : {args.flow_timeout}s")
    print(f"  Idle timeout  : {args.activity_timeout}s")
    print(f"  Auto-label    : {args.auto_label}")
    print(f"  Label fija    : {args.label}")
    print(f"  Salida        : {args.out}")
    print(f"{'='*55}\n")

    # ── 1. Parsear PCAP ──────────────────────────────────────────────────
    flows = parse_pcap(
        args.pcap,
        flow_timeout=args.flow_timeout,
        activity_timeout=args.activity_timeout,
    )

    # ── 2. Construir DataFrame ───────────────────────────────────────────
    X, y = build_dataset(flows, label=args.label, auto_label=args.auto_label)

    # ── 3. Validación opcional ───────────────────────────────────────────
    if args.validate:
        validate_against_reference(X, args.validate)

    # ── 4. Guardar ───────────────────────────────────────────────────────
    out_path = args.out
    if args.split:
        data = make_split(X, y, test_size=args.test_size)
        print(f"\n[INFO] Train: {data['X_train'].shape}, Test: {data['X_test'].shape}")
        if not out_path.endswith(".pkl"):
            out_path += ".pkl"
        with open(out_path, "wb") as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
        print(f"[OK] Split guardado en: {out_path}")

        if args.csv:
            csv_train = out_path.replace(".pkl", "_train.csv")
            csv_test  = out_path.replace(".pkl", "_test.csv")
            data["X_train"].assign(**{"Attack Type": data["y_train"]}).to_csv(csv_train, index=False)
            data["X_test"].assign(**{"Attack Type": data["y_test"]}).to_csv(csv_test, index=False)
            print(f"[OK] CSV guardados: {csv_train}, {csv_test}")
    else:
        if out_path.endswith(".csv") or args.csv:
            full = X.copy()
            full["Attack Type"] = y.values
            csv_path = out_path if out_path.endswith(".csv") else out_path.replace(".pkl", ".csv")
            full.to_csv(csv_path, index=False)
            print(f"[OK] CSV guardado en: {csv_path}")

        if not out_path.endswith(".csv"):
            if not out_path.endswith(".pkl"):
                out_path += ".pkl"
            with open(out_path, "wb") as f:
                pickle.dump({"X": X, "y": y}, f, protocol=pickle.HIGHEST_PROTOCOL)
            print(f"[OK] Dataset guardado en: {out_path}")

    print("\n[DONE] Proceso completado exitosamente.\n")


if __name__ == "__main__":
    main()
