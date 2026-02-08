from flask import Flask, request, jsonify
import subprocess, os, json, time

app = Flask(__name__)
CAPTURE_DIR = "./captures"

def run(cmd):
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode(errors="ignore")

def count_frames_with_filter(pcap, display_filter):
    """
    Cuenta frames que cumplen un display filter usando tshark.
    Robusto: usa frame.number (una línea por frame).
    """
    out = run(["tshark", "-r", pcap, "-Y", display_filter, "-T", "fields", "-e", "frame.number"])
    out = out.strip()
    if not out:
        return 0
    return len(out.splitlines())

def get_total_frames(pcap):
    """
    Total de frames:
    - preferencia: capinfos si existe
    - fallback: tshark listando frame.number y contar líneas
    """
    try:
        # capinfos -c -> packets
        out = run(["capinfos", "-c", pcap])
        # Busca una línea tipo: "Number of packets:   1234"
        for line in out.splitlines():
            if "Number of packets" in line:
                digits = "".join(ch for ch in line if ch.isdigit())
                return int(digits) if digits else 0
    except Exception:
        pass

    out = run(["tshark", "-r", pcap, "-T", "fields", "-e", "frame.number"])
    out = out.strip()
    return 0 if not out else len(out.splitlines())

def get_first_last_ts(pcap):
    first_ts = run(["tshark", "-r", pcap, "-T", "fields", "-e", "frame.time_epoch", "-c", "1"]).strip()
    if not first_ts:
        return "", ""
    # último timestamp: tail -n 1 equivalente
    last_out = run(["tshark", "-r", pcap, "-T", "fields", "-e", "frame.time_epoch"])
    last_out = last_out.strip()
    last_ts = last_out.splitlines()[-1] if last_out else ""
    return first_ts, last_ts

@app.route("/analyze", methods=["POST"])
def analyze():
    pcap = request.json.get("pcap") if request.is_json else None
    if not pcap:
        return jsonify({"error": "Falta campo 'pcap'"}), 400

    # Si te pasan ruta relativa, permitir buscar dentro de CAPTURE_DIR
    if not os.path.isabs(pcap):
        pcap = os.path.join(CAPTURE_DIR, pcap)

    if not os.path.exists(pcap):
        return jsonify({"error": "PCAP no válido", "pcap": pcap}), 400

    frames_total = get_total_frames(pcap)
    first_ts, last_ts = get_first_last_ts(pcap)

    tcp_count = count_frames_with_filter(pcap, "tcp")
    udp_count = count_frames_with_filter(pcap, "udp")

    modbus_count = count_frames_with_filter(pcap, "modbus")

    func_codes = []
    if modbus_count > 0:
        out = run(["tshark", "-r", pcap, "-Y", "modbus", "-T", "fields", "-e", "modbus.func_code"])
        func_codes = sorted({x.strip() for x in out.splitlines() if x.strip()})

    tcp_conv = run(["tshark", "-r", pcap, "-q", "-z", "conv,tcp"])
    udp_conv = run(["tshark", "-r", pcap, "-q", "-z", "conv,udp"])

    return jsonify({
        "pcap": pcap,
        "analysis_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "frames_total": frames_total,
        "first_ts_epoch": first_ts,
        "last_ts_epoch": last_ts,
        "l4_counts": {"tcp": tcp_count, "udp": udp_count},
        "modbus": {
            "detected": modbus_count > 0,
            "frames": modbus_count,
            "func_codes": func_codes
        },
        "conversations": {
            "tcp": tcp_conv,
            "udp": udp_conv
        }
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
