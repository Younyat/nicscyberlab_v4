uninstall_ics_traffic_analysis.shfrom flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)
CAPTURE_DIR = "./captures"

@app.route("/analyze", methods=["POST"])
def analyze():
    pcap = request.json.get("pcap")

    if not pcap or not os.path.exists(pcap):
        return jsonify({"error": "PCAP no válido"}), 400

    # Contar TCP total
    tcp_total = subprocess.check_output(
        ["tshark", "-r", pcap, "-Y", "tcp", "-q", "-z", "io,phs"]
    ).decode(errors="ignore")

    # Contar Modbus TCP (puerto 502)
    modbus = subprocess.check_output(
        ["tshark", "-r", pcap, "-Y", "tcp.port == 502", "-q", "-z", "io,phs"]
    ).decode(errors="ignore")

    return jsonify({
        "pcap": pcap,
        "tcp_detected": "YES" if "TCP" in tcp_total else "NO",
        "modbus_detected": "YES" if "502" in modbus else "NO"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
