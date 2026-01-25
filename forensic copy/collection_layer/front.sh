curl -s -X POST http://127.0.0.1:5059/collect \
  -H 'Content-Type: application/json' \
  -d '{
    "experiment_id": "EXP-PLC-01",
    "scenario_id": "SCADA-PLC-DEBIAN",
    "trigger_type": "manual",
    "trigger_ref": "operator_request",
    "policy": {
      "sources": [{"id":"host-forensic-node","type":"local"}],
      "network": {"enabled": true, "seconds": 20, "bpf": "tcp and port 502 and host 10.0.2.22"},
      "system": {"enabled": true},
      "industrial": {"enabled": true, "modbus": {"host":"10.0.2.22","port":502,"unit":1,"start":0,"count":10}}
    }
  }' | jq
