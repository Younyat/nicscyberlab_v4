class ModbusStateIntegrity:
    """
    Question:
    Is there evidence of unstable or inconsistent Modbus state?
    """

    def run(self, facts: dict) -> dict:
        industrial = facts.get("industrial", {})

        return {
            "question": "modbus_state_integrity",
            "answer": "DEGRADED" if industrial.get("timeouts") else "STABLE",
            "snapshots": len(industrial.get("snapshots", [])),
            "timeouts_detected": industrial.get("timeouts")
        }
