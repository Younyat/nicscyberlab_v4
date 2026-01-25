from datetime import datetime, timezone


class UnauthorizedModbusWrite:
    QUESTION_ID = "unauthorized_modbus_write"

    def run(self, facts: dict) -> dict:
        modbus_frames = facts.get("modbus_frames", [])

        suspicious = []
        for frame in modbus_frames:
            if frame.get("function_code") in (5, 6, 15, 16):  # Write operations
                suspicious.append(frame)

        verdict = "SUSPICIOUS_ACTIVITY" if suspicious else "NO_EVIDENCE"

        return {
            "question": self.QUESTION_ID,
            "analysis_utc": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "summary": {
                "total_modbus_frames": len(modbus_frames),
                "write_operations": len(suspicious)
            },
            "details": suspicious,
            "forensic_note": (
                "Modbus write operations are not inherently malicious. "
                "Contextual validation is required."
            )
        }
