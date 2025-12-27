#!/usr/bin/env python3

from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import ModbusSequentialDataBlock
import time
import random
from threading import Thread

# ------------------------------------------------------------
# CONFIGURACIÓN
# ------------------------------------------------------------
MODBUS_PORT = 50502
HR_START = 0
HR_COUNT = 200        # Necesitamos al menos hasta HR100

# ------------------------------------------------------------
# DATASTORE MODBUS
# ------------------------------------------------------------
store = ModbusSlaveContext(
    hr=ModbusSequentialDataBlock(HR_START, [0] * HR_COUNT)
)

# single=True → OpenPLC ignora Unit ID
context = ModbusServerContext(slaves=store, single=True)

# ------------------------------------------------------------
# SENSOR VIRTUAL
# ------------------------------------------------------------
def update_sensor(ctx):
    while True:
        value = random.randint(10, 50)

        # FC3 = Holding Registers
        # HR100  <-->  %IW100
        ctx[0].setValues(3, 100, [value])

        print(f"[SLAVE] HR100 (%IW100) actualizado → {value}")
        time.sleep(2)

Thread(target=update_sensor, args=(context,), daemon=True).start()

# ------------------------------------------------------------
# ARRANQUE DEL SERVIDOR
# ------------------------------------------------------------
print(f"[SLAVE] Servidor Modbus TCP activo en 0.0.0.0:{MODBUS_PORT}")
StartTcpServer(context, address=("0.0.0.0", MODBUS_PORT))
