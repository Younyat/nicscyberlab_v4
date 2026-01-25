from questions.questions.unauthorized_modbus_write import UnauthorizedModbusWrite
from questions.questions.modbus_state_integrity import ModbusStateIntegrity

QUESTION_REGISTRY = {
    "unauthorized_modbus_write": UnauthorizedModbusWrite,
    "modbus_state_integrity": ModbusStateIntegrity,
}
