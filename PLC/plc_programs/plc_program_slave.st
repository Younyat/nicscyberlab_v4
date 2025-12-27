PROGRAM prog0
  VAR
    sensor_ext AT %IW100 : INT;   (* HR100 *)
    actuator   AT %MW0   : INT;
  END_VAR

  actuator := sensor_ext * 2;
END_PROGRAM


CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION
