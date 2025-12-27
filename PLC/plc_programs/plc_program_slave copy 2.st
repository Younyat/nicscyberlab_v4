PROGRAM prog0
  VAR
    sensor_ext AT %IW100 : INT; 
    v_llenar   AT %MW1   : INT; 
    v_vaciar   AT %MW2   : INT;
  END_VAR

  (* Esta lógica interna sí puede cambiar el valor de sensor_ext *)
  IF v_llenar = 1 THEN
      sensor_ext := sensor_ext + 5;
  END_IF;

  IF v_vaciar = 1 THEN
      sensor_ext := sensor_ext - 5;
  END_IF;
END_PROGRAM

CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK Main(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM Inst0 WITH Main : prog0;
  END_RESOURCE
END_CONFIGURATION