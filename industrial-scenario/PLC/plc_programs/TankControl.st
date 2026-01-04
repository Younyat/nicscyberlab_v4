PROGRAM TankSimple
  VAR
    (* Actuador *)
    openOutletValve AT %QX0.1 : BOOL;

    (* Sensor digital de estado *)
    outletValveOpenStatus AT %QX0.3 : BOOL;

    (* Actuador *)
    openInletValve AT %QX0.4 : BOOL;

    (* Sensor digital de estado *)
    inletValveOpenStatus AT %QX0.5 : BOOL ;



    (* Sensor analógico *)
    level AT %QW2 : INT;

    (* Nivel máximo / umbral *)
    level_max AT %QW3 : INT;

    airValveOpenStatus AT %QX0.6 : BOOL;
  END_VAR
  


  (* ------------------------------
     LÓGICA SIMPLE DEL TANQUE
     ------------------------------ *)

  (* Si el nivel alcanza o supera el máximo → vaciar *)
  IF level > level_max AND airValveOpenStatus THEN
    openOutletValve := TRUE;
    outletValveOpenStatus := TRUE;
    openInletValve := FALSE;
    inletValveOpenStatus := FALSE;
    level := level - 1;
  END_IF;

 IF level < level_max AND airValveOpenStatus THEN
    openOutletValve := FALSE;
    outletValveOpenStatus := FALSE;
    openInletValve := TRUE;
    inletValveOpenStatus := TRUE;
    level := level + 1;
  END_IF;


  IF level = level_max  THEN
    openOutletValve := FALSE;
    outletValveOpenStatus := FALSE;
    openInletValve := FALSE;
    inletValveOpenStatus := FALSE;
  END_IF;

 



  IF level < 0 THEN level := 0; END_IF;
  IF level > 99 THEN level := 100; END_IF;
END_PROGRAM


CONFIGURATION Config0
  RESOURCE Res0 ON PLC
    TASK task0(INTERVAL := T#100ms, PRIORITY := 0);
    PROGRAM P0 WITH task0 : TankSimple;
  END_RESOURCE
END_CONFIGURATION
