from flask import Flask
from flask_cors import CORS


def create_app():
    """
    Factory de la app Flask.
    Se registrarán blueprints y configuración aquí.
    """
    app = Flask(__name__)
    
    CORS(app)

    # Los blueprints se registrarán más adelante
    try:
        from app_core.presentation.api import api_bp
        app.register_blueprint(api_bp)

        from app_core.infrastructure.dashboard.dashboard_F35 import dashboard_f35
        app.register_blueprint(dashboard_f35)

        from app_core.infrastructure.attack.ssh_launcher import attack_infra_bp
        # Esto registrará la ruta como: /api/hud/attack/launch
        app.register_blueprint(attack_infra_bp, url_prefix='/api/hud/attack')
        # ------------------------------------------------
        
        
        # Registramos el blueprint del sniffer que está en app_core/infrastructure/ics_traffic/traffic_api.py
        from app_core.infrastructure.ics_traffic.traffic_api import traffic_bp
        app.register_blueprint(traffic_bp)

       
         


        from app_core.infrastructure.host_tools_installer.host_tools_endpoints import host_tools_bp
        # Lo registramos con el prefijo /api/host
        app.register_blueprint(host_tools_bp, url_prefix='/api/host')
        print("[OK] Host Tools Blueprint cargado correctamente")




        from app_core.presentation.api import api_bp

        app.register_blueprint(api_bp, url_prefix='/api')

    except Exception:
        # Permite iniciar mientras se migra código.
        pass

    return app
