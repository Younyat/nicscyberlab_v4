import subprocess
import logging
import os
import sys
import yaml

from flask import Flask
from flask_cors import CORS

from app_core.config.logging import setup_logging
from app_core.presentation.api import api_bp


# ===== Configurar logging =====
log_file = "app.log"
logger = setup_logging(log_file)


class StreamToLogger(object):
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message.rstrip() != "":
            self.logger.log(self.level, message.rstrip())

    def flush(self):
        pass


logging.basicConfig(level=logging.INFO)
sys.stdout = StreamToLogger(logger, logging.INFO)
sys.stderr = StreamToLogger(logger, logging.ERROR)


# === Generar y cargar credenciales OpenStack ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
GEN_SCRIPT = os.path.join(BASE_DIR, "generate_app_cred_openrc_from_clouds.sh")
OPENRC_PATH = os.path.join(BASE_DIR, "admin-openrc.sh")
KOLLA_CLOUDS = "/etc/kolla/clouds.yaml"
DEFAULT_CLOUD = "kolla-admin"


def load_clouds_creds(clouds_path: str, cloud_name: str) -> dict:
    """Lee /etc/kolla/clouds.yaml y devuelve las credenciales del cloud elegido."""
    with open(clouds_path, "r") as f:
        data = yaml.safe_load(f) or {}

    clouds = data.get("clouds") or {}
    cloud_cfg = clouds.get(cloud_name)
    if not cloud_cfg:
        raise ValueError(f"No se encontró el cloud '{cloud_name}' en {clouds_path}")

    auth = cloud_cfg.get("auth") or {}
    return {
        "OS_AUTH_URL": auth.get("auth_url"),
        "OS_USERNAME": auth.get("username"),
        "OS_PASSWORD": auth.get("password"),
        "OS_PROJECT_NAME": auth.get("project_name", "admin"),
        "OS_PROJECT_DOMAIN_NAME": auth.get("project_domain_name", "Default"),
        "OS_USER_DOMAIN_NAME": auth.get("user_domain_name", "Default"),
        "OS_REGION_NAME": cloud_cfg.get("region_name", "RegionOne"),
        "OS_INTERFACE": cloud_cfg.get("interface", "public"),
    }


def write_openrc(creds: dict, output_path: str):
    """Escribe un admin-openrc.sh a partir de credenciales ya leídas."""
    content = [
        "#!/bin/bash",
        "# Archivo generado automáticamente desde /etc/kolla/clouds.yaml",
        "",
        "unset OS_AUTH_TYPE",
        "unset OS_AUTH_URL",
        "unset OS_USERNAME",
        "unset OS_PASSWORD",
        "unset OS_USER_DOMAIN_NAME",
        "unset OS_PROJECT_NAME",
        "unset OS_PROJECT_DOMAIN_NAME",
        "unset OS_REGION_NAME",
        "unset OS_APPLICATION_CREDENTIAL_ID",
        "unset OS_APPLICATION_CREDENTIAL_SECRET",
        "unset OS_APPLICATION_CREDENTIAL_NAME",
        "",
    ]

    for key, value in creds.items():
        if value:
            content.append(f"export {key}={value}")

    content.append('echo "Credenciales OpenStack cargadas"')

    with open(output_path, "w") as f:
        f.write("\n".join(content) + "\n")

    os.chmod(output_path, 0o755)
    logger.info(f" admin-openrc.sh generado en {output_path}")


def ensure_openrc() -> bool:
    """
    Asegura que exista admin-openrc.sh.
    1) Si ya existe, no lo toca.
    2) Intenta generarlo en Python desde /etc/kolla/clouds.yaml (sin tmp/ni apt).
    3) Como último recurso, llama al script legacy si existe.
    """
    if os.path.exists(OPENRC_PATH):
        logger.info(f" admin-openrc.sh ya existe en {OPENRC_PATH}, se reutiliza.")
        return True

    try:
        if os.path.exists(KOLLA_CLOUDS):
            creds = load_clouds_creds(KOLLA_CLOUDS, DEFAULT_CLOUD)
            write_openrc(creds, OPENRC_PATH)
            return True
        else:
            logger.warning(f" No se encontró {KOLLA_CLOUDS}. Se probará el script legacy.")
    except Exception as e:
        logger.warning(f" Falló la generación Python de admin-openrc.sh: {e}")

    try:
        if os.path.exists(GEN_SCRIPT):
            logger.info(f" Ejecutando script legacy de credenciales: {GEN_SCRIPT}")

            if not os.access(GEN_SCRIPT, os.X_OK):
                os.chmod(GEN_SCRIPT, 0o755)
                logger.info(f" Permisos de ejecución otorgados a {GEN_SCRIPT}")

            proc = subprocess.run(
                ["bash", GEN_SCRIPT],
                cwd=BASE_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False
            )

            logger.info(" Salida del script:")
            logger.info(proc.stdout)
            if proc.stderr:
                logger.warning(" Errores durante la ejecución del script:")
                logger.warning(proc.stderr)

            if proc.returncode == 0 and os.path.exists(OPENRC_PATH):
                logger.info(f" Script ejecutado correctamente. Archivo generado: {OPENRC_PATH}")
                return True
            else:
                logger.warning(f" No se generó correctamente {OPENRC_PATH}. Código de salida: {proc.returncode}")
        else:
            logger.warning(f" Script {GEN_SCRIPT} no encontrado. Se omite la generación automática.")
    except Exception as e:
        logger.error(f" Error al ejecutar el script {GEN_SCRIPT}: {e}", exc_info=True)

    return False


ensure_openrc()

if os.path.exists(OPENRC_PATH):
    try:
        with open(OPENRC_PATH) as f:
            for line in f:
                line = line.strip()
                if line.startswith("export "):
                    key, value = line.replace("export ", "").split("=", 1)
                    os.environ[key] = value
        logger.info(f" Credenciales OpenStack cargadas desde {OPENRC_PATH}")
    except Exception as e:
        logger.error(f" Error al cargar {OPENRC_PATH}: {e}")
else:
    logger.warning(f" Archivo {OPENRC_PATH} no encontrado. Los comandos OpenStack pueden fallar.")


def create_app():
    """
    Factory mínima que registra el blueprint API.
    """
    flask_app = Flask(__name__)
    CORS(flask_app)
    flask_app.register_blueprint(api_bp)

    try:
        from app_core.infrastructure.forge_vi_dashboard.endpoints import forge_vi_bp
        flask_app.register_blueprint(forge_vi_bp)
        logger.info("[OK] FORGE-VI Scientific Dashboard Blueprint cargado correctamente")
    except Exception as e:
        logger.warning(f"[WARN] forge_vi_bp no cargado: {e}")

    return flask_app


app = create_app()

if __name__ == "__main__":
    app.run(host="localhost", port=5001, debug=True)
