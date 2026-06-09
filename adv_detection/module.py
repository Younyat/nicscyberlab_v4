from __future__ import annotations

from flask import Flask

from .routes import adv_detection_bp


def register_module(app: Flask) -> None:
    app.register_blueprint(adv_detection_bp)