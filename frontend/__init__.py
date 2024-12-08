from flask import Flask
from frontend.routes import main_bp


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    app.register_blueprint(main_bp)

    return app
