from flask import Flask
from flask_login import LoginManager
from config import Config

login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    from users import users
    return users.get(user_id)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    login_manager.init_app(app)
    from .it_staff import it_bp
    from .hospital_staff import hospital_bp
    app.register_blueprint(it_bp)
    app.register_blueprint(hospital_bp)
    return app