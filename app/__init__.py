from flask import Flask
from flask_login import LoginManager
from config import Config

# Initialize LoginManager here so it's accessible to blueprints
login_manager = LoginManager()

@login_manager.user_loader
def load_user(user_id):
    """Loads a user object from the users dictionary."""
    from users import users
    return users.get(user_id)

def create_app():
    """Application factory function."""
    app = Flask(__name__)
    app.config.from_object(Config)

    login_manager.init_app(app)

    # Import and register the blueprints for each staff type
    from .it_staff import it_bp
    from .hospital_staff import hospital_bp
    
    app.register_blueprint(it_bp)
    app.register_blueprint(hospital_bp)

    return app