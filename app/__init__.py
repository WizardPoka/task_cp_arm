# __init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from app.config import Config
from app.models import db
from app.routes import bp as routes_bp
from flasgger import Swagger
# Инициализация Swagger

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    db.init_app(app)
    jwt = JWTManager(app)
    migrate = Migrate(app, db)

    app.register_blueprint(routes_bp)


    
    # Конфигурация Swagger для поддержки JWT авторизации
    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "Your API",
            "description": "API documentation with JWT authentication",
            "version": "1.0.0"
        },
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme. Example: 'Authorization: Bearer {token}'"
            }
        },
        "security": [
            {
                "Bearer": []
            }
        ]
    }

    swagger = Swagger(app, template=swagger_template)
    
    # swagger = Swagger(app)
    
    return app
