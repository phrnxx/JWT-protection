from flask import Flask, jsonify
from flask_smorest import Api
from flask_jwt_extended import JWTManager
from datetime import timedelta

from db import db
from blocklist import BLOCKLIST
from resources.item import blp as ItemBlueprint
from resources.auth import blp as AuthBlueprint

app = Flask(__name__)

app.config["API_TITLE"] = "Stores REST API"
app.config["API_VERSION"] = "v1"
app.config["OPENAPI_VERSION"] = "3.0.3"
app.config["OPENAPI_URL_PREFIX"] = "/"
app.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
app.config["OPENAPI_SWAGGER_UI_URL"] = "https://cdn.jsdelivr.net/npm/swagger-ui-dist/"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["PROPAGATE_EXCEPTIONS"] = True

app.config["JWT_SECRET_KEY"] = "секретний ключ"  
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1) 

db.init_app(app)
api = Api(app)
jwt = JWTManager(app)

@jwt.token_in_blocklist_loader
def check_if_token_in_blocklist(jwt_header, jwt_payload):
    return jwt_payload["jti"] in BLOCKLIST

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "message": "Термін дії токену закінчився.",
        "error": "token_expired"
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({
        "message": "Перевірка підпису не вдалась.",
        "error": "invalid_token"
    }), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({
        "description": "Запит не містить токену доступу.",
        "error": "authorization_required"
    }), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({
        "description": "Токен було відкликано.",
        "error": "token_revoked"
    }), 401

with app.app_context():
    db.create_all()

api.register_blueprint(ItemBlueprint)
api.register_blueprint(AuthBlueprint)

if __name__ == "__main__":
    app.run(debug=True)