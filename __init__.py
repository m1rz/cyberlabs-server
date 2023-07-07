#!/usr/bin/env python3
from flask import Flask, request, jsonify, current_app
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from flask_socketio import SocketIO
from pymongo import MongoClient
from datetime import timedelta
import hashlib
import secrets
import string

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = ''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(64))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config['DATABASE_CONN_STRING'] = "mongodb://root:cyberlabs@localhost:27017/"
app.config['DATABASE_NAME'] = "cyberlabs"
cors = CORS(app)
jwt = JWTManager(app)
sockio = SocketIO(app, origins=["https://cyberlabs.surge.sh"])

from auth import auth
from admin import admin
from machines import machines
from sockmanager import create_sockmanager

@jwt.user_lookup_loader
def user_lookup_db(header, data):
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]
        check = db.users.find_one({"username": f"{data['sub']}"})

    return check if check else False
        

app.register_blueprint(auth)
app.register_blueprint(admin, url_prefix='/admin')
app.register_blueprint(machines)
sock = create_sockmanager(sockio)
app.register_blueprint(sock)

@app.route('/')
@jwt_required()
def home():
    current_user = get_jwt_identity()
    res = {
        'response': f'Hello, {current_user}',
    }
    return jsonify(res)

if __name__ == '__main__':
    sockio.run(app)