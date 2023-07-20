from base64 import b64decode
import hashlib
import json
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import jwt_required, current_user
from pymongo import MongoClient
from functools import reduce

from auth import get_user
from proxmox import get_system_resources

admin = Blueprint('admin', __name__)

def authenticate_admin(req):
    token = req.headers['Authorization']
    if not token: return False
    token = token.split(" ")[1]
    if token is not None:
        user = json.loads(b64decode(token.split('.')[1]).decode())['sub']
        user_obj = get_user(user)
        if user_obj and user_obj['role'] == 'admin':
            return True
    return False

@admin.route('/user/create/', methods=['POST'])
@jwt_required()
def admin_create_user():
    if not 'username' in request.form or not 'password' in request.form:
        return jsonify({ 
            'result': 'error',
            'reason': 'Incomplete credentials', 
            },), 403

    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        if db.users.find_one({"username": f"{request.form['username']}"}):
            return jsonify({ 
                'result': 'error',
                'reason': 'Username taken', 
            },), 403

        creds = {
            "username": f"{request.form['username']}",
            "role": f"{request.form['role']}",
            "password": f"{hashlib.sha256(str(request.form['password']).encode()).hexdigest()}",
        }
        
        transact = db.users.insert_one(creds)
        res = {
            'result': 'success',
            'userId': f'{transact.inserted_id}',
        }

    return jsonify(res)

@admin.route('/user/<user>', methods = ['DELETE'])
@jwt_required()
def delete_user(user):
    if authenticate_admin(request):
        with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
            db = client[current_app.config['DATABASE_NAME']]
            res = db.users.delete_one({"username": f"{user}"})
            if res.acknowledged:
                return jsonify({
                    "result": "success",
                    "deleted_lines": f"{res.deleted_count}",
                })
    return jsonify({
        "result": "Failed to delete user."
    })

@admin.route('/stats', methods = ['GET'])
@jwt_required()
def server_stats():
    if authenticate_admin(request):
        stats = {}
        data = get_system_resources()
        for key in data[0].keys():
            stats[key] = reduce(lambda a, b: a + b.get(key), data, 0) / len(data)
        return jsonify(stats)
