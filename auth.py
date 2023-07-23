from base64 import b64decode
import json
from flask import Blueprint, make_response, redirect, request, jsonify, current_app
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, current_user
from pymongo import MongoClient
from jinja2 import Environment, FileSystemLoader
from bson.objectid import ObjectId
import hashlib

from proxmox import connect_vm, get_new_vm_id

auth = Blueprint('auth', __name__)

env = Environment(loader=FileSystemLoader("config/templates/"))
new_machine = env.get_template("ubuntu-2204-server.j2")

def authenticate_user(token):
    if token is not None:
        user = json.loads(b64decode(token.split('.')[1]).decode())['sub']
        user_obj = get_user(user)
        if user_obj:
            return user_obj
    return False

@auth.route('/login/', methods = ['POST'])
def login():
    if not 'username' in request.form or not 'password' in request.form:
        return jsonify({ 
            'result': 'error',
            'reason': 'Missing username or password', 
            },), 403

    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]
        check = db.users.find_one({"username": f"{request.form['username']}"})
        if check:
            credcheck = {
                "username": f"{request.form['username']}",
                "password": f"{hashlib.sha256(str(request.form['password']).encode()).hexdigest()}",
            }
            if credcheck['username'] == check['username'] and credcheck['password'] == check['password']:
                res = jsonify({ 
                    'result': 'success',
                    'reason': 'Login success',
                    'access_token': create_access_token(identity=credcheck['username']), 
                },)
                return res

    res = { 
        'result': 'error',
        'reason': 'Incorrect username or password',
        }
    return jsonify(res), 403


@auth.route('/logout/', methods = ['GET'])
@jwt_required()
def logout():
    if current_user:
        logout_session(current_user['username'])
        return jsonify({'message': 'Successfully logged out.'})
    return jsonify({'message': 'Not logged in.'})




@auth.route('/register/', methods = ['POST'])
def register():
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
            "role": "user",
            "password": f"{hashlib.sha256(str(request.form['password']).encode()).hexdigest()}",
        }
        
        transact = db.users.insert_one(creds)
        res = {
            'result': 'success',
            'userId': f'{transact.inserted_id}',
        }

    return jsonify(res)

@auth.route('/user/')
@jwt_required()
def currentuser():
    user = current_user.copy()
    user.pop('_id')
    user.pop('password')
    return jsonify(user)
    """res = {
        'user': current_user.username,
        'role': current_user.password,
    }"""

@auth.route('/users/')
@jwt_required()
def get_all_users():
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        users = []
        db_users = db.users.find()

        for user in db_users:
            user.pop('_id')
            user.pop('password')
            users.append(user)

        return users
    
@auth.route('/user/<user>', methods = ['PUT','DELETE'])
def delete_user(user):
    if request.method == 'PUT':
        if request.form['oldpw'] and request.form['newpw']:
            with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
                    db = client[current_app.config['DATABASE_NAME']]
                    res = db.users.update_one({
                        "username": user,
                        "password": f"{hashlib.sha256(str(request.form['oldpw']).encode()).hexdigest()}",
                    }, {"$set": {
                        "password": f"{hashlib.sha256(str(request.form['newpw']).encode()).hexdigest()}"
                    }})
                    if res.matched_count == 1:
                        return jsonify({
                            "result": "success"
                        })
        return jsonify({
            "result": "failure"
        })
                        

    elif request.method == 'DELETE':
        auth_header = request.headers['Authorization']
        if auth_header:
            user_obj = authenticate_user(auth_header.split(" ")[1])
            if user_obj and user_obj['role'] == 'admin':
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
    
@auth.route('/connect', methods = ['GET'])
@jwt_required()
def connect_machine():
    if not 'vmid' in request.args:
        return jsonify({
            "result": "error",
            "reason": "no vmid"
        })
    res = connect_vm(current_user['username'], int(request.args.get('vmid')))
    if res and 'ticket' in res:
        resp = make_response(res)
        resp.set_cookie('PVEAuthCookie', res.get('PVEAuthCookie'))
        return resp

@auth.route('/connect2', methods = ['GET'])
def connect_machine_2():
    if not 'vmid' in request.args or not 'username' in request.args:
        return jsonify({
            "result": "error",
            "reason": "not enough creds"
        })
    res = connect_vm(request.args.get('username'), int(request.args.get('vmid')))
    if res and 'ticket' in res:
        resp = make_response(redirect(f"/proxmox/?console=kvm&novnc=1&vmid={request.args.get('vmid')}&vmname=server&node=proxmox&resize=off"))
        resp.set_cookie('PVEAuthCookie', res.get('PVEAuthCookie'))
        return resp
    
@auth.route('/cookies', methods = ['GET'])
def check_cookies():
    resp = make_response({'cookie': request.cookies.get('PVEAuthCookie')})
    resp.set_cookie('PVEAuthCookie', "test")
    return resp

def login_session(user_name, sid):
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        login = db.sessions.insert_one({
            'name': f'{user_name}',
            'sid': f'{sid}',
        })
        return True if login.acknowledged else False

def logout_session(user_name):
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        logout = db.sessions.delete_one({'name': f'{user_name}'})
        return True if logout.acknowledged else False

def get_user_from_sid(sid):
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        user = db.sessions.find_one({"sid": f"{sid}"})
        if user:
            return user
        return False

def get_user(user_name):
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        user = db.users.find_one({"username": f"{user_name}"})
        if user:
            return user
        return False
    
def get_user_machines(user):
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        machines = db.machines.find({"owner": ObjectId(user['_id'])}, {'_id': False, 'owner': False})
        if machines:   
            machines_list = []
            for machine in machines:
                machines_list.append(machine)
            return machines_list
        return False
    
def get_all_machines():
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        machines = db.machines.find({}, {'_id': False, 'owner': False})
        if machines:   
            machines_list = []
            for machine in machines:
                machines_list.append(machine)
            return machines_list
        return False

def create_user_machine(user, data: dict):
    machine_info = data.copy()
    machine_desc = machine_info.pop('desc') + "\n\n__ " + user['username'] + " __"
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        new_vmid = get_new_vm_id()
        options = {
            "vmid": new_vmid,
            "name": f"{machine_info.pop('name')}",
            "desc": f"{machine_desc}",
            "owner": ObjectId(user['_id']),
            "state": "Stopped",
            "params": machine_info,
        }

        machine_plan = new_machine.render({
            **options,
            **(machine_info.get("data", {})),
            'username': user["username"],
            'password': user['username'],
            'vmid': new_vmid
        })

        file_name = user["username"] + "-" + options.get("name") + ".tf"
        print(f"Writing Terraform plan to {file_name}...")

        with open("config/proxmox/" + file_name, "w") as plan_file:
            plan_file.write(machine_plan)

        machine = db.machines.insert_one(options)
        return machine.inserted_id
    
def get_machine_templates():
    with MongoClient(current_app.config['DATABASE_CONN_STRING']) as client:
        db = client[current_app.config['DATABASE_NAME']]

        templates = db.templates.find({}, {'_id': False})
        if templates:   
            templates_list = []
            for template in templates:
                templates_list.append(template)
            return templates_list
        return False