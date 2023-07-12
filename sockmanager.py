from flask import Blueprint, jsonify, request
from flask_socketio import SocketIO, emit
from flask_jwt_extended import jwt_required, current_user
from base64 import b64decode
from threading import Thread
import json
from admin import authenticate_admin

from auth import create_user_machine, get_all_machines, get_user, get_user_machines, login_session, get_user_from_sid
from packages import *
#from proxmox import *

def create_sockmanager(sockio: SocketIO):
    sockmanager = Blueprint('sockmanager', __name__)

    def authenticate_user(token):
        if token['token'] is not None:
            jwt = token['token'].split('.')[1]
            if not len(jwt) % 4 == 0:
                jwt += '=' * (4 - len(jwt) % 4) 
            user = json.loads(b64decode(jwt).decode())['sub']
            user_obj = get_user(user)
            if user_obj:
                return user_obj
        return False

    @sockio.on('connect')
    def client_connected(auth):
        emit("authenticate")

    @sockio.on('authenticate')
    def checkjwt(role):
        #print(role['token'])
        # if role['token'] is not None:
        #     user = json.loads(b64decode(role['token'].split('.')[1]).decode())['sub']
        #     if get_user(user):
        #         print(get_user(user)['role'])
        #         authenticated(user)
        user = authenticate_user(role)
        if user:
            print(user['role'])
            emit('confirm_auth', role['token'])
            authenticated(user)
        else:
            emit('confirm_auth', "0")
        return False
    
    @sockio.on('machines_brief')
    def active_machines_brief(user = None):
        if not user:
            user = get_user(get_user_from_sid(request.sid)['name'])

        machines = get_user_machines(user)
        # machines = get_user_vms(user['username'])
        # machines_brief = [{'name': m['name']} for m in machines]
        # emit('machines_brief', tuple(machines_brief))
        """ emit("machines_brief",(
        {'name': 'Active Machine 1'},
        {'name': 'Active Machine 2'},
        {'name': 'Active Machine 3'}))
        """
        emit("machines_brief", tuple(machines))

    @sockio.on('all_machines')
    def all_machines():
        user = get_user(get_user_from_sid(request.sid)['name'])
        if user and user['role'] == 'admin':
            machines = get_all_machines()
            emit("all_machines", tuple(machines))

    @sockio.on('machines')
    def active_machines(user):
        # machines = get_user_vms(user)
        # emit('machines', tuple(machines))
        emit("machines",(
        {'name': 'Active Machine 1'},
        {'name': 'Active Machine 2'},
        {'name': 'Active Machine 3'}))

    @sockio.on('templates')
    def all_templates():
        emit("templates",(
        {'name': 'Machine Template 1'},
        {'name': 'Machine Template 2'},
        {'name': 'Machine Template 3'}))

    @sockio.on('get_os_versions')
    def get_os_versions():
        print("Sending OS versions")
        emit('get_os_versions',list(get_ubuntu_versions().keys()))

    @sockio.on('get_os_packages')
    def get_os_packages(os_version_name):
        print("Sending packages for " + os_version_name[0])
        emit("os_packages", find_package(*os_version_name))
        """ res = Thread(target=lambda x: emit("os_packages", get_packages_by_version(x)), args=(os_version_name,)) """

    @sockmanager.route('/announce/', methods = ['POST'])
    @jwt_required()
    def make_announcement():
        if authenticate_admin(request):
            message = request.form['msg']
            if message:
                sockio.emit('announce', message)
                return jsonify({
                    'result': 'success',
                    'message': f'{message}',
                })
        return jsonify({
            'result': 'error',
            'reason': 'Failed to make announcement.',
        })
    
    @sockmanager.route('/machine/create/', methods = ['POST'])
    @jwt_required()
    def create_machine():
        request_data = request.get_json()
        if request_data:
            user = current_user
            transact_id = create_user_machine(user, request_data)
            return jsonify({
                'result': 'success',
                'id': f'{transact_id}',
            })
        return jsonify({
            'result': 'error',
            'reason': 'Failed to create machine.',
        })

    def authenticated(user):
        print(f"{request.sid} connected. Sending active machines list.")
        login_session(user['username'], request.sid)
        active_machines_brief(user)
        all_templates()
    
    return sockmanager