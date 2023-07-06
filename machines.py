from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

machines = Blueprint('machines', __name__)

@machines.route('/machines/', methods = ["GET"])
@jwt_required()
def user_manage_machines():

    # TODO: connect to proxmox and get machines
    active_machines = [{'name': 'Machine 1'},
                       {'name': 'Machine 2'}, 
                       {'name': 'Machine 3'}]
    
    response = jsonify(active_machines)
    return response