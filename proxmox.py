from proxmoxer import ProxmoxAPI
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timedelta
from math import trunc
import os, requests

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
load_dotenv()

proxmox = ProxmoxAPI(os.getenv('PROXMOX_URL'), user=os.getenv('PROXMOX_USER'), password=os.getenv('PROXMOX_PASS'), verify_ssl=False)


#### GET Methods ########################################

def get_system_resources():
    #return proxmox.cluster.metrics.get()
    return proxmox.nodes('proxmox').rrddata.get(timeframe='hour', cf='AVERAGE')

def get_all_vms():
    return proxmox.nodes('proxmox').qemu.get()

def get_user_vms(user: str):
    uservms = []
    for machine in get_all_vms():
        machine_config = proxmox.nodes('proxmox').qemu(machine['vmid']).config.get()
        #print(machine_config)
        if 'description' in machine_config and user in machine_config['description']:
            uservms.append(machine)
    return uservms

def get_vm_from_name(vm_name):
    for machine in get_all_vms():
        if vm_name in machine['name']:
            return machine
        
def get_vm_status(vm_id):
    if vm_id:
        return proxmox.nodes('proxmox').qemu(vm_id).status.current.get()

def get_new_vm_id():
    vmids = []
    for machine in get_all_vms():
        vmids.append(machine['vmid'])
    vm_id = 100
    while vm_id in vmids:
        vm_id += 1
    return vm_id

def create_vm(user, vm_name, opt={}):
    vmids = []
    vm_id = get_new_vm_id()
    print(f"Creating VM {vm_name} with ID {vm_id}...")
    opt['name'] = vm_name
    opt['description'] = "\n\n__ " + user + " __" if 'description' not in opt else opt['description'] + "\n\n__ " + user + " __"
    return proxmox.nodes('proxmox').qemu.post(vmid=vm_id, **opt)

def delete_vm(vm_id):
    if vm_id:
        return proxmox.nodes('proxmox').qemu(vm_id).delete()
    return None
    
def connectVM(user: str, vmid: int):
    pmuser = f"{user}{vmid}@pve"
    proxmox.access.users.put(userid=pmuser,password=pmuser,expires=trunc(datetime.now() + timedelta(hours=2)))
    proxmox.access.acl.put(path=f"/vms/{vmid}",roles="VNCUser",users=pmuser)
    ticket = proxmox.access.ticket.post(username=pmuser,password=pmuser)
    if not ticket:
        return False
    vncticket = proxmox.nodes('proxmox').qemu(f'{vmid}').vncproxy.post(websocket=1)
    if 'upid' in vncticket:
        return True
    vncconnect = proxmox.nodes('proxmox').qemu(f'{vmid}').vncwebsocket(vncticket=ticket['ticket'],port=vncticket['port'])

# print(get_system_resources())
# print(get_all_vms())
