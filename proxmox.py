from proxmoxer import ProxmoxAPI
from dotenv import load_dotenv
from urllib3.exceptions import InsecureRequestWarning
import os, requests

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
load_dotenv()

proxmox = ProxmoxAPI(os.getenv('PROXMOX_URL'), user=os.getenv('PROXMOX_USER'), password=os.getenv('PROXMOX_PASS'), verify_ssl=False)


#### GET Methods ########################################

def get_system_resources():
    #return proxmox.cluster.metrics.get()
    proxmox.nodes('proxmox').rrddata.get(timeframe='hour')

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

def create_vm(user, vm_name, opt={}):
    vmids = []
    for machine in get_all_vms():
        vmids.append(machine['vmid'])
    vm_id = 100
    while vm_id in vmids:
        vm_id += 1
    print(f"Creating VM {vm_name} with ID {vm_id}...")
    opt['name'] = vm_name
    opt['description'] = "\n\n__ " + user + " __" if 'description' not in opt else opt['description'] + "\n\n__ " + user + " __"
    return proxmox.nodes('proxmox').qemu.post(vmid=vm_id, **opt)

def delete_vm(vm_id):
    if vm_id:
        return proxmox.nodes('proxmox').qemu(vm_id).delete()
    return None
    

# print(get_system_resources())
# print(get_all_vms())
