import inotify.adapters
import inotify.constants
import subprocess

def monitor():
    i = inotify.adapters.Inotify()
    watch_mask = inotify.constants.IN_CLOSE_WRITE | inotify.constants.IN_DELETE
    i.add_watch('config/proxmox', watch_mask)

    for event in i.event_gen(yield_nones=False):
        (_, type_names, path, filename) = event
        if not 'terraform.tfstate' in filename and not 'terraform.tfstate.backup' in filename:
            subprocess.run(['terraform', 'apply', '-auto-approve', '-input=false'])

if __name__ == '__main__':
    monitor()

