import inotify.adapters
import inotify.constants
import subprocess

def monitor():
    i = inotify.adapters.Inotify()
    watch_mask = inotify.constants.IN_CLOSE_WRITE | inotify.constants.IN_DELETE
    i.add_watch('config', watch_mask)

    for event in i.event_gen(yield_nones=False):
        subprocess.run(['TF_IN_AUTOMATION=true','terraform', 'apply', '-auto-approve', '-input=false'])

