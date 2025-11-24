import os, time, json, shutil
from monitor import MonitorController

root = os.getcwd()
watch_dir = os.path.join(root, 'test_watch')
qdir = os.path.join(root, 'quarantine_test')
logs_dir = os.path.join(root, 'logs')

# Prepare directories
os.makedirs(watch_dir, exist_ok=True)
os.makedirs(qdir, exist_ok=True)
os.makedirs(logs_dir, exist_ok=True)

# Clean previous test files
for pdir in (watch_dir, qdir):
    for fname in list(os.listdir(pdir)):
        fp = os.path.join(pdir, fname)
        try:
            if os.path.isfile(fp):
                os.remove(fp)
        except Exception:
            pass

# Create several high-entropy files
files = []
for i in range(5):
    p = os.path.join(watch_dir, f'test_file_{i}.bin')
    with open(p, 'wb') as f:
        f.write(os.urandom(8192))
    files.append(p)

# Low threshold cfg to force detection
cfg = {
    'window_seconds': 60,
    'check_interval': 1,
    'modified_threshold': 1,
    'entropy_threshold': 1.0,
    'high_entropy_count': 1,
    'sample_entropy_count': 5,
    'process_suspicion_score': 1000,
    'quarantine_dir': qdir,
    'auto_quarantine': True,
    'detection_score_threshold': 10
}

# Callback to collect messages
messages = []
def cb(msg):
    print('[GUI CALLBACK]', msg)
    messages.append(msg)

mc = MonitorController([watch_dir], cfg, gui_callback=cb)

# Record events for created files
for p in files:
    mc.record_event(p)

# Run manual check
print('Running manual check...')
mc.check_now()

# Wait for background quarantine to run (give some time)
print('Waiting up to 10s for quarantine thread...')
for i in range(10):
    time.sleep(1)

# Read logs
rec_log = os.path.join(logs_dir, 'recovery_log.json')
events_log = os.path.join(logs_dir, 'events.jsonl')

print('\n=== Recovery log tail ===')
if os.path.exists(rec_log):
    with open(rec_log, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()
        for line in lines[-10:]:
            try:
                j = json.loads(line)
                print(json.dumps(j, indent=2))
            except Exception:
                print(line)
else:
    print('No recovery log found')

print('\n=== Events log tail ===')
if os.path.exists(events_log):
    with open(events_log, 'r', encoding='utf-8') as f:
        lines = f.read().splitlines()
        for line in lines[-20:]:
            try:
                j = json.loads(line)
                print(json.dumps(j, indent=2))
            except Exception:
                print(line)
else:
    print('No events log found')

print('\n=== Quarantine dir contents ===')
if os.path.exists(qdir):
    for rootdir, dirs, fnames in os.walk(qdir):
        for fname in fnames:
            print(os.path.join(rootdir, fname))
else:
    print('Quarantine dir missing')

print('\n=== GUI callback messages ===')
for m in messages:
    print(m)
