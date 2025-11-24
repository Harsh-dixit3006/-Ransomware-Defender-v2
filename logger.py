# logger.py
import logging, logging.handlers, os, json, time
LOG_DIR = os.path.join(os.getcwd(), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, 'rdefender.log')

logger = logging.getLogger('rdefender')
logger.setLevel(logging.DEBUG)

# File handler
fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
fh.setLevel(logging.DEBUG)
fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
fh.setFormatter(fmt)
logger.addHandler(fh)

# Console handler
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(fmt)
logger.addHandler(ch)

def json_event(event: dict):
    # append a JSON line to events.log
    path = os.path.join(LOG_DIR, 'events.jsonl')
    try:
        with open(path, 'a') as f:
            f.write(json.dumps({'ts': int(time.time()), **event}) + '\n')
    except Exception:
        pass
