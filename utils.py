import os, time, math

def file_size(path):
    try:
        return os.path.getsize(path)
    except:
        return 0

def now_ts():
    return int(time.time())
