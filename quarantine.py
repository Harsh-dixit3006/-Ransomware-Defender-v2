# quarantine.py
import os, shutil, time, json

LOGFILE = os.path.join(os.getcwd(), 'logs', 'recovery_log.json')

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def quarantine_files(file_paths, base_quarantine_dir):
    """Quarantine files by moving them to quarantine directory.
    
    Args:
        file_paths: List of file paths to quarantine
        base_quarantine_dir: Directory to move files to
    
    Returns:
        List of tuples (original_path, dest_path, status)
    """
    ensure_dir(base_quarantine_dir)
    moved = []
    timestamp = int(time.time())
    
    for idx, p in enumerate(file_paths):
        if not p or not isinstance(p, str):
            moved.append((p, None, 'invalid_path'))
            continue
            
        # Check if file exists
        if not os.path.exists(p):
            moved.append((p, None, 'file_not_found'))
            continue
        
        # Skip if it's a directory
        if os.path.isdir(p):
            moved.append((p, None, 'is_directory'))
            continue
        
        try:
            # Create unique filename with timestamp and index
            rel = os.path.basename(p)
            # Sanitize filename
            safe_name = "".join(c for c in rel if c.isalnum() or c in "._- ")
            dest = os.path.join(base_quarantine_dir, f"{timestamp}_{idx}_{safe_name}")
            
            # Ensure destination doesn't exist
            counter = 0
            base_dest = dest
            while os.path.exists(dest):
                counter += 1
                name, ext = os.path.splitext(base_dest)
                dest = f"{name}_{counter}{ext}"
            
            status = 'unknown'
            try:
                # Try to move first (atomic operation)
                shutil.move(p, dest)
                status = 'moved'
            except PermissionError as e:
                # File might be locked, try copy then remove
                try:
                    shutil.copy2(p, dest)
                    try:
                        os.remove(p)
                        status = 'copied_and_removed'
                    except PermissionError:
                        status = 'copied_but_remove_failed_permission'
                    except Exception as e2:
                        status = f'copied_but_remove_failed:{str(e2)}'
                except Exception as e:
                    dest = None
                    status = f'copy_failed:{str(e)}'
            except OSError as e:
                # Handle other OS errors
                try:
                    shutil.copy2(p, dest)
                    try:
                        os.remove(p)
                        status = 'copied_and_removed'
                    except Exception as e2:
                        status = f'copied_but_remove_failed:{str(e2)}'
                except Exception as e3:
                    dest = None
                    status = f'failed:{str(e3)}'
            except Exception as e:
                dest = None
                status = f'failed:{str(e)}'
            
            moved.append((p, dest, status))
            
        except Exception as e:
            moved.append((p, None, f'failed:{str(e)}'))
    
    # write to recovery log
    log_entry = {
        'timestamp': timestamp,
        'moved': moved,
        'total_files': len(file_paths),
        'successful': len([m for m in moved if m[2] in ('moved', 'copied_and_removed')])
    }
    try:
        # ensure logs dir exists
        logdir = os.path.dirname(LOGFILE)
        if logdir:
            os.makedirs(logdir, exist_ok=True)
        with open(LOGFILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        # Log error but don't fail quarantine
        import logging
        logging.error(f"Failed to write recovery log: {e}")
    
    return moved

def list_recovery_log():
    try:
        with open(LOGFILE, 'r') as f:
            return f.read().splitlines()
    except:
        return []
