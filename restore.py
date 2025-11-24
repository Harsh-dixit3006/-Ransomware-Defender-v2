# restore.py
# Simple command-line utility to restore files from quarantine using the recovery log.
import os, json, shutil, argparse

LOGFILE = 'recovery_log.json'

def list_entries():
    if not os.path.exists(LOGFILE):
        print('No recovery log found:', LOGFILE)
        return
    with open(LOGFILE, 'r') as f:
        for i,line in enumerate(f):
            try:
                j = json.loads(line)
                moved = j.get('moved', [])
                print(f'Entry {i}: ts={j.get("timestamp")}, moved={len(moved)} files')
                # show a summary of statuses when available
                statuses = []
                for m in moved[:5]:
                    try:
                        # support both (orig,dest) and (orig,dest,status)
                        if len(m) >= 3:
                            statuses.append(m[2])
                        else:
                            statuses.append('moved')
                    except Exception:
                        statuses.append('unknown')
                if statuses:
                    print('   sample statuses:', ','.join(statuses))
            except Exception:
                print('Malformed line', i)

def restore(entry_idx, out_dir=None):
    with open(LOGFILE, 'r') as f:
        lines = f.readlines()
    if entry_idx < 0 or entry_idx >= len(lines):
        print('Entry index out of range')
        return
    entry = json.loads(lines[entry_idx])
    moved = entry.get('moved', [])
    for item in moved:
        # support either [orig, dest] or [orig, dest, status]
        try:
            if isinstance(item, (list, tuple)):
                if len(item) >= 2:
                    orig = item[0]
                    dest = item[1]
                    status = item[2] if len(item) >= 3 else 'moved'
                else:
                    print('Skipping malformed moved entry:', item)
                    continue
            else:
                print('Skipping non-list moved entry:', item)
                continue
        except Exception:
            print('Skipping malformed moved entry:', item)
            continue

        if not dest:
            print('Skipping (no dest recorded):', orig)
            continue
        target = os.path.join(out_dir or os.getcwd(), os.path.basename(orig))
        try:
            shutil.move(dest, target)
            print('Restored', dest, '->', target)
        except Exception as e:
            print('Failed restore:', e)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--restore', type=int, help='Entry index to restore')
    parser.add_argument('--out', help='Output directory for restore')
    args = parser.parse_args()
    if args.list:
        list_entries()
    elif args.restore is not None:
        restore(args.restore, args.out)
    else:
        parser.print_help()
