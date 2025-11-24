import os, time, threading, collections, shutil, stat
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from detector import file_entropy, is_ransomware_wave, score_files
from quarantine import quarantine_files

try:
    import psutil
except Exception:
    psutil = None

from logger import logger, json_event


class BehaviorHandler(FileSystemEventHandler):
    def __init__(self, controller):
        self.controller = controller

    def on_modified(self, event):
        if not event.is_directory:
            self.controller.record_event(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.controller.record_event(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.controller.record_event(event.dest_path)


class MonitorController:
    def __init__(self, watch_paths, cfg, gui_callback=None):
        self.watch_paths = watch_paths
        self.cfg = cfg
        self.gui_callback = gui_callback
        self._lock = threading.Lock()
        self.events = []
        self.observer = Observer()
        self.handler = BehaviorHandler(self)
        self.running = False
        # GUI event aggregation to prevent flooding the UI
        self._gui_event_count = 0
        self._last_gui_event_push = 0.0

        if 'auto_quarantine' not in self.cfg:
            self.cfg['auto_quarantine'] = False

    def start(self):
        for p in self.watch_paths:
            if os.path.exists(p):
                logger.info(f"Scheduling watch on: {p}")
                self.observer.schedule(self.handler, p, recursive=True)

        self.observer.start()
        self.running = True

        self._checker_thread = threading.Thread(target=self._checker, daemon=True)
        self._checker_thread.start()

        if self.gui_callback:
            self.gui_callback("Started monitoring")

    def stop(self):
        self.observer.stop()
        self.observer.join(timeout=2)
        self.running = False

        if self.gui_callback:
            self.gui_callback("Stopped monitoring")

    def record_event(self, path):
        ts = int(time.time())
        push_summary = None
        with self._lock:
            self.events.append((ts, path))
            # accumulate count for rate-limited GUI updates
            self._gui_event_count += 1
            now = time.time()
            if now - self._last_gui_event_push >= 1.0:
                push_summary = self._gui_event_count
                self._gui_event_count = 0
                self._last_gui_event_push = now

        logger.debug(f"Recorded event: {path}")
        json_event({'type': 'fs_event', 'path': path})

        # Rate-limited summary for GUI to avoid flooding
        if self.gui_callback and push_summary:
            self.gui_callback(f"Events observed: +{int(push_summary)} in last second")

    def _get_recent_events(self):
        cutoff = int(time.time()) - self.cfg['window_seconds']
        with self._lock:
            recent = [p for (t, p) in self.events if t >= cutoff]
            self.events = [(t, p) for (t, p) in self.events if t >= cutoff]
        return recent

    def _checker(self):
        while self.running:
            try:
                time.sleep(self.cfg['check_interval'])
                recent = self._get_recent_events()

                if not recent:
                    continue

                # Sample entropies
                entropies = []
                sample_count = min(len(recent), self.cfg['sample_entropy_count'])

                for p in recent[:sample_count]:
                    try:
                        e = file_entropy(p)
                    except Exception:
                        e = 0.0
                    entropies.append(e)

                score_report = score_files(len(recent), entropies, self.cfg)
                json_event({'type': 'scan_summary', 'score_report': score_report})

                if is_ransomware_wave(len(recent), entropies, self.cfg) or \
                   score_report.get('score', 0) >= self.cfg.get('detection_score_threshold', 60):

                    self._on_detection(recent, entropies, score_report)

                suspect = self.detect_suspicious_process()
                if suspect and self.gui_callback:
                    self.gui_callback(f"Suspicious process: {suspect.pid} {suspect.name()}")

            except Exception as e:
                logger.exception("Error in monitor checker loop: " + str(e))

                if self.gui_callback:
                    self.gui_callback("Error in monitor thread: " + str(e))

    def check_now(self):
        recent = self._get_recent_events()

        if not recent:
            if self.gui_callback:
                self.gui_callback("No recent events to scan")
            return

        entropies = [file_entropy(p) for p in recent[:self.cfg['sample_entropy_count']]]
        score_report = score_files(len(recent), entropies, self.cfg)

        json_event({'type': 'manual_scan', 'score_report': score_report})

        if is_ransomware_wave(len(recent), entropies, self.cfg) or \
           score_report.get('score', 0) >= self.cfg.get('detection_score_threshold', 60):
            self._on_detection(recent, entropies, score_report)

    def detect_suspicious_process(self):
        if psutil is None:
            return None

        top = None
        for p in psutil.process_iter(['pid', 'name', 'io_counters', 'open_files']):
            try:
                info = p.info
                pid = info.get('pid')
                name = info.get('name', '').lower()
                
                # Skip system/critical processes
                if pid <= 10 or name in ('system', 'csrss.exe', 'smss.exe', 'wininit.exe', 'services.exe'):
                    continue
                
                of = info.get('open_files') or []
                io = info.get('io_counters')
                write_bytes = getattr(io, 'write_bytes', 0) if io else 0

                score = len(of) + (write_bytes // (1024 * 1024))

                if not top or score > top[0]:
                    top = (score, p)

            except Exception:
                continue

        if top and top[0] >= self.cfg['process_suspicion_score']:
            logger.info(f"Detected suspicious process {top[1].pid} ({top[1].name()}) score={top[0]}")
            return top[1]

        return None

    def map_file_to_process(self, path):
        if psutil is None:
            return None

        for p in psutil.process_iter(['pid', 'name', 'open_files']):
            try:
                for of in p.info.get('open_files') or []:
                    if os.path.abspath(path) == os.path.abspath(of.path):
                        return p
            except Exception:
                continue

        return None

    def _on_detection(self, recent_files, entropies, score_report=None):
        logger.warning("Ransomware-like wave detected")
        
        # Filter out files that don't exist or are directories
        valid_files = []
        for f in recent_files:
            if f and os.path.exists(f) and os.path.isfile(f):
                valid_files.append(f)
            else:
                logger.debug(f"Skipping invalid file for quarantine: {f}")

        if not valid_files:
            logger.warning("No valid files to quarantine")
            if self.gui_callback:
                self.gui_callback("Detection: No valid files found to quarantine")
            return

        attributed = []
        for f in valid_files:
            p = self.map_file_to_process(f)
            attributed.append((f, p.pid if p else None, p.name() if p else None))

        quarantine_dir = self.cfg.get('quarantine_dir', './quarantine')
        moved = []

        if self.cfg.get('auto_quarantine'):
            def _do_quarantine(files, qdir):
                try:
                    if self.gui_callback:
                        self.gui_callback(f"🛡 Quarantining {len(files)} file(s)...")

                    moved_local = quarantine_files(files, qdir)
                    
                    # Count successful quarantines
                    successful = [m for m in moved_local if m[2] in ('moved', 'copied_and_removed')]
                    failed = [m for m in moved_local if m[2] not in ('moved', 'copied_and_removed')]

                    if self.gui_callback:
                        if successful:
                            self.gui_callback(f"✅ Quarantine successful: {len(successful)} file(s) moved")
                        if failed:
                            self.gui_callback(f"⚠️ Quarantine warnings: {len(failed)} file(s) had issues")
                            for f_item in failed[:5]:  # Show first 5 failures
                                self.gui_callback(f"   - {os.path.basename(f_item[0])}: {f_item[2]}")

                    logger.info(f"Quarantine completed: {len(successful)} successful, {len(failed)} failed")
                    return moved_local

                except Exception as e:
                    logger.exception("Quarantine thread failed: " + str(e))

                    if self.gui_callback:
                        self.gui_callback(f"❌ Quarantine failed: {str(e)}")

                    return []

            qt = threading.Thread(target=_do_quarantine, args=(valid_files, quarantine_dir), daemon=True)
            qt.start()

            moved = ['in_progress']

        else:
            logger.info("Auto-quarantine disabled")

            if self.gui_callback:
                self.gui_callback(f"⚠️ DETECTION: {len(valid_files)} suspicious file(s) detected. Auto-quarantine is DISABLED. Enable it in settings to automatically quarantine files.")

        suspect = self.detect_suspicious_process()
        killed = None

        if suspect:
            try:
                # Safety check: prevent killing critical system processes
                if suspect.pid <= 10:
                    logger.warning(f"Skipping critical system PID {suspect.pid}; cannot terminate safely")
                    if self.gui_callback:
                        self.gui_callback(f"Skipping critical system process PID {suspect.pid}")
                else:
                    pid = suspect.pid
                    pname = suspect.name()
                    termination_status = 'unknown'
                    
                    try:
                        # Try graceful termination first
                        suspect.terminate()
                        try:
                            suspect.wait(timeout=3)
                        except Exception:
                            pass

                        # Check if process stopped
                        stopped = not psutil.pid_exists(pid) if psutil else not suspect.is_running()

                        if stopped:
                            killed = (pid, pname)
                            termination_status = 'terminated_gracefully'
                            msg = f'Stopped process gracefully: PID {pid} ({pname})'
                            logger.warning(msg)
                            if self.gui_callback:
                                self.gui_callback('✅ ' + msg)
                        else:
                            # Force kill if graceful termination failed
                            try:
                                suspect.kill()
                                suspect.wait(timeout=3)
                            except Exception:
                                pass

                            # Re-check if process stopped
                            stopped = not psutil.pid_exists(pid) if psutil else not suspect.is_running()

                            if stopped:
                                killed = (pid, pname)
                                termination_status = 'killed_forcibly'
                                msg = f'Killed process forcibly: PID {pid} ({pname})'
                                logger.warning(msg)
                                if self.gui_callback:
                                    self.gui_callback('🛑 ' + msg)
                            else:
                                termination_status = 'failed'
                                msg = f'Failed to stop suspicious process PID {pid} ({pname})'
                                logger.error(msg)
                                if self.gui_callback:
                                    self.gui_callback('❌ ' + msg)
                    except Exception as e:
                        termination_status = 'error'
                        msg = f'Error stopping process PID {pid} ({pname}): {e}'
                        logger.exception(msg)
                        if self.gui_callback:
                            self.gui_callback('❌ ' + msg)

                    # Log termination event
                    json_event({'type': 'process_termination', 'pid': pid, 'name': pname, 'status': termination_status, 'timestamp': int(time.time())})

            except Exception as e:
                logger.exception("Failed to kill suspect: " + str(e))
                killed = None

        # Attempt to terminate children of suspect as well (best-effort)
        if suspect and psutil is not None:
            try:
                for child in suspect.children(recursive=True):
                    try:
                        if child.pid <= 10:
                            continue
                        cpid = child.pid
                        cname = child.name()
                        status = 'unknown'
                        try:
                            child.terminate()
                            try:
                                child.wait(timeout=2)
                            except Exception:
                                pass
                            if psutil.pid_exists(cpid):
                                try:
                                    child.kill()
                                    child.wait(timeout=2)
                                except Exception:
                                    pass
                            status = 'terminated' if not psutil.pid_exists(cpid) else 'failed'
                        except Exception as ce:
                            status = f'error:{ce}'
                        json_event({'type': 'process_termination', 'pid': cpid, 'name': cname, 'status': f'child_{status}', 'timestamp': int(time.time())})
                    except Exception:
                        continue
            except Exception:
                pass

        report = {
            'timestamp': int(time.time()),
            'files_quarantined': moved,
            'attributed': attributed,
            'process_killed': killed,
            'sample_entropies': entropies,
            'score_report': score_report
        }

        json_event({'type': 'detection', 'report': report})

        if self.gui_callback:
            score = score_report.get('score', 0) if score_report else 0
            self.gui_callback(f"🚨 === RANSOMWARE DETECTION ===")
            self.gui_callback(f"   Threat Score: {score}/100")
            self.gui_callback(f"   Suspicious Files: {len(recent_files)}")
            self.gui_callback(f"   Auto-Quarantine: {'ENABLED' if self.cfg.get('auto_quarantine') else 'DISABLED'}")
            if killed:
                self.gui_callback(f"   Process Killed: PID {killed[0]} ({killed[1]})")
            self.gui_callback(f"   Details: {str(report)[:200]}...")

        # After taking immediate actions, perform a safeguard: copy recent files
        # to a protected folder under logs/safeguards/<timestamp> and attempt to
        # make the copied files read-only. Run safeguard in a background thread
        # so we don't block the monitor or GUI.
        def _safeguard(files):
            try:
                safeguard_base = os.path.join(os.getcwd(), 'logs', 'safeguards')
                os.makedirs(safeguard_base, exist_ok=True)
                ts = int(time.time())
                dest_root = os.path.join(safeguard_base, str(ts))
                os.makedirs(dest_root, exist_ok=True)
                copied = []
                for f in files:
                    try:
                        # preserve path structure: use basename to avoid escaping watched trees
                        rel = os.path.basename(f)
                        dest = os.path.join(dest_root, rel)
                        # ensure parent dir
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        shutil.copy2(f, dest)
                        # try to mark read-only
                        try:
                            os.chmod(dest, stat.S_IREAD)
                        except Exception:
                            pass
                        copied.append((f, dest, 'copied'))
                    except Exception as e:
                        copied.append((f, None, f'failed:{str(e)}'))
                # record safeguard event
                json_event({'type': 'safeguard', 'timestamp': int(time.time()), 'dest': dest_root, 'copied': copied})
                if self.gui_callback:
                    self.gui_callback(f'Safeguard completed: {dest_root} ({len(copied)} files)')
                logger.info(f'Safeguard completed: {dest_root} entries={len(copied)}')
            except Exception as e:
                logger.exception('Safeguard failed: ' + str(e))
                if self.gui_callback:
                    self.gui_callback('Safeguard failed: ' + str(e))

        st = threading.Thread(target=_safeguard, args=(recent_files,), daemon=True)
        st.start()
