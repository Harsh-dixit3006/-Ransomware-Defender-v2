# gui.py (enhanced)
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, simpledialog, ttk
import threading, os, json, sys, traceback, time, queue
from monitor import MonitorController
from quarantine import list_recovery_log, quarantine_files
from logger import logger

DEFAULT_CFG = {
    'window_seconds': 10,
    'check_interval': 3,
    'modified_threshold': 12,
    'entropy_threshold': 7.5,
    'high_entropy_count': 6,
    'sample_entropy_count': 20,
    'process_suspicion_score': 5,
    'quarantine_dir': './quarantine',
    'auto_quarantine': False,
    'detection_score_threshold': 60
}

class App:
    def __init__(self, root):
        self.root = root
        root.title('🛡️ Ransomware Defender — Enhanced')
        root.geometry('1000x750')
        root.configure(bg='#1a1a2e')
        root.minsize(900, 650)
        
        self.paths = []
        self.cfg = DEFAULT_CFG.copy()
        self.controller = None
        self._log_queue = queue.Queue()
        self._pending_logs = []
        self._last_log_update = 0
        self._log_update_interval = 0.1
        self._event_count = 0
        self._last_event_log = 0
        self._is_monitoring = False
        # Log throttling controls
        self._max_queue = 5000
        self._dropped_logs = 0

        # Modern style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background='#1a1a2e')
        style.configure('Card.TFrame', background='#16213e', relief='flat')
        
        # Main container
        main_container = tk.Frame(root, bg='#1a1a2e')
        main_container.pack(fill='both', expand=True, padx=15, pady=15)

        # Header with title
        header = tk.Frame(main_container, bg='#16213e', relief='flat', bd=0)
        header.pack(fill='x', pady=(0, 15))
        tk.Label(header, text='🛡️ RANSOMWARE DEFENDER', font=('Segoe UI', 16, 'bold'),
                bg='#16213e', fg='#00d4ff').pack(pady=12)

        # Control panel card
        control_card = tk.Frame(main_container, bg='#16213e', relief='flat', bd=0)
        control_card.pack(fill='x', pady=(0, 10))
        
        # Primary controls
        primary_frame = tk.Frame(control_card, bg='#16213e')
        primary_frame.pack(fill='x', padx=15, pady=12)

        self.btn_add = tk.Button(primary_frame, text='➕ Add Path', command=self.add_path,
                                 bg='#0f3460', fg='#00d4ff', font=('Segoe UI', 9, 'bold'),
                                 relief='flat', padx=15, pady=8, cursor='hand2', bd=0,
                                 activebackground='#16213e', activeforeground='#00ff88')
        self.btn_add.pack(side='left', padx=3)

        self.btn_remove_path = tk.Button(primary_frame, text='➖ Remove', command=self.remove_path,
                                        bg='#0f3460', fg='#ff6b6b', font=('Segoe UI', 9, 'bold'),
                                        relief='flat', padx=15, pady=8, cursor='hand2', bd=0,
                                        activebackground='#16213e', activeforeground='#ff4757')
        self.btn_remove_path.pack(side='left', padx=3)

        tk.Frame(primary_frame, bg='#0f3460', width=2, height=30).pack(side='left', padx=8)

        self.btn_start = tk.Button(primary_frame, text='▶ START', command=self.start_monitor,
                                  bg='#00d4ff', fg='#0f3460', font=('Segoe UI', 10, 'bold'),
                                  relief='flat', padx=20, pady=8, cursor='hand2', bd=0,
                                  activebackground='#00ff88', activeforeground='#0f3460')
        self.btn_start.pack(side='left', padx=3)

        self.btn_stop = tk.Button(primary_frame, text='⏹ STOP', command=self.stop_monitor,
                                  bg='#ff4757', fg='white', font=('Segoe UI', 10, 'bold'),
                                  relief='flat', padx=20, pady=8, cursor='hand2', bd=0, state='disabled',
                                  activebackground='#ff6b6b', activeforeground='white')
        self.btn_stop.pack(side='left', padx=3)

        self.btn_scan = tk.Button(primary_frame, text='🔍 SCAN', command=self.scan_now,
                                  bg='#ffa502', fg='#0f3460', font=('Segoe UI', 9, 'bold'),
                                  relief='flat', padx=15, pady=8, cursor='hand2', bd=0, state='disabled',
                                  activebackground='#ffb142', activeforeground='#0f3460')
        self.btn_scan.pack(side='left', padx=3)

        tk.Frame(primary_frame, bg='#0f3460', width=2, height=30).pack(side='left', padx=8)

        self.btn_quarantine = tk.Button(primary_frame, text='📋 Quarantine', command=self.view_quarantine,
                                       bg='#0f3460', fg='#a29bfe', font=('Segoe UI', 9, 'bold'),
                                       relief='flat', padx=12, pady=8, cursor='hand2', bd=0,
                                       activebackground='#16213e', activeforeground='#dfe6e9')
        self.btn_quarantine.pack(side='left', padx=3)

        self.btn_restore = tk.Button(primary_frame, text='↩ Restore', command=self.restore_prompt,
                                     bg='#0f3460', fg='#74b9ff', font=('Segoe UI', 9, 'bold'),
                                     relief='flat', padx=12, pady=8, cursor='hand2', bd=0,
                                     activebackground='#16213e', activeforeground='#dfe6e9')
        self.btn_restore.pack(side='left', padx=3)

        self.btn_export = tk.Button(primary_frame, text='💾 Export', command=self.export_logs,
                                   bg='#0f3460', fg='#dfe6e9', font=('Segoe UI', 9, 'bold'),
                                   relief='flat', padx=12, pady=8, cursor='hand2', bd=0,
                                   activebackground='#16213e', activeforeground='#dfe6e9')
        self.btn_export.pack(side='left', padx=3)

        self.btn_quit = tk.Button(primary_frame, text='✖', command=self._quit,
                                 bg='#2d3436', fg='#dfe6e9', font=('Segoe UI', 10, 'bold'),
                                 relief='flat', padx=12, pady=8, cursor='hand2', bd=0,
                                 activebackground='#636e72', activeforeground='white')
        self.btn_quit.pack(side='right', padx=3)

        # Status bar
        status_frame = tk.Frame(main_container, bg='#0f3460', relief='flat', bd=0)
        status_frame.pack(fill='x', pady=(0, 10))
        
        status_inner = tk.Frame(status_frame, bg='#0f3460')
        status_inner.pack(padx=15, pady=10)
        
        tk.Label(status_inner, text='●', font=('Arial', 12), bg='#0f3460', fg='#636e72').pack(side='left', padx=(0, 5))
        self.status_var = tk.StringVar()
        self.status_var.set('Idle')
        self.status_label = tk.Label(status_inner, textvariable=self.status_var, 
                                     font=('Segoe UI', 10, 'bold'), bg='#0f3460', fg='#dfe6e9')
        self.status_label.pack(side='left')
        
        self.paths_label = tk.Label(status_inner, text='Watched: 0 paths', 
                                    font=('Segoe UI', 9), bg='#0f3460', fg='#74b9ff')
        self.paths_label.pack(side='right', padx=10)

        # Configuration card
        cfg_frame = tk.Frame(main_container, bg='#16213e', relief='flat', bd=0)
        cfg_frame.pack(fill='x', pady=(0, 10))
        
        tk.Label(cfg_frame, text='⚙️ Configuration', bg='#16213e', fg='#00d4ff',
                font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=15, pady=(10, 5))

        cfg_inner = tk.Frame(cfg_frame, bg='#16213e')
        cfg_inner.pack(fill='x', padx=15, pady=(0, 12))

        tk.Label(cfg_inner, text='Modified threshold:', bg='#16213e', fg='#dfe6e9',
                font=('Segoe UI', 9)).pack(side='left', padx=(0, 5))
        self.ent_mod = tk.Entry(cfg_inner, width=6, font=('Segoe UI', 9), bg='#0f3460',
                               fg='#00d4ff', insertbackground='#00d4ff', relief='flat', bd=0)
        self.ent_mod.insert(0, str(self.cfg['modified_threshold']))
        self.ent_mod.pack(side='left', padx=5, ipady=3)

        tk.Label(cfg_inner, text='Entropy threshold:', bg='#16213e', fg='#dfe6e9',
                font=('Segoe UI', 9)).pack(side='left', padx=(20, 5))
        self.ent_ent = tk.Entry(cfg_inner, width=6, font=('Segoe UI', 9), bg='#0f3460',
                               fg='#00d4ff', insertbackground='#00d4ff', relief='flat', bd=0)
        self.ent_ent.insert(0, str(self.cfg['entropy_threshold']))
        self.ent_ent.pack(side='left', padx=5, ipady=3)

        self.auto_var = tk.BooleanVar()
        self.auto_var.set(False)
        self.chk_auto = tk.Checkbutton(cfg_inner, text='🛡️ Auto-quarantine on detection', 
                                       variable=self.auto_var, bg='#16213e', fg='#00ff88',
                                       font=('Segoe UI', 9, 'bold'), selectcolor='#0f3460',
                                       activebackground='#16213e', activeforeground='#00ff88')
        self.chk_auto.pack(side='left', padx=(20, 0))

        # Log frame
        log_frame = tk.Frame(main_container, bg='#16213e', relief='flat', bd=0)
        log_frame.pack(fill='both', expand=True)
        
        tk.Label(log_frame, text='📊 Activity Log', bg='#16213e', fg='#00d4ff',
                font=('Segoe UI', 10, 'bold')).pack(anchor='w', padx=15, pady=(10, 5))

        log_container = tk.Frame(log_frame, bg='#16213e')
        log_container.pack(fill='both', expand=True, padx=15, pady=(0, 12))

        self.log = scrolledtext.ScrolledText(log_container, height=20, wrap='word',
                                            font=('Consolas', 9), bg='#0f0f1e', fg='#00d4ff',
                                            insertbackground='#00d4ff', relief='flat', bd=0)
        self.log.pack(fill='both', expand=True)
        self._log_lines = 0
        self._max_log_lines = 2000
        self._trim_target_lines = 1000

        # Start log update processor
        self._process_log_queue()

        self._log('🛡️ Ransomware Defender initialized', 'info')
        self._log('➕ Add watch paths and click START to begin monitoring', 'info')
        
        # Update button states
        self._update_button_states()

    def add_path(self):
        p = filedialog.askdirectory()
        if p:
            if p not in self.paths:
                self.paths.append(p)
                self._log(f'✅ Added: {p}')
                self.paths_label.config(text=f'Watched: {len(self.paths)} paths')
            else:
                messagebox.showinfo('Path exists', 'This path is already being watched.')

    def remove_path(self):
        if not self.paths:
            messagebox.showinfo('No paths', 'No watch paths to remove.')
            return
        
        if self._is_monitoring:
            messagebox.showwarning('Monitoring active', 'Stop monitoring before removing paths.')
            return
        
        # Create a dialog to select which path to remove
        dlg = tk.Toplevel(self.root)
        dlg.title('Remove Watch Path')
        dlg.geometry('500x350')
        dlg.configure(bg='#1a1a2e')
        dlg.transient(self.root)
        dlg.grab_set()
        
        tk.Label(dlg, text='Select a path to remove:', font=('Segoe UI', 10, 'bold'),
                bg='#1a1a2e', fg='#00d4ff').pack(pady=15)
        
        listbox = tk.Listbox(dlg, font=('Segoe UI', 9), height=12, bg='#0f3460',
                            fg='#dfe6e9', selectbackground='#00d4ff', selectforeground='#0f3460',
                            relief='flat', bd=0)
        listbox.pack(fill='both', expand=True, padx=15, pady=5)
        
        for path in self.paths:
            listbox.insert('end', path)
        
        def do_remove():
            selection = listbox.curselection()
            if not selection:
                messagebox.showwarning('No selection', 'Please select a path to remove.')
                return
            
            idx = selection[0]
            removed_path = self.paths.pop(idx)
            self._log(f'❌ Removed: {removed_path}')
            self.paths_label.config(text=f'Watched: {len(self.paths)} paths')
            dlg.destroy()
        
        btn_frame = tk.Frame(dlg, bg='#1a1a2e')
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text='Remove', command=do_remove,
                 bg='#ff4757', fg='white', font=('Segoe UI', 9, 'bold'),
                 relief='flat', padx=20, pady=8, bd=0, cursor='hand2').pack(side='left', padx=5)
        
        tk.Button(btn_frame, text='Cancel', command=dlg.destroy,
                 bg='#636e72', fg='white', font=('Segoe UI', 9, 'bold'),
                 relief='flat', padx=20, pady=8, bd=0, cursor='hand2').pack(side='left', padx=5)

    def start_monitor(self):
        if not self.paths:
            messagebox.showwarning('No path', 'Add at least one watch path first.')
            return
        
        if self._is_monitoring:
            messagebox.showinfo('Already running', 'Monitoring is already active.')
            return
        
        try:
            self.cfg['modified_threshold'] = int(self.ent_mod.get())
            self.cfg['entropy_threshold'] = float(self.ent_ent.get())
        except ValueError:
            messagebox.showerror('Config', 'Invalid configuration values. Please enter valid numbers.')
            return
        except Exception as e:
            messagebox.showerror('Config', f'Configuration error: {str(e)}')
            return
        
        # set auto_quarantine from UI
        self.cfg['auto_quarantine'] = bool(self.auto_var.get())
        
        if self.controller:
            self.controller.stop()
        
        self.controller = MonitorController(self.paths, self.cfg, gui_callback=self._gui_callback)
        try:
            self.controller.start()
            self._is_monitoring = True
            self._log('▶ Monitoring started')
            self._log(f'🛡️ Auto-quarantine: {"ENABLED" if self.cfg["auto_quarantine"] else "DISABLED"}')
            self.status_var.set('🟢 Monitoring Active')
            self.status_label.config(fg='#00ff88')
            self._update_button_states()
        except Exception as e:
            self._is_monitoring = False
            self._log(f'Failed to start controller: {str(e)}')
            messagebox.showerror('Start Failed', f'Failed to start monitoring: {str(e)}')
            self._update_button_states()

    def stop_monitor(self):
        if self.controller and self._is_monitoring:
            try:
                self.controller.stop()
                self._is_monitoring = False
                self._log('⏹ Monitoring stopped')
                self.status_var.set('🔴 Stopped')
                self.status_label.config(fg='#ff6b6b')
                self._update_button_states()
            except Exception as e:
                self._log(f'Error stopping controller: {str(e)}')
                messagebox.showerror('Stop Failed', f'Error stopping monitoring: {str(e)}')

    def view_quarantine(self):
        lines = list_recovery_log()
        dlg = tk.Toplevel(self.root)
        dlg.title('📋 Quarantine / Recovery Log')
        dlg.geometry('900x600')
        dlg.configure(bg='#1a1a2e')
        
        header = tk.Frame(dlg, bg='#16213e')
        header.pack(fill='x')
        tk.Label(header, text='📋 Quarantine Log', font=('Segoe UI', 12, 'bold'),
                bg='#16213e', fg='#00d4ff').pack(pady=10)
        
        st = scrolledtext.ScrolledText(dlg, width=100, height=30, bg='#0f0f1e',
                                      fg='#dfe6e9', font=('Consolas', 9), relief='flat', bd=0)
        st.pack(fill='both', expand=True, padx=15, pady=15)
        st.insert('end', '\n'.join(lines))
        st.configure(state='disabled')

    def restore_prompt(self):
        # simple restore helper: user selects a file from quarantine dir to move back
        qdir = self.cfg.get('quarantine_dir','./quarantine')
        if not os.path.isdir(qdir):
            messagebox.showinfo('No quarantine', 'No quarantine directory found.')
            return
        f = filedialog.askopenfilename(initialdir=qdir, title='Select file in quarantine to restore')
        if not f:
            return
        dest = filedialog.asksaveasfilename(initialfile=os.path.basename(f), title='Restore to path')
        if not dest:
            return
        try:
            import shutil
            shutil.move(f, dest)
            messagebox.showinfo('Restored', f'Moved {f} -> {dest}')
            logger.info(f'Restored {f} to {dest}')
        except Exception as e:
            messagebox.showerror('Restore failed', str(e))

    def export_logs(self):
        import shutil
        logdir = os.path.join(os.getcwd(), 'logs')
        if not os.path.isdir(logdir):
            messagebox.showinfo('No logs', 'No logs directory found')
            return
        dest = filedialog.asksaveasfilename(defaultextension='.zip', title='Export logs to zip', initialfile='rdefender_logs.zip')
        if not dest:
            return
        try:
            shutil.make_archive(dest.replace('.zip',''), 'zip', logdir)
            messagebox.showinfo('Exported', f'Logs exported to {dest}')
        except Exception as e:
            messagebox.showerror('Export failed', str(e))

    def _gui_callback(self, message):
        """Thread-safe callback from monitor controller"""
        def append():
            self._log(message)
            # Update status on detection
            if '===DETECTION===' in message or 'DETECTION' in message.upper():
                self.status_var.set('🚨 THREAT DETECTED!')
                self.status_label.config(fg='#ff4757')
                self.root.bell()
            elif 'Quarantine' in message or 'quarantine' in message:
                self.status_var.set('🛡️ Quarantine Active')
                self.status_label.config(fg='#ffa502')
        self.root.after(0, append)

    def scan_now(self):
        if not self.controller or not self._is_monitoring:
            messagebox.showwarning('Not running', 'Start monitoring first before scanning.')
            return
        try:
            self._log('Manual scan initiated...')
            self.controller.check_now()
            self._log('Manual scan completed.')
        except Exception as e:
            self._log(f'Scan failed: {str(e)}')
            messagebox.showerror('Scan Failed', f'Scan error: {str(e)}')

    def _log(self, text, level='info'):
        """Add log message to queue for thread-safe UI updates"""
        timestamped = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {text}"
        try:
            # Cap queue size; coalesce new entries if overflowing
            if hasattr(self._log_queue, 'qsize') and self._log_queue.qsize() >= self._max_queue:
                self._dropped_logs += 1
            else:
                self._log_queue.put(timestamped)
        except Exception:
            pass
    
    def _process_log_queue(self):
        """Process log queue periodically to update UI without blocking"""
        try:
            # Dynamically process a larger batch when backlog is high
            backlog = self._log_queue.qsize() if hasattr(self._log_queue, 'qsize') else 0
            batch_size = 10
            if backlog > 100:
                batch_size = min(200, backlog)
            count = 0
            while count < batch_size and not self._log_queue.empty():
                try:
                    text = self._log_queue.get_nowait()
                    self._append_log_direct(text)
                    count += 1
                except queue.Empty:
                    break
            # If logs were dropped, emit a single coalesced notice
            if self._dropped_logs > 0:
                self._append_log_direct(f"[info] Suppressed {self._dropped_logs} log messages due to high activity")
                self._dropped_logs = 0
        except Exception:
            pass
        
        # Schedule next update (slightly slower when backlog huge to reduce churn)
        delay = 50 if (self._log_queue.qsize() if hasattr(self._log_queue, 'qsize') else 0) < 1000 else 100
        self.root.after(delay, self._process_log_queue)
    
    def _append_log_direct(self, text):
        """Directly append to log widget (called from main thread only)"""
        try:
            self.log.insert('end', text + '\n')
            self._log_lines += 1
            # trim if too many lines to keep UI responsive
            if self._log_lines > self._max_log_lines:
                # aggressively trim to target to avoid Tk fragmentation
                try:
                    delete_until = self._log_lines - self._trim_target_lines
                    delete_until = max(delete_until, int(self._max_log_lines * 0.5))
                    self.log.delete('1.0', f'{delete_until + 1}.0')
                    self._log_lines -= delete_until
                except Exception:
                    # best effort
                    pass
            self.log.see('end')
        except Exception:
            # avoid raising from logging
            pass

    def _update_button_states(self):
        """Update button states based on monitoring status"""
        if self._is_monitoring:
            self.btn_start.config(state='disabled')
            self.btn_stop.config(state='normal')
            self.btn_scan.config(state='normal')
            self.btn_add.config(state='disabled')
        else:
            self.btn_start.config(state='normal')
            self.btn_stop.config(state='disabled')
            self.btn_scan.config(state='disabled')
            self.btn_add.config(state='normal')
    
    def _quit(self):
        if self.controller and self.controller.running:
            try:
                self.controller.stop()
            except Exception:
                pass
        self.root.quit()
        try:
            self.root.destroy()
        except Exception:
            pass

def run_app():
    root = tk.Tk()
    app = App(root)

    # Better exception reporting for Tk callbacks
    def _report_callback_exception(exc, val, tb):
        try:
            logger.exception('Uncaught Tk exception', exc_info=(exc, val, tb))
        except Exception:
            pass
        try:
            # show in GUI log if possible
            app._log('Internal error: ' + str(val))
        except Exception:
            pass

    # Tkinter calls this when exceptions occur in callbacks
    root.report_callback_exception = _report_callback_exception

    try:
        root.mainloop()
    except KeyboardInterrupt:
        try:
            app._log('Interrupted by user (KeyboardInterrupt)')
        except Exception:
            pass
        try:
            if app.controller and app.controller.running:
                app.controller.stop()
        except Exception:
            pass
        try:
            root.quit()
            root.destroy()
        except Exception:
            pass
        sys.exit(0)
