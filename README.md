# Ransomware Defender (Level-4) — File Behavior Monitor (Enhanced)

**What's new in this enhanced package**
- Improved file-to-process attribution using `psutil` open-file mapping.
- JSONL event logging and rotating logs in `logs/`.
- GUI buttons to view quarantine log, restore files, and export logs.
- `restore.py` CLI tool to restore files from the quarantine recovery log.
- `service_templates/` includes a systemd unit sample and Windows instructions.
- Safer process termination (terminate -> wait -> kill fallback).

**Usage**
1. Install dependencies:
```
pip install -r requirements.txt
```
2. Run GUI:
```
python main.py
```
or run headless monitor (not included by default) — edit `main.py` to use monitor directly.

**Security & Safety**
- Always test in a controlled environment.
- Quarantine moves files — ensure you have backups before restoring.
- Consider integration with EDR / SIEM for production.

**Next steps (can add)**
- Integrate OS-specific file handle mapping (Windows API) for more reliable attribution.
- Add signature-based YARA checks.
- Harden as a real service with secure auto-update.

