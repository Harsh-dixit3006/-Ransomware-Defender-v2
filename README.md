# Ransomware Defender (Level-4) — File Behavior Monitor (Enhanced)

👤 Developed By:
🧑‍💻 Harsh Dixit
GitHub: https://github.com/Harsh-dixit3006

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
- Quarantine moves files — ensure you have backups before restoring.# 🛡️ Ransomware Defender (Level-4) — File Behavior Monitor (Enhanced)

<p align="center">
  <img src="https://via.placeholder.com/800x200?text=RANSOMWARE+DEFENDER" alt="Project Banner"/>
</p>

<p align="center">
  <b>A Real-Time AI-Driven Ransomware Detection & Response System 🚨</b>
</p>

---

<p align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-green)
![Status](https://img.shields.io/badge/Release-Stable-brightgreen)
![License](https://img.shields.io/badge/License-MIT-purple)

</p>

---

## ✨ What's new in this enhanced package

* 🔍 **Improved file-to-process attribution** using `psutil` open-file mapping
* 🧾 **JSONL event logging** + rotating logs stored in `logs/`
* 🖥️ **GUI dashboard additions**

  * Open quarantine log
  * Restore quarantined files
  * Export logs as ZIP
* 🔄 **`restore.py` CLI tool** to restore files from quarantine history
* ⚙️ **`service_templates/`**

  * Example `systemd` unit
  * Windows service instructions
* 🛡️ **Safer process handling**

  * terminate → wait → kill fallback

---

## 🚀 Usage

### 1️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

### 2️⃣ Launch the GUI

```bash
python main.py
```

Or run as a headless monitor
*(requires small modification in `main.py`)*.

---

## 🔒 Security & Safety

⚠️ **Important Guidelines**

* Always test on **non-production data first**
* Ransomware response includes **file quarantine**
* Make sure **you have backups** before restoring real files
* For enterprise environments:

  * Integrate with **SIEM / EDR**
  * Enable **privileged execution** for full process inspection

---

## 🚧 Next Steps / Roadmap (Suggested Enhancements)

✔️ OS-level file handle tracing (Windows native APIs)
✔️ YARA or signature-based scanning support
✔️ Harden into a production service with:

* Secure auto-update
* Locked-down execution context
  ✔️ Add logging export to cloud (Azure / ELK / Splunk)

---

## 💡 Additional Suggestions (From AI)

Here are some recommended improvements you can add later:

* **Dark-mode GUI theme** for better usability
* **Configurable policy profiles**, such as:

  * High-Security mode
  * Developer mode
  * Learning mode
* **Email / Telegram / Discord alert notifications**
* **AES-based pre-attack shadow copy backups**
* **Behavior ML model integration**

  * Detect suspicious ransomware patterns over time
* **Plugin system** for custom actions

  * Shut down network interface
  * Block USB storage
  * Trigger system lockdown

---

## ⭐ Project Snapshot

* Built using **Python + Tkinter**
* Uses `watchdog` for filesystem monitoring
* Uses `psutil` for process attribution
* Generates structured logs for audits
* Includes forensic-friendly quarantining

---

## 📂 Repository Structure (Recommended Display in GitHub)

```
ransomware_defender/
│
├── main.py
├── gui.py
├── monitor.py
├── detector.py
├── quarantine.py
├── logger.py
├── restore.py
├── requirements.txt
│
├── logs/
│   ├── rdefender.log
│   ├── events.jsonl
│   └── recovery_log.json
│
├── service_templates/
│   ├── SYSTEMD.service
│   └── WINDOWS_INSTRUCTIONS.txt
│
└── README.md
```

---

## 🤝 Contribute

Want to help improve the project?

```
Fork → Create Branch → Commit → Pull Request
```

Bug reports, feature ideas, and PRs are always welcome.

---

## 📜 License

Distributed under the **MIT License**.
See `LICENSE` for full details.

---

<p align="center">
  Developed with ❤️ for cybersecurity defenders.
</p>

- Consider integration with EDR / SIEM for production.

**Next steps (can add)**
- Integrate OS-specific file handle mapping (Windows API) for more reliable attribution.
- Add signature-based YARA checks.
- Harden as a real service with secure auto-update.

