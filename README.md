# 🔐 PortLock - Real-Time USB Port Protection Tool

---

**PortLock** is a real-time USB intrusion detection and locking system designed for Windows. It monitors USB devices being plugged in and only allows those that are password-authorized or whitelisted by Serial/Vendor ID. Unauthorized USBs are blocked, logged, and can optionally be ejected or disabled entirely.

---

## 🚀 Features

| Feature                         | Description                                                      |
| ------------------------------- | ---------------------------------------------------------------- |
| ✅ Real-time USB Monitoring     | Detects when a USB device is plugged in instantly                |
| 🔐 Password Prompt              | Asks for a password when unauthorized USB is inserted            |
| 🧾 Attempt Logging              | Records all unauthorized attempts in a timestamped log           |
| ✅ Permanent Whitelist          | Remembers authorized USBs across sessions using Serial/Vendor ID |
| ⚠️ Auto Eject on Wrong Password | Ejects USB device after wrong password (optional)                |
| 📢 Notifications                | Toast pop-ups to alert about blocked or allowed devices          |
| 🧰 System Tray Mode             | Minimized mode with icon and background monitoring               |
| 💻 Convert to .EXE              | Ready for `.exe` conversion with PyInstaller                     |
| 🔧 USB Mode Control (Planned)   | Block USB storage, keyboards, or set USB as read-only            |

---

## 🛠 Installation

### ⚙️ Requirements

- Python 3.8+
- Windows OS
- Administrator Privileges (for ejecting or device control)

### 📦 Python Packages

```bash
pip install -r requirements.txt
```

### 🧪 Optional Tools

For USB ejecting (planned fixes):

- [DevCon](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/devcon) – Microsoft device control utility

---

## 🧑‍💻 Usage

### 🔍 Start the Monitor

```bash
python main.py
```

You can also create a `.bat` or shortcut to launch on startup.

---

## 📁 File Structure

```
portlock/
├── core/
│   ├── detector.py         # Real-time USB detection logic
│   ├── locker.py           # Password + whitelist system
│   └── utils.py            # Eject, log, notification
├── logs/
│   └── unauthorized.log    # Attempts logged here
├── data/
│   └── whitelist.json      # Stored trusted devices
├── main.py                 # Entry point
├── requirements.txt
└── README.md
```

---

## 🛡 Security Philosophy

This tool is designed for **local endpoint protection** to block physical USB-based data theft and malware spread. It works **offline**, without any remote control or backdoor access.

---

## 📓 Future Plans

- [ ] Cross-platform support (Linux & macOS)
- [ ] Tray icon with status popups
- [ ] Advanced logging dashboard (GUI or web)
- [ ] Configurable USB rules (e.g., allow only storage, block HID)
- [ ] Integration with Windows Group Policy or BitLocker

---

## 🧠 Notes

- If the eject function fails, it might require `powershell` scripts or admin drivers like `devcon`.
- You can test unauthorized detection by inserting any USB not in the whitelist and denying the prompt.

---

## 👤 Author

**Jatin Dhir**
📧 [Contact](mailto:dhirjatin@icloud.com)
🌐 [GitHub Profile](https://github.com/Jatin-Dhir)
