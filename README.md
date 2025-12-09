# Port-scanning-sql-injection
An educational Python-based security scanner demonstrating basic SQL injection detection and TCP port scanning concepts in authorized environments.

# Interactive Educational Scanner

An **interactive, educational security testing tool** written in Python.  
It demonstrates **basic SQL Injection detection techniques** and a **multi-threaded TCP port scanner** for learning and lab use.

⚠️ **This project is strictly for educational purposes.**  
Use it **only on systems you own or have explicit written permission to test.**

---

## ✨ Features

- Interactive menu-driven CLI
- SQL Injection payload testing (error-based, boolean, time-based)
- Threaded TCP port scanning (fast)
- Common ports scan or full 1–65535 scan (optional)
- Text or JSON output
- Built-in permission confirmation prompt

---

## 📌 Supported Tests

1. **SQL Injection Test**
   - Injects payloads into URL query parameters
   - Detects error-based responses and significant content changes

2. **Port Scan (Common)**
   - Scans commonly used ports (HTTP, SSH, FTP, MySQL, RDP, etc.)

3. **Port Scan (Full Range)**
   - Optional scan from port 1–65535  
   - ⚠️ Heavy & noisy — use only in controlled environments

4. **Combined Scan**
   - SQL Injection + common port scan

---

## 🛠 Requirements

- Python **3.8+**
- `requests` library

Install dependency:
```bash
pip install requests

