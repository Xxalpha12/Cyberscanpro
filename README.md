# NetScan Pro 🛡️
### Automated Network & Web Application Vulnerability Assessment Tool
**FUPRE Final Year Project | Author: Obeh | Department of Computer Science**

---

## Project Structure

```
netscampro/
├── main.py                  ← Entry point (CLI + dashboard launcher)
├── dashboard.py             ← Flask web dashboard
├── requirements.txt         ← Python dependencies
│
├── modules/
│   ├── __init__.py
│   ├── logger.py            ← Logging utility
│   ├── database.py          ← SQLite database handler
│   ├── network_scanner.py   ← Host/port/service discovery (Nmap + sockets)
│   ├── web_tester.py        ← Web vulnerability scanner (SQLi, XSS, etc.)
│   ├── cve_mapper.py        ← CVE lookup via NVD API
│   └── report_generator.py  ← PDF + HTML report generation
│
├── templates/
│   ├── report.html          ← Jinja2 HTML report template
│   ├── dashboard.html       ← Flask dashboard home
│   ├── new_scan.html        ← New scan form with live log
│   └── scan_detail.html     ← Scan results detail view
│
├── db/
│   └── netscampro.db        ← SQLite database (auto-created)
│
└── output/
    └── *.pdf / *.html       ← Generated reports + scan logs
```

---

## Installation

### 1. Install system dependency
```bash
# Linux/Kali
sudo apt install nmap

# macOS
brew install nmap
```

### 2. Install Python packages
```bash
pip install -r requirements.txt
```

---

## Usage

### CLI — Network scan only
```bash
python main.py -t 192.168.1.10
```

### CLI — Full scan (network + web + CVE)
```bash
python main.py -t 192.168.1.0/24 --full --output both
```

### CLI — Custom options
```bash
python main.py -t 192.168.1.10 --web --cve --ports 1-65535 --scan-type full --output pdf -v
```

### Launch Web Dashboard
```bash
python main.py --dashboard
# Open: http://localhost:5000
```

---

## CLI Options

| Flag | Description |
|------|-------------|
| `-t`, `--target` | Target IP or CIDR range |
| `--web` | Enable web application testing |
| `--cve` | Enable CVE lookup |
| `--full` | Enable all modules (web + CVE) |
| `--ports` | Port range (default: 1-1024) |
| `--scan-type` | quick / full / stealth |
| `--output` | pdf / html / both |
| `--dashboard` | Launch web dashboard |
| `--port` | Dashboard port (default: 5000) |
| `-v` | Verbose output |

---

## Test Environment Setup

For safe testing without hitting real systems:

1. **Install VirtualBox** + **Metasploitable 2** (intentionally vulnerable Linux VM)
2. **Install DVWA** (Damn Vulnerable Web Application) on the VM
3. Set both VMs to **Host-Only Adapter** networking
4. Run NetScan Pro targeting the Metasploitable IP

```bash
# Example against Metasploitable
python main.py -t 192.168.56.101 --full --output both -v
```

---

## Ethical Use Disclaimer

> ⚠️ NetScan Pro is designed **exclusively** for authorized security assessments
> in controlled lab environments. Never use this tool against any system you
> do not own or have explicit written permission to test.
> Unauthorized use is illegal and unethical.

---

## Modules Overview

| Module | File | Key Libraries |
|--------|------|---------------|
| Network Scanner | `modules/network_scanner.py` | python-nmap, Scapy, socket |
| Web App Tester | `modules/web_tester.py` | requests, BeautifulSoup4 |
| CVE Mapper | `modules/cve_mapper.py` | requests (NVD API) |
| Report Generator | `modules/report_generator.py` | ReportLab, Jinja2 |
| Database | `modules/database.py` | SQLite3 |
| Dashboard | `dashboard.py` | Flask |
