# 🛡️ Purple Team WiFi Security Audit Suite

**Comprehensive WiFi Security Assessment Tools for SMB/Restaurant Networks**

A professional-grade WiFi security testing toolkit designed to identify critical vulnerabilities in small business networks. All tools run on both **Termux (Android)** and **Linux/Kali**, with no external dependencies beyond Python's standard library.

---

## 📋 Overview

The WiFi Security Audit Suite comprises 4 specialized tools + 1 orchestrator:

| Tool | Purpose | MITRE ATT&CK |
|------|---------|--------------|
| **Rogue AP Detector** | Evil Twin & malicious WiFi networks | T1557.002, T1040 |
| **Client Isolation Tester** | Network segmentation vulnerabilities | T1046, T1135 |
| **Router Default Checker** | Default credentials & exposed admin | T1078.001, T1133 |
| **Network Exposure Scanner** | Internal system exposure & PCI DSS violations | T1046, T1135, T1040 |
| **WiFi Audit Suite** | Orchestrator running all 4 tools + unified report | — |

---

## 🎯 Key Features

### ✓ Termux & Linux Compatible
- Auto-detects environment (Termux vs Linux)
- Uses native WiFi APIs where available (`termux-wifi-scaninfo`, `nmcli`, `iwlist`)
- Pure Python socket-based port scanning (no nmap required)
- Works on Android tablets in Termux

### ✓ Demo Mode for Presentations
All tools support `--demo` flag to generate sample vulnerability reports without live network access. Perfect for sales demonstrations.

### ✓ Door-Opener Narratives
Each tool generates executive summaries formatted for non-technical business owners:
- What was found (in plain language)
- Why it matters (customer impact)
- How to fix it (recommended actions)

### ✓ Professional Reporting
- Human-readable console output with proper formatting
- JSON output for integration with other tools
- Timestamped reports saved to `~/purple_team_reports/`

### ✓ No External Dependencies
- Uses **Python stdlib only** (socket, subprocess, json, etc.)
- Optional: `requests` library (auto-detected, falls back to raw sockets)
- No need for nmap, aircrack-ng, or other external tools

---

## 🚀 Installation & Setup

### Termux (Android)

```bash
# Update package manager
apt update && apt upgrade -y

# Install Python 3
apt install -y python3

# Install optional WiFi tools (auto-detected by scripts)
apt install -y termux-api

# Clone/copy the WiFi suite to Termux
# Then make scripts executable (already done)
```

### Linux / Kali

```bash
# Ensure Python 3 is installed
sudo apt install -y python3

# Optional: install network tools (auto-detected)
sudo apt install -y network-manager

# Install requests library (optional, improves router detection)
pip3 install requests

# Clone/copy the WiFi suite
# Then make scripts executable
chmod +x /path/to/wifi/*.py
```

---

## 📚 Tool Details

### 1️⃣ Rogue AP Detector (`rogue_ap_detector.py`)

**What it does:**
- Scans for visible WiFi networks
- Detects Evil Twin attacks (same SSID, different MAC addresses)
- Identifies hidden networks on same channels as legitimate networks

**Usage:**
```bash
# Live scan (requires WiFi scanning permissions)
python3 rogue_ap_detector.py

# Demo mode for presentations
python3 rogue_ap_detector.py --demo

# JSON output only
python3 rogue_ap_detector.py --json

# Save to custom location
python3 rogue_ap_detector.py --output /path/to/output.json
```

**Door-Opener Message:**
```
"Someone may already be running a fake copy of your WiFi outside your door"
```

**Example Finding:**
- Detects 2 networks with same SSID "RestaurantGuest" but different BSSIDs
- Explains how customers could accidentally connect to attacker's network
- Recommends changing WiFi name to something unique

---

### 2️⃣ Client Isolation Tester (`client_isolation_tester.py`)

**What it does:**
- Determines if WiFi has client isolation (AP Isolation) enabled
- Scans local subnet for reachable devices
- Classifies devices by type (POS, printer, camera, NAS, etc.)
- Detects devices on ports indicating POS terminals and sensitive equipment

**Usage:**
```bash
# Scan current network
python3 client_isolation_tester.py

# Demo with sample data
python3 client_isolation_tester.py --demo

# Scan specific subnet
python3 client_isolation_tester.py --subnet 192.168.1.0/24

# JSON output
python3 client_isolation_tester.py --json
```

**Door-Opener Message:**
```
"From your customer WiFi, I can reach these devices on your network right now"
```

**Example Finding:**
- Found 8 devices reachable from guest network
- POS terminal on 192.168.1.100:9100 (CRITICAL)
- File storage on 192.168.1.101:445 accessible without auth
- Windows RDP on 192.168.1.102:3389 available to customers

---

### 3️⃣ Router Default Checker (`router_default_checker.py`)

**What it does:**
- Detects router admin interfaces on common ports (80, 443, 8080, 8443, 8888)
- Identifies router brand from HTTP responses
- Tests well-known default credentials per brand:
  - TP-Link: admin/admin, admin/tplink
  - ASUS: admin/admin
  - Vodafone/Movistar: admin/1234
  - D-Link, Netgear, Huawei, ZTE, etc.

**Usage:**
```bash
# Test default gateway
python3 router_default_checker.py

# Demo mode
python3 router_default_checker.py --demo

# Test specific host
python3 router_default_checker.py --host 192.168.0.1

# JSON output
python3 router_default_checker.py --json
```

**Door-Opener Message:**
```
"Your router admin panel is accessible and we were able to log in with the default password"
```

**Example Finding:**
- TP-Link router detected at 192.168.1.1
- Admin accessible via HTTP on port 80
- Default credentials admin/admin work
- Attacker could change WiFi password or redirect DNS

---

### 4️⃣ Network Exposure Scanner (`network_exposure_scanner.py`)

**What it does:**
- Fast subnet scan for all active hosts
- Checks 15+ service ports on each host
- Classifies devices by service (database, POS, camera, file storage)
- Detects PCI DSS compliance violations
- Identifies unencrypted protocols (Telnet, FTP)

**Detected Services:**
```
21/TCP    - FTP (unencrypted)
22/TCP    - SSH
23/TCP    - Telnet (CRITICAL - no encryption)
80/TCP    - HTTP
139/TCP   - NetBIOS (file sharing)
443/TCP   - HTTPS
445/TCP   - SMB (network storage)
554/RTSP  - IP cameras
631/IPP   - Printers
3306/TCP  - MySQL database
3389/TCP  - Windows RDP
5432/TCP  - PostgreSQL database
5900/TCP  - VNC remote desktop
8080/TCP  - HTTP alternate
9100/TCP  - POS receipt printer / JetDirect
```

**Usage:**
```bash
# Comprehensive network scan
python3 network_exposure_scanner.py

# Demo mode (45+ devices shown)
python3 network_exposure_scanner.py --demo

# Custom subnet
python3 network_exposure_scanner.py --subnet 192.168.0.0/24

# JSON output
python3 network_exposure_scanner.py --json
```

**Door-Opener Message:**
```
"Your internal network is visible from customer WiFi - we found POS terminals,
databases, and file servers that are directly accessible to anyone on guest WiFi"
```

**Example Findings:**
- MySQL database (192.168.1.102:3306) exposed to customers
- POS terminal (192.168.1.100:9100) visible from guest network
- Telnet unencrypted protocol (192.168.1.104:23) in use
- FTP file transfer without encryption (192.168.1.105:21) accessible
- **PCI DSS Violations**: Multiple

---

### 5️⃣ WiFi Audit Suite (`wifi_audit_suite.py`)

**What it does:**
- Runs all 4 tools in sequence
- Aggregates findings into unified report
- Generates executive summary
- Creates professional "door opener" narrative

**Usage:**
```bash
# Full audit (comprehensive assessment)
python3 wifi_audit_suite.py

# Demo mode for presentations
python3 wifi_audit_suite.py --demo

# JSON output only
python3 wifi_audit_suite.py --json

# Custom output directory
python3 wifi_audit_suite.py --output /path/to/reports/

# Don't save results (console only)
python3 wifi_audit_suite.py --no-save
```

**Output Example:**
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    🛡️  PURPLE TEAM WiFi AUDIT SUITE 🛡️
  Comprehensive WiFi Security Assessment Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

OVERALL SECURITY ASSESSMENT:
  Overall Risk Level: [CRITICAL]
  Critical Issues: 8
  High Risk Issues: 7

EVIL TWIN NETWORKS (1):
  • FreeWiFi_Public
    BSSIDs: AA:BB:CC:DD:EE:01, AA:BB:CC:DD:EE:02

CLIENT ISOLATION: DISABLED (CRITICAL)
  Customers can reach internal business systems

EXPOSED INTERNAL DEVICES (8):
  • 192.168.1.100 - POS Terminal
  • 192.168.1.101 - File Storage (NAS)
  • 192.168.1.102 - Database
  ... and 5 more

DEFAULT CREDENTIALS DISCOVERED:
  • 192.168.1.1:80 (TP-Link)
    Username: admin

PCI DSS COMPLIANCE VIOLATIONS (3):
  • PCI DSS 1.3: Payment device visible from guest network
  ...
```

---

## 🎬 Usage Scenarios

### Scenario 1: Restaurant WiFi Assessment
```bash
# Connect to restaurant guest WiFi
# Then run:
python3 wifi_audit_suite.py

# Results show:
# - Evil Twin networks targeting customers
# - POS terminals visible from WiFi
# - Unencrypted payment processing
# - No client isolation
```

### Scenario 2: Sales Demo on Prospect's WiFi
```bash
# Use demo mode (no actual scanning needed):
python3 wifi_audit_suite.py --demo

# Shows realistic vulnerabilities
# Can play sample report for business owner
# "This is what we typically find"
```

### Scenario 3: Individual Tool for Specific Check
```bash
# Quick check: Are default router credentials active?
python3 router_default_checker.py

# Takes 15 seconds, direct answer
```

### Scenario 4: JSON Integration with Other Tools
```bash
# Export findings as JSON for parsing
python3 wifi_audit_suite.py --json > audit_results.json

# Can import into reporting platform, CRM, etc.
```

---

## 📊 Report Locations

All reports are saved to **`~/purple_team_reports/`** with timestamp:

```
~/purple_team_reports/
├── rogue_ap_detector_20260322_143022.json
├── client_isolation_tester_20260322_143045.json
├── router_default_checker_20260322_143102.json
├── network_exposure_scanner_20260322_143156.json
└── wifi_audit_suite_20260322_143200.json
```

Each JSON file contains:
- Complete scan data
- Findings categorized by severity
- Door-opener narrative
- Remediation recommendations
- MITRE ATT&CK mapping

---

## ⚡ Performance Characteristics

| Tool | Typical Runtime | Network Requirements |
|------|---|---|
| Rogue AP Detector | 10-15s | WiFi scanning permission |
| Client Isolation Tester | 30-45s | Connected to network |
| Router Default Checker | 10-20s | Can reach gateway |
| Network Exposure Scanner | 45-60s | Same network as targets |
| **Full Suite** | **2-3 minutes** | All above |

---

## 🔒 Security & Ethics

### ⚠️ CRITICAL: Authorization Required
```
These tools are designed ONLY for authorized security testing on networks
you own or have EXPLICIT WRITTEN PERMISSION to test.

Unauthorized network scanning is ILLEGAL under:
- Computer Fraud and Abuse Act (USA)
- Computer Misuse Act (UK)
- NetzDG (Germany)
- Various other jurisdictions

ALWAYS obtain written authorization before testing.
```

### Safe Usage
1. Get written permission from network owner
2. Define scope (which networks to test)
3. Schedule testing for off-peak hours
4. Use demo mode first to review reports
5. Provide results to authorized contacts only

---

## 🐛 Troubleshooting

### "No networks found" on Linux
```bash
# Try with nmcli (NetworkManager required)
nmcli dev wifi list

# Or try iwlist
iwlist wlan0 scan

# Or use --demo mode to verify tool works
python3 rogue_ap_detector.py --demo
```

### Port scanning slow on Linux
- Default socket timeout is 0.3-0.5s (fast)
- Large subnets take longer (254 hosts × 15 ports)
- Use `--subnet 192.168.1.100/25` to scan smaller range

### Router not detected
- Some routers use HTTPS-only (port 443/8443)
- Check if router admin is accessible via browser first
- Try explicit IP: `python3 router_default_checker.py --host 10.0.0.1`

### Permission denied errors (Termux)
```bash
# Grant WiFi permission in Termux
termux-wifi-scaninfo

# If still fails, use --demo mode
```

---

## 📝 Example Door-Opener Script

**What you say to the business owner:**

*"During our WiFi security assessment, we discovered several critical issues that put your business and customers at risk. Let me walk you through what we found..."*

**Show the report:**
- Print `wifi_audit_suite_[timestamp].txt`
- Share JSON report via email
- Walk through the "Door Opener Narrative" section

**Recommended Actions Workflow:**
1. Enable AP Isolation (5 minutes)
2. Change router admin password (2 minutes)
3. Move POS to separate network (30 minutes planning)
4. Disable Telnet/FTP (10 minutes)
5. Schedule follow-up audit in 30 days

---

## 🔗 Integration with Purple Team Suite

These WiFi tools integrate with the larger Purple Team Security Suite:

```
purple_team_suite/
├── orchestrator.py          (Main suite coordinator)
├── wifi/
│   ├── rogue_ap_detector.py
│   ├── client_isolation_tester.py
│   ├── router_default_checker.py
│   ├── network_exposure_scanner.py
│   └── wifi_audit_suite.py
├── network/                 (Network tools)
├── web_discovery/           (Web reconnaissance)
├── ssl_tls/                (SSL/TLS assessment)
└── kali_integration/        (Kali Linux extensions)
```

---

## 📖 References

- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **PCI DSS Compliance**: https://www.pcisecuritystandards.org/
- **OWASP Network Testing**: https://owasp.org/

---

## 📄 License & Disclaimers

**Purple Team WiFi Audit Suite** - Ethical Security Testing Tool

```
⚠️  WARNING: AUTHORIZED USE ONLY
This tool is designed for authorized security testing only.
Unauthorized use is illegal.

Use at your own risk. The authors assume no liability for misuse.
```

---

## 🎓 Training & Methodology

### Typical Assessment Workflow

1. **Pre-Assessment**
   - Obtain written authorization
   - Schedule with network owner
   - Review existing documentation

2. **Execution** (use WiFi Audit Suite)
   - Run `wifi_audit_suite.py --demo` first (show capabilities)
   - Connect to target WiFi
   - Run `wifi_audit_suite.py` for live assessment
   - Duration: 2-3 minutes

3. **Analysis**
   - Review findings from each tool
   - Aggregate critical issues
   - Check PCI DSS violations

4. **Reporting**
   - Share generated report
   - Walk through door-opener narrative
   - Prioritize remediation actions
   - Schedule follow-up

---

## 💡 Pro Tips

### For SMB/Restaurant Owners
- Run quarterly audits to track improvement
- Use --demo mode to understand what we test
- Share results with IT person/managed service provider
- Budget 30-60 min follow-up meetings to plan fixes

### For Security Professionals
- Run all tools via `wifi_audit_suite.py` for consistency
- Customize demo data in each tool for your methodology
- Export JSON for integration with ticketing systems
- Use reports as proof-of-concept for bigger engagements

### For Managed Service Providers
- Add WiFi audits to quarterly compliance checks
- Use demo mode in proposals to show findings
- Run tools from Kali for standardization
- Save results in customer folder structure

---

**Purple Team WiFi Audit Suite** | Version 1.0 | 2026
