# 🛡️ CodeAlpha — Network Intrusion Detection System (NIDS)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?style=for-the-badge&logo=flask&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-2.5-orange?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**A real-time Network Intrusion Detection System with a live web dashboard — built as part of the CodeAlpha Cybersecurity Internship.**

</div>

---

## 📌 Overview

This project is a Python-based **Network Intrusion Detection System (NIDS)** that monitors network traffic, detects malicious activity using custom rule-based detection, and visualizes everything through a sleek real-time web dashboard.

It covers the full pipeline — from raw packet capture all the way to alerting and visualization — making it a complete end-to-end security monitoring solution.

---

## 🎯 Features

- 🔴 **Real-Time Packet Capture** — Sniffs live network traffic using Scapy
- ⚡ **10 Detection Rules** — Covers a wide range of network attacks
- 📊 **Live Web Dashboard** — Beautiful dark-themed UI with auto-updating charts
- 🚨 **Instant Alerts** — Severity-based alerting (HIGH / MEDIUM / LOW)
- 🖥️ **Simulation Mode** — Run and demo without root privileges
- 🌐 **REST API** — JSON endpoints for integration with other tools

---

## 🔍 Detection Capabilities

| # | Attack Type | Severity | Protocol | How It's Detected |
|---|------------|----------|----------|--------------------|
| 1 | **SYN Flood** | 🔴 HIGH | TCP | >100 SYN packets from same IP in 5s |
| 2 | **Port Scan** | 🟠 MEDIUM | TCP | >15 distinct ports probed in 5s |
| 3 | **ICMP Flood** | 🔴 HIGH | ICMP | >50 ICMP packets in 5s window |
| 4 | **Ping of Death** | 🔴 HIGH | ICMP | ICMP packet size >65,500 bytes |
| 5 | **DNS Tunneling** | 🔴 HIGH | DNS | Query length exceeds 100 characters |
| 6 | **DNS Exfiltration** | 🔴 HIGH | DNS | Abnormally long DNS label detected |
| 7 | **ARP Spoofing** | 🔴 HIGH | ARP | MAC address change for a known IP |
| 8 | **NULL Scan** | 🟠 MEDIUM | TCP | TCP packet with zero flags set |
| 9 | **XMAS Scan** | 🟠 MEDIUM | TCP | FIN + PSH + URG flags set simultaneously |
| 10 | **Suspicious Port Access** | 🟠 MEDIUM | TCP/UDP | Known exploit ports targeted (4444, 31337, etc.) |

---

## 📊 Dashboard Preview

The live dashboard includes:

| Widget | Description |
|--------|-------------|
| 📈 **Traffic Timeline** | Live packets/sec graph for TCP, UDP, ICMP |
| 🥧 **Protocol Breakdown** | Donut chart showing traffic composition |
| 🚨 **Alert Feed** | Real-time table of all detected intrusions |
| ⚡ **Alert Types** | Distribution of threat categories |
| 🔴 **Top Source IPs** | Most active / suspicious source addresses |
| 🎯 **Top Destinations** | Most targeted hosts on the network |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/ishaluuu/CodeAlpha_NetworkIntrusionDetection.git

# 2. Navigate into the folder
cd CodeAlpha_NetworkIntrusionDetection

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the Dashboard

**Option 1 — Simulation Mode** *(No root required — perfect for demo)*
```bash
python dashboard.py --simulate
```

**Option 2 — Live Capture** *(Requires root/Administrator)*
```bash
# Linux / macOS
sudo python dashboard.py

# Specify a network interface
sudo python dashboard.py --interface eth0

# Windows (run Command Prompt as Administrator)
python dashboard.py
```

Then open your browser and go to:
```
http://localhost:5000
```

---

## ⚙️ Configuration

You can adjust detection thresholds in `nids_engine.py`:

```python
class DetectionEngine:
    SYN_FLOOD_THRESHOLD    = 100   # SYN packets per 5s window
    PORT_SCAN_THRESHOLD    = 15    # Distinct ports per 5s window
    ICMP_FLOOD_THRESHOLD   = 50    # ICMP packets per 5s window
    LARGE_PAYLOAD_BYTES    = 9000  # Oversized packet threshold
```

---

## 🏗️ Project Structure

```
CodeAlpha_NetworkIntrusionDetection/
│
├── nids_engine.py      # Core detection engine (packet capture + rules)
├── dashboard.py        # Flask web server + real-time dashboard UI
├── requirements.txt    # Python dependencies
└── README.md           # Project documentation
```

### How It Works

```
Network Traffic
      ↓
 Scapy Packet Sniffer
      ↓
 process_packet()
      ↓
 Detection Rules Engine
      ↓
 Shared State (thread-safe)
      ↓
 Flask REST API
      ↓
 Live Browser Dashboard
```

---

## 🛠️ CLI Options

```
python dashboard.py [OPTIONS]

Options:
  --interface, -i    Network interface to sniff (e.g. eth0, wlan0)
  --simulate,  -s    Run in simulation mode (no root needed)
  --port,      -p    Dashboard port (default: 5000)
  --host             Dashboard host (default: 0.0.0.0)
```

---

## 🧰 Tech Stack

| Tool | Purpose |
|------|---------|
| **Python** | Core language |
| **Scapy** | Packet capture & analysis |
| **Flask** | Web server & REST API |
| **Chart.js** | Live dashboard charts |
| **HTML/CSS/JS** | Frontend dashboard UI |

---

## ⚠️ Legal Disclaimer

> This tool was developed **strictly for educational purposes** as part of the CodeAlpha Cybersecurity Internship Program.
> Only deploy and use this tool on networks that **you own or have explicit written permission** to monitor.
> Unauthorized interception of network traffic may violate local, state, and federal laws.

---

## 👤 Author

**Risaal** — CodeAlpha Cybersecurity Internship  
🔗 [GitHub](https://github.com/ishaluuu) 
🔗 [LinkedIn](https://www.linkedin.com/in/risaal-riyas-4967b8382/)

---

## 🙏 Acknowledgements

- [CodeAlpha](https://codealpha.tech) — for providing this internship opportunity
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [OWASP](https://owasp.org/)
