# 🛡️ CodeAlpha NIDS — Network Intrusion Detection System

> **CodeAlpha Cybersecurity Internship — Task 4**  
> A Python-based Network Intrusion Detection System with real-time web dashboard.

---

## 📸 Features

- **Live Packet Capture** — Captures and analyzes network traffic using Scapy
- **10 Detection Rules** — SYN Flood, Port Scan, ICMP Flood, DNS Tunneling, ARP Spoofing, NULL/XMAS Scans, and more
- **Real-Time Dashboard** — Live web UI with charts, alert feed, and traffic analytics
- **Simulation Mode** — Runs without root/admin privileges for demo purposes
- **Zero External Dashboard Dependencies** — Pure HTML/JS frontend served by Flask

---

## 🔍 Detection Capabilities

| Attack Type | Severity | Protocol | Detection Method |
|------------|----------|----------|-----------------|
| SYN Flood | 🔴 HIGH | TCP | >100 SYN packets from same IP in 5s |
| Port Scan | 🟠 MEDIUM | TCP | >15 distinct ports probed in 5s |
| ICMP Flood / Ping of Death | 🔴 HIGH | ICMP | >50 pings/5s or oversized ICMP |
| DNS Tunneling | 🔴 HIGH | DNS/UDP | Query length >100 chars |
| DNS Exfiltration | 🔴 HIGH | DNS/UDP | Abnormal label lengths |
| ARP Spoofing | 🔴 HIGH | ARP | MAC address change for known IP |
| NULL Scan | 🟠 MEDIUM | TCP | TCP packet with no flags set |
| XMAS Scan | 🟠 MEDIUM | TCP | FIN+PSH+URG flags set |
| Suspicious Port Access | 🟠 MEDIUM | TCP/UDP | Known exploit ports (4444, 31337, etc.) |
| Oversized Packet | 🟡 LOW | TCP | Packet >9000 bytes |

---

## 🚀 Quick Start

### Prerequisites

```bash
pip install -r requirements.txt
```

### Option 1: Simulation Mode (No root required)
```bash
python dashboard.py --simulate
```

### Option 2: Live Capture (Requires root/admin)
```bash
# Linux/Mac
sudo python dashboard.py

# Specify interface
sudo python dashboard.py --interface eth0

# Windows (run as Administrator)
python dashboard.py
```

Then open your browser at: **http://localhost:5000**

---

## 📊 Dashboard Overview

The web dashboard provides:

- **Live Traffic Timeline** — Packets/sec graph for TCP, UDP, ICMP
- **Protocol Breakdown** — Donut chart of traffic composition  
- **Alert Feed** — Real-time table of detected intrusions with severity badges
- **Alert Type Distribution** — Bar chart of threat categories
- **Top Source IPs** — Most active (potentially malicious) sources
- **Top Destination IPs** — Most targeted hosts

---

## ⚙️ Configuration

Edit thresholds in `nids_engine.py`:

```python
class DetectionEngine:
    SYN_FLOOD_THRESHOLD    = 100   # SYN packets per 5s
    PORT_SCAN_THRESHOLD    = 15    # distinct ports per 5s  
    ICMP_FLOOD_THRESHOLD   = 50    # ICMP packets per 5s
    LARGE_PAYLOAD_BYTES    = 9000  # oversized packet threshold
```

### Suspicious Ports

The following ports trigger medium-severity alerts when targeted:

```
22    SSH          3389  RDP          4444  Metasploit
23    Telnet       5555  Android ADB  6667  IRC
31337 Back Orifice 12345 NetBus       1337  Exploit port
```

---

## 🏗️ Architecture

```
nids/
├── nids_engine.py    # Core detection engine (Scapy + rules)
├── dashboard.py      # Flask server + HTML dashboard
├── requirements.txt  # Python dependencies
└── README.md
```

**Data flow:**
```
Network Interface
      ↓
  Scapy sniffer (nids_engine.py)
      ↓
  process_packet()
      ↓
  DetectionEngine rules
      ↓
  NIDSState (thread-safe store)
      ↓
  Flask API (/api/snapshot)
      ↓
  Browser Dashboard (polling every 1.5s)
```

---

## 🛠️ CLI Options

```
usage: dashboard.py [-h] [--interface INTERFACE] [--simulate] [--port PORT] [--host HOST]

options:
  -h, --help            show this help message and exit
  --interface, -i       Network interface (e.g. eth0, wlan0)
  --simulate, -s        Simulation mode — no root required
  --port, -p            Dashboard port (default: 5000)
  --host                Dashboard host (default: 0.0.0.0)
```

---

## ⚠️ Legal Disclaimer

> This tool is developed **for educational purposes only** as part of the CodeAlpha Cybersecurity Internship.  
> Only use on networks you **own or have explicit permission** to monitor.  
> Unauthorized network monitoring may violate local laws.

---

## 👤 Author

**CodeAlpha Cybersecurity Internship**  
Task 4 — Network Intrusion Detection System  

---

## 📚 References

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Snort Rule Writing Guide](https://docs.snort.org/)
- [MITRE ATT&CK — Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [OWASP Network Intrusion Detection](https://owasp.org/)
