"""
CodeAlpha NIDS - Network Intrusion Detection System
Core detection engine using Scapy for packet analysis.
"""

import time
import json
import threading
from collections import defaultdict, deque
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, ARP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not available - running in simulation mode")

# ─── Shared State (thread-safe) ───────────────────────────────────────────────

class NIDSState:
    def __init__(self):
        self.lock = threading.Lock()
        self.alerts = deque(maxlen=500)
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "other_packets": 0,
            "total_alerts": 0,
            "start_time": datetime.now().isoformat(),
        }
        self.traffic_timeline = deque(maxlen=60)   # last 60 seconds
        self.alert_counts_by_type = defaultdict(int)
        self.top_sources = defaultdict(int)
        self.top_destinations = defaultdict(int)
        self._last_timeline_tick = time.time()
        self._tick_counter = defaultdict(int)

    def add_alert(self, alert_type, severity, src_ip, dst_ip, detail, protocol="TCP"):
        with self.lock:
            alert = {
                "id": self.stats["total_alerts"] + 1,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
                "type": alert_type,
                "severity": severity,   # HIGH / MEDIUM / LOW
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "detail": detail,
            }
            self.alerts.appendleft(alert)
            self.stats["total_alerts"] += 1
            self.alert_counts_by_type[alert_type] += 1
        logger.warning(f"[{severity}] {alert_type}: {src_ip} → {dst_ip} | {detail}")

    def record_packet(self, proto, src_ip=None, dst_ip=None):
        with self.lock:
            self.stats["total_packets"] += 1
            self.stats[f"{proto}_packets"] = self.stats.get(f"{proto}_packets", 0) + 1
            if src_ip:
                self.top_sources[src_ip] += 1
            if dst_ip:
                self.top_destinations[dst_ip] += 1
            self._tick_counter[proto] += 1

            now = time.time()
            if now - self._last_timeline_tick >= 1.0:
                self.traffic_timeline.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "tcp": self._tick_counter.get("tcp", 0),
                    "udp": self._tick_counter.get("udp", 0),
                    "icmp": self._tick_counter.get("icmp", 0),
                })
                self._tick_counter.clear()
                self._last_timeline_tick = now

    def get_snapshot(self):
        with self.lock:
            return {
                "stats": dict(self.stats),
                "alerts": list(self.alerts)[:50],
                "timeline": list(self.traffic_timeline),
                "alert_types": dict(self.alert_counts_by_type),
                "top_sources": sorted(self.top_sources.items(), key=lambda x: x[1], reverse=True)[:10],
                "top_destinations": sorted(self.top_destinations.items(), key=lambda x: x[1], reverse=True)[:10],
            }

state = NIDSState()

# ─── Detection Rules ──────────────────────────────────────────────────────────

class DetectionEngine:
    # Thresholds
    SYN_FLOOD_THRESHOLD    = 100   # SYN packets from same IP per 5s
    PORT_SCAN_THRESHOLD    = 15    # distinct ports hit per 5s
    ICMP_FLOOD_THRESHOLD   = 50    # ICMP packets per 5s
    LARGE_PAYLOAD_BYTES    = 9000  # oversized packet

    SUSPICIOUS_PORTS = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        4444: "Metasploit default",
        5555: "Android ADB",
        6666: "IRC/malware",
        6667: "IRC",
        8080: "HTTP Alt/proxy",
        31337: "Elite/Back Orifice",
        12345: "NetBus",
        1337: "Common exploit port",
    }

    PRIVATE_RANGES = [
        ("10.0.0.0",    "10.255.255.255"),
        ("172.16.0.0",  "172.31.255.255"),
        ("192.168.0.0", "192.168.255.255"),
    ]

    def __init__(self):
        self._syn_tracker   = defaultdict(list)    # ip -> [timestamps]
        self._port_tracker  = defaultdict(set)     # ip -> set of ports
        self._port_times    = defaultdict(float)   # ip -> window start
        self._icmp_tracker  = defaultdict(list)
        self._lock = threading.Lock()

    def _clean_window(self, tracker, ip, window=5.0):
        now = time.time()
        tracker[ip] = [t for t in tracker[ip] if now - t < window]

    def check_syn_flood(self, src_ip, flags):
        if flags and "S" in flags and "A" not in flags:
            with self._lock:
                self._syn_tracker[src_ip].append(time.time())
                self._clean_window(self._syn_tracker, src_ip)
                count = len(self._syn_tracker[src_ip])
            if count > self.SYN_FLOOD_THRESHOLD:
                return True, count
        return False, 0

    def check_port_scan(self, src_ip, dst_port):
        with self._lock:
            now = time.time()
            if now - self._port_times.get(src_ip, 0) > 5.0:
                self._port_tracker[src_ip] = set()
                self._port_times[src_ip] = now
            self._port_tracker[src_ip].add(dst_port)
            count = len(self._port_tracker[src_ip])
        if count > self.PORT_SCAN_THRESHOLD:
            return True, count
        return False, 0

    def check_icmp_flood(self, src_ip):
        with self._lock:
            self._icmp_tracker[src_ip].append(time.time())
            self._clean_window(self._icmp_tracker, src_ip)
            count = len(self._icmp_tracker[src_ip])
        if count > self.ICMP_FLOOD_THRESHOLD:
            return True, count
        return False, 0

    def check_suspicious_port(self, port):
        return port in self.SUSPICIOUS_PORTS, self.SUSPICIOUS_PORTS.get(port, "")

    def check_large_payload(self, pkt_len):
        return pkt_len > self.LARGE_PAYLOAD_BYTES

    def check_arp_spoofing(self, src_ip, src_mac, arp_cache):
        if src_ip in arp_cache and arp_cache[src_ip] != src_mac:
            return True, arp_cache[src_ip]
        return False, None

engine = DetectionEngine()
arp_cache = {}

# ─── Packet Processor ─────────────────────────────────────────────────────────

def process_packet(pkt):
    try:
        if IP not in pkt:
            # ARP spoofing detection
            if ARP in pkt and SCAPY_AVAILABLE:
                src_ip  = pkt[ARP].psrc
                src_mac = pkt[ARP].hwsrc
                spoofed, old_mac = engine.check_arp_spoofing(src_ip, src_mac, arp_cache)
                if spoofed:
                    state.add_alert("ARP Spoofing", "HIGH", src_ip, "BROADCAST",
                                    f"MAC changed {old_mac} → {src_mac}", "ARP")
                else:
                    arp_cache[src_ip] = src_mac
            return

        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        pkt_len = len(pkt)

        # ── TCP ──────────────────────────────────────────────────────────────
        if TCP in pkt:
            state.record_packet("tcp", src_ip, dst_ip)
            flags    = str(pkt[TCP].flags)
            dst_port = pkt[TCP].dport
            src_port = pkt[TCP].sport

            # SYN Flood
            flooded, count = engine.check_syn_flood(src_ip, flags)
            if flooded:
                state.add_alert("SYN Flood", "HIGH", src_ip, dst_ip,
                                f"{count} SYN packets in 5s window", "TCP")

            # Port Scan
            scanned, ports = engine.check_port_scan(src_ip, dst_port)
            if scanned:
                state.add_alert("Port Scan", "MEDIUM", src_ip, dst_ip,
                                f"Scanning {ports} distinct ports", "TCP")

            # Suspicious port
            suspicious, svc = engine.check_suspicious_port(dst_port)
            if suspicious:
                state.add_alert("Suspicious Port Access", "MEDIUM", src_ip, dst_ip,
                                f"Port {dst_port} ({svc}) targeted", "TCP")

            # Null / Xmas / FIN scan detection
            if flags == "":
                state.add_alert("NULL Scan", "MEDIUM", src_ip, dst_ip,
                                "TCP packet with no flags (NULL scan)", "TCP")
            elif "F" in flags and "P" in flags and "U" in flags:
                state.add_alert("XMAS Scan", "MEDIUM", src_ip, dst_ip,
                                "TCP XMAS scan detected (FPU flags)", "TCP")

            # Large payload
            if engine.check_large_payload(pkt_len):
                state.add_alert("Oversized Packet", "LOW", src_ip, dst_ip,
                                f"Packet size {pkt_len} bytes exceeds threshold", "TCP")

        # ── UDP ──────────────────────────────────────────────────────────────
        elif UDP in pkt:
            state.record_packet("udp", src_ip, dst_ip)
            dst_port = pkt[UDP].dport

            # DNS anomaly detection
            if DNS in pkt and pkt[UDP].sport == 53:
                try:
                    qname = pkt[DNS].qd.qname.decode() if pkt[DNS].qd else ""
                    if len(qname) > 100:
                        state.add_alert("DNS Tunneling", "HIGH", src_ip, dst_ip,
                                        f"Suspiciously long DNS query: {qname[:60]}...", "DNS")
                    labels = qname.rstrip('.').split('.')
                    if any(len(l) > 40 for l in labels):
                        state.add_alert("DNS Exfiltration", "HIGH", src_ip, dst_ip,
                                        f"Anomalous DNS label length detected", "DNS")
                except Exception:
                    pass

            suspicious, svc = engine.check_suspicious_port(dst_port)
            if suspicious:
                state.add_alert("Suspicious Port Access", "LOW", src_ip, dst_ip,
                                f"UDP port {dst_port} ({svc}) targeted", "UDP")

        # ── ICMP ─────────────────────────────────────────────────────────────
        elif ICMP in pkt:
            state.record_packet("icmp", src_ip, dst_ip)
            flooded, count = engine.check_icmp_flood(src_ip)
            if flooded:
                state.add_alert("ICMP Flood", "HIGH", src_ip, dst_ip,
                                f"{count} ICMP packets in 5s (ping flood)", "ICMP")

            # Oversized ICMP (ping of death)
            if pkt_len > 65500:
                state.add_alert("Ping of Death", "HIGH", src_ip, dst_ip,
                                f"Oversized ICMP packet: {pkt_len} bytes", "ICMP")

        else:
            state.record_packet("other", src_ip, dst_ip)

    except Exception as e:
        logger.debug(f"Packet processing error: {e}")


# ─── Simulation Mode ──────────────────────────────────────────────────────────

import random
import ipaddress

ATTACK_SCENARIOS = [
    ("SYN Flood",           "HIGH",   "TCP",  lambda: f"192.168.1.{random.randint(1,254)}",   lambda: f"10.0.0.{random.randint(1,10)}",    lambda: f"{random.randint(80,500)} SYN packets in 5s window"),
    ("Port Scan",           "MEDIUM", "TCP",  lambda: f"172.16.{random.randint(0,5)}.{random.randint(1,254)}", lambda: f"10.0.0.{random.randint(1,20)}", lambda: f"Scanning {random.randint(16,200)} distinct ports"),
    ("ICMP Flood",          "HIGH",   "ICMP", lambda: f"203.0.113.{random.randint(1,254)}",    lambda: f"192.168.1.1",                       lambda: f"{random.randint(51,300)} ICMP packets in 5s"),
    ("DNS Tunneling",       "HIGH",   "DNS",  lambda: f"198.51.100.{random.randint(1,50)}",    lambda: f"8.8.8.8",                           lambda: f"Long DNS query: {'x'*random.randint(60,90)}.evil.com"),
    ("Suspicious Port Access","MEDIUM","TCP", lambda: f"10.10.{random.randint(0,5)}.{random.randint(1,254)}", lambda: f"192.168.1.{random.randint(1,10)}", lambda: f"Port {random.choice([4444,31337,6667,23,3389])} targeted"),
    ("ARP Spoofing",        "HIGH",   "ARP",  lambda: f"192.168.0.{random.randint(1,10)}",     lambda: "192.168.0.1",                        lambda: f"MAC changed aa:bb:cc:dd:ee:{random.randint(10,99):02x} → ff:ff:ff:ff:ff:ff"),
    ("NULL Scan",           "MEDIUM", "TCP",  lambda: f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}", lambda: f"10.0.0.{random.randint(1,5)}", lambda: "TCP packet with no flags (NULL scan)"),
    ("Oversized Packet",    "LOW",    "TCP",  lambda: f"192.168.2.{random.randint(1,50)}",     lambda: f"10.0.0.{random.randint(1,5)}",      lambda: f"Packet size {random.randint(9001,65000)} bytes"),
    ("XMAS Scan",           "MEDIUM", "TCP",  lambda: f"77.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}", lambda: f"192.168.1.{random.randint(1,20)}", lambda: "TCP XMAS scan detected (FPU flags)"),
    ("DNS Exfiltration",    "HIGH",   "DNS",  lambda: f"203.{random.randint(1,99)}.{random.randint(1,254)}.{random.randint(1,254)}", lambda: "1.1.1.1", lambda: "Anomalous DNS label length detected"),
]

def simulation_loop():
    """Generate realistic-looking traffic and alerts for demo purposes."""
    logger.info("Running in SIMULATION MODE — no root/Scapy required")
    protos = ["tcp", "udp", "icmp", "other"]
    weights = [0.6, 0.25, 0.1, 0.05]

    while True:
        # Normal traffic burst
        for _ in range(random.randint(5, 25)):
            proto = random.choices(protos, weights=weights)[0]
            src = f"{random.randint(10,200)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            dst = f"10.0.0.{random.randint(1,20)}"
            state.record_packet(proto, src, dst)

        # Occasionally fire an alert
        if random.random() < 0.35:
            scenario = random.choice(ATTACK_SCENARIOS)
            name, severity, proto, src_fn, dst_fn, detail_fn = scenario
            state.add_alert(name, severity, src_fn(), dst_fn(), detail_fn(), proto)

        time.sleep(random.uniform(0.3, 1.2))


def start_capture(interface=None, simulate=False):
    """Start packet capture or simulation."""
    if simulate or not SCAPY_AVAILABLE:
        t = threading.Thread(target=simulation_loop, daemon=True)
        t.start()
        return

    try:
        logger.info(f"Starting live capture on interface: {interface or 'default'}")
        sniff(
            iface=interface,
            prn=process_packet,
            store=False,
            filter="ip or arp",
        )
    except PermissionError:
        logger.warning("Permission denied — switching to simulation mode (run with sudo for live capture)")
        simulation_loop()
    except Exception as e:
        logger.error(f"Capture error: {e} — switching to simulation mode")
        simulation_loop()
