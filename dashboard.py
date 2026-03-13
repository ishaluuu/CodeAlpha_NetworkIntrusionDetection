"""
CodeAlpha NIDS - Dashboard Server
Flask web app serving real-time intrusion detection data.
"""

import threading
import argparse
import sys
import os

from flask import Flask, jsonify, render_template_string
from nids_engine import state, start_capture

app = Flask(__name__)

# ─── HTML Dashboard ───────────────────────────────────────────────────────────

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>CodeAlpha NIDS — Intrusion Detection Dashboard</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;900&display=swap');

  :root {
    --bg:       #080c12;
    --surface:  #0d1520;
    --panel:    #111c2e;
    --border:   #1a2d4a;
    --accent:   #00d4ff;
    --red:      #ff3c5a;
    --orange:   #ff8c42;
    --green:    #00ff9f;
    --yellow:   #ffd60a;
    --text:     #c8d8e8;
    --muted:    #4a6080;
    --high:     #ff3c5a;
    --medium:   #ff8c42;
    --low:      #ffd60a;
    --glow:     0 0 20px rgba(0,212,255,0.15);
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Exo 2', sans-serif;
    font-size: 13px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed; inset: 0; z-index: 9999; pointer-events: none;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.03) 2px, rgba(0,0,0,0.03) 4px);
  }

  /* Header */
  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 28px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100;
    backdrop-filter: blur(8px);
  }

  .logo {
    display: flex; align-items: center; gap: 12px;
  }
  .logo-icon {
    width: 36px; height: 36px;
    background: linear-gradient(135deg, var(--accent), #005f8a);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px; box-shadow: 0 0 16px rgba(0,212,255,0.3);
  }
  .logo-text { font-size: 18px; font-weight: 900; letter-spacing: 1px; }
  .logo-text span { color: var(--accent); }
  .logo-sub { font-size: 10px; color: var(--muted); font-family: 'Share Tech Mono', monospace; letter-spacing: 2px; }

  .header-right { display: flex; align-items: center; gap: 20px; }

  .live-badge {
    display: flex; align-items: center; gap: 6px;
    background: rgba(0,255,159,0.08); border: 1px solid rgba(0,255,159,0.3);
    border-radius: 20px; padding: 4px 12px;
    font-size: 11px; color: var(--green); font-weight: 700; letter-spacing: 1px;
  }
  .live-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--green);
    animation: pulse 1.4s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 0 0 rgba(0,255,159,0.5); }
    50% { opacity: 0.6; box-shadow: 0 0 0 5px rgba(0,255,159,0); }
  }

  .uptime { font-family: 'Share Tech Mono', monospace; color: var(--muted); font-size: 11px; }

  /* Layout */
  main { padding: 20px 24px; max-width: 1600px; margin: 0 auto; }

  /* Stat cards */
  .stats-row {
    display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 20px;
  }

  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 16px;
    position: relative; overflow: hidden;
    transition: border-color 0.2s;
  }
  .stat-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: var(--accent-color, var(--accent));
  }
  .stat-card:hover { border-color: var(--accent); box-shadow: var(--glow); }

  .stat-label { font-size: 9px; letter-spacing: 2px; color: var(--muted); text-transform: uppercase; margin-bottom: 6px; }
  .stat-value { font-family: 'Share Tech Mono', monospace; font-size: 26px; font-weight: 700; color: var(--accent-color, var(--accent)); }
  .stat-sub { font-size: 9px; color: var(--muted); margin-top: 2px; }

  /* Grid layout */
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  .span-2 { grid-column: span 2; }

  /* Panels */
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }
  .panel-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    background: var(--panel);
  }
  .panel-title {
    font-size: 11px; font-weight: 700; letter-spacing: 2px;
    text-transform: uppercase; color: var(--accent);
    display: flex; align-items: center; gap: 8px;
  }
  .panel-body { padding: 14px; }

  /* Charts */
  .chart-wrap { position: relative; height: 180px; }
  .chart-wrap-sm { position: relative; height: 150px; }

  /* Alerts table */
  .alerts-table { width: 100%; border-collapse: collapse; }
  .alerts-table th {
    font-size: 9px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--muted); padding: 8px 10px; text-align: left;
    border-bottom: 1px solid var(--border);
  }
  .alerts-table td { padding: 7px 10px; border-bottom: 1px solid rgba(26,45,74,0.5); font-size: 11px; vertical-align: middle; }

  .alerts-table tr { transition: background 0.15s; }
  .alerts-table tr:hover td { background: rgba(0,212,255,0.04); }

  .alert-row-HIGH td:first-child { border-left: 3px solid var(--high); }
  .alert-row-MEDIUM td:first-child { border-left: 3px solid var(--medium); }
  .alert-row-LOW td:first-child { border-left: 3px solid var(--low); }

  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 9px; font-weight: 700; letter-spacing: 1px;
  }
  .badge-HIGH   { background: rgba(255,60,90,0.15);  color: var(--high);   border: 1px solid rgba(255,60,90,0.3); }
  .badge-MEDIUM { background: rgba(255,140,66,0.15); color: var(--medium); border: 1px solid rgba(255,140,66,0.3); }
  .badge-LOW    { background: rgba(255,214,10,0.15); color: var(--low);    border: 1px solid rgba(255,214,10,0.3); }

  .proto-badge {
    display: inline-block; padding: 1px 6px; border-radius: 3px;
    font-family: 'Share Tech Mono', monospace; font-size: 9px;
    background: rgba(0,212,255,0.08); color: var(--accent);
    border: 1px solid rgba(0,212,255,0.2);
  }

  .mono { font-family: 'Share Tech Mono', monospace; color: var(--text); }
  .muted { color: var(--muted); }

  /* Top IPs */
  .ip-list { list-style: none; }
  .ip-list li {
    display: flex; align-items: center; justify-content: space-between;
    padding: 6px 0;
    border-bottom: 1px solid rgba(26,45,74,0.5);
    font-size: 11px;
  }
  .ip-list li:last-child { border-bottom: none; }
  .ip-bar-wrap { flex: 1; margin: 0 10px; height: 3px; background: var(--border); border-radius: 2px; overflow: hidden; }
  .ip-bar { height: 100%; background: var(--accent); border-radius: 2px; transition: width 0.4s; }
  .ip-count { font-family: 'Share Tech Mono', monospace; color: var(--accent); font-size: 10px; min-width: 36px; text-align: right; }

  /* Threat type list */
  .type-list { list-style: none; }
  .type-list li {
    display: flex; align-items: center; gap: 8px;
    padding: 6px 0;
    border-bottom: 1px solid rgba(26,45,74,0.5);
    font-size: 11px;
  }
  .type-list li:last-child { border-bottom: none; }
  .type-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .type-count { margin-left: auto; font-family: 'Share Tech Mono', monospace; color: var(--orange); }

  /* Alerts container scroll */
  .alerts-scroll { max-height: 340px; overflow-y: auto; }
  .alerts-scroll::-webkit-scrollbar { width: 4px; }
  .alerts-scroll::-webkit-scrollbar-track { background: var(--panel); }
  .alerts-scroll::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  /* New alert flash */
  @keyframes flashIn {
    from { background: rgba(0,212,255,0.1); }
    to   { background: transparent; }
  }
  .new-alert { animation: flashIn 1.2s ease-out; }

  /* No data */
  .empty { padding: 30px; text-align: center; color: var(--muted); font-size: 11px; }

  /* Responsive */
  @media (max-width: 1100px) {
    .stats-row { grid-template-columns: repeat(3, 1fr); }
    .grid-3 { grid-template-columns: 1fr; }
    .grid-2 { grid-template-columns: 1fr; }
    .span-2 { grid-column: span 1; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🛡</div>
    <div>
      <div class="logo-text">Code<span>Alpha</span> NIDS</div>
      <div class="logo-sub">NETWORK INTRUSION DETECTION SYSTEM</div>
    </div>
  </div>
  <div class="header-right">
    <div class="uptime" id="clock">--:--:--</div>
    <div class="live-badge"><div class="live-dot"></div>LIVE MONITORING</div>
  </div>
</header>

<main>

  <!-- Stat Cards -->
  <div class="stats-row">
    <div class="stat-card" style="--accent-color: var(--accent)">
      <div class="stat-label">Total Packets</div>
      <div class="stat-value" id="s-total">0</div>
      <div class="stat-sub">captured</div>
    </div>
    <div class="stat-card" style="--accent-color: var(--red)">
      <div class="stat-label">Total Alerts</div>
      <div class="stat-value" id="s-alerts">0</div>
      <div class="stat-sub">detected</div>
    </div>
    <div class="stat-card" style="--accent-color: #4dabf7">
      <div class="stat-label">TCP Packets</div>
      <div class="stat-value" id="s-tcp">0</div>
      <div class="stat-sub">stream</div>
    </div>
    <div class="stat-card" style="--accent-color: var(--orange)">
      <div class="stat-label">UDP Packets</div>
      <div class="stat-value" id="s-udp">0</div>
      <div class="stat-sub">datagram</div>
    </div>
    <div class="stat-card" style="--accent-color: var(--yellow)">
      <div class="stat-label">ICMP Packets</div>
      <div class="stat-value" id="s-icmp">0</div>
      <div class="stat-sub">control msg</div>
    </div>
    <div class="stat-card" style="--accent-color: var(--green)">
      <div class="stat-label">HIGH Severity</div>
      <div class="stat-value" id="s-high">0</div>
      <div class="stat-sub">critical alerts</div>
    </div>
  </div>

  <!-- Row 1: Traffic Timeline + Alert Breakdown -->
  <div class="grid-2" style="grid-template-columns: 2fr 1fr; margin-bottom:16px">
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">📈 Live Traffic Timeline <span style="font-size:9px;color:var(--muted);font-weight:400">(packets/sec)</span></div>
      </div>
      <div class="panel-body">
        <div class="chart-wrap"><canvas id="timelineChart"></canvas></div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🥧 Traffic Breakdown</div>
      </div>
      <div class="panel-body">
        <div class="chart-wrap"><canvas id="protoChart"></canvas></div>
      </div>
    </div>
  </div>

  <!-- Row 2: Alerts Table -->
  <div class="panel" style="margin-bottom:16px">
    <div class="panel-header">
      <div class="panel-title">🚨 Live Alert Feed</div>
      <div style="font-size:9px;color:var(--muted)">Most recent first</div>
    </div>
    <div class="alerts-scroll">
      <table class="alerts-table">
        <thead>
          <tr>
            <th>#</th><th>Time</th><th>Severity</th><th>Type</th>
            <th>Source IP</th><th>Destination</th><th>Protocol</th><th>Detail</th>
          </tr>
        </thead>
        <tbody id="alertsTbody">
          <tr><td colspan="8" class="empty">Waiting for alerts...</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <!-- Row 3: Threat Types + Top Sources + Top Destinations -->
  <div class="grid-3">
    <div class="panel">
      <div class="panel-header"><div class="panel-title">⚡ Alert Types</div></div>
      <div class="panel-body">
        <ul class="type-list" id="typeList"><li><span class="muted">Collecting data...</span></li></ul>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><div class="panel-title">🔴 Top Source IPs</div></div>
      <div class="panel-body">
        <ul class="ip-list" id="srcList"><li><span class="muted">Collecting...</span></li></ul>
      </div>
    </div>
    <div class="panel">
      <div class="panel-header"><div class="panel-title">🎯 Top Destinations</div></div>
      <div class="panel-body">
        <ul class="ip-list" id="dstList"><li><span class="muted">Collecting...</span></li></ul>
      </div>
    </div>
  </div>

</main>

<script>
// ── Chart setup ────────────────────────────────────────────────────────────────
const accent   = '#00d4ff';
const red      = '#ff3c5a';
const orange   = '#ff8c42';
const yellow   = '#ffd60a';
const green    = '#00ff9f';
const gridCol  = 'rgba(26,45,74,0.6)';
const textCol  = '#4a6080';

Chart.defaults.color = textCol;
Chart.defaults.font.family = "'Share Tech Mono', monospace";
Chart.defaults.font.size = 10;

// Timeline chart
const timelineCtx = document.getElementById('timelineChart').getContext('2d');
const timelineChart = new Chart(timelineCtx, {
  type: 'line',
  data: {
    labels: [],
    datasets: [
      { label: 'TCP',  data: [], borderColor: accent,  backgroundColor: 'rgba(0,212,255,0.08)', tension: 0.4, fill: true, pointRadius: 0, borderWidth: 2 },
      { label: 'UDP',  data: [], borderColor: orange,  backgroundColor: 'rgba(255,140,66,0.06)', tension: 0.4, fill: true, pointRadius: 0, borderWidth: 1.5 },
      { label: 'ICMP', data: [], borderColor: yellow,  backgroundColor: 'rgba(255,214,10,0.05)', tension: 0.4, fill: true, pointRadius: 0, borderWidth: 1.5 },
    ]
  },
  options: {
    responsive: true, maintainAspectRatio: false, animation: { duration: 300 },
    plugins: { legend: { position: 'top', labels: { boxWidth: 10, padding: 12, color: textCol } } },
    scales: {
      x: { grid: { color: gridCol }, ticks: { maxTicksLimit: 8, color: textCol } },
      y: { grid: { color: gridCol }, ticks: { color: textCol }, beginAtZero: true }
    }
  }
});

// Protocol donut
const protoCtx = document.getElementById('protoChart').getContext('2d');
const protoChart = new Chart(protoCtx, {
  type: 'doughnut',
  data: {
    labels: ['TCP', 'UDP', 'ICMP', 'Other'],
    datasets: [{ data: [0,0,0,0], backgroundColor: [accent, orange, yellow, '#7b5ea7'],
      borderColor: '#0d1520', borderWidth: 3, hoverOffset: 6 }]
  },
  options: {
    responsive: true, maintainAspectRatio: false, animation: { duration: 500 },
    cutout: '68%',
    plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 10, color: textCol } } }
  }
});

// ── State ─────────────────────────────────────────────────────────────────────
let lastAlertId = 0;
let highCount = 0;

// ── Fetch & update ─────────────────────────────────────────────────────────────
async function fetchData() {
  try {
    const res = await fetch('/api/snapshot');
    const d = await res.json();

    // Stats
    const st = d.stats;
    document.getElementById('s-total').textContent  = fmt(st.total_packets);
    document.getElementById('s-alerts').textContent = fmt(st.total_alerts);
    document.getElementById('s-tcp').textContent    = fmt(st.tcp_packets || 0);
    document.getElementById('s-udp').textContent    = fmt(st.udp_packets || 0);
    document.getElementById('s-icmp').textContent   = fmt(st.icmp_packets || 0);

    // High count from alerts
    highCount = (d.alerts || []).filter(a => a.severity === 'HIGH').length;
    // Actually get cumulative from alert_types
    const high = d.alerts.filter(a => a.severity === 'HIGH').length;
    document.getElementById('s-high').textContent = fmt(high);

    // Timeline
    const tl = d.timeline || [];
    if (tl.length) {
      timelineChart.data.labels = tl.map(t => t.time);
      timelineChart.data.datasets[0].data = tl.map(t => t.tcp);
      timelineChart.data.datasets[1].data = tl.map(t => t.udp);
      timelineChart.data.datasets[2].data = tl.map(t => t.icmp);
      timelineChart.update('none');
    }

    // Protocol donut
    protoChart.data.datasets[0].data = [
      st.tcp_packets || 0, st.udp_packets || 0,
      st.icmp_packets || 0, st.other_packets || 0
    ];
    protoChart.update('none');

    // Alerts table
    updateAlerts(d.alerts || []);

    // Alert types
    updateTypeList(d.alert_types || {});

    // Top IPs
    updateIPList('srcList', d.top_sources || []);
    updateIPList('dstList', d.top_destinations || []);

  } catch(e) { console.warn('Fetch error:', e); }
}

function fmt(n) {
  if (n >= 1000000) return (n/1000000).toFixed(1) + 'M';
  if (n >= 1000)    return (n/1000).toFixed(1) + 'K';
  return String(n);
}

function updateAlerts(alerts) {
  if (!alerts.length) return;
  const tbody = document.getElementById('alertsTbody');
  const newAlerts = alerts.filter(a => a.id > lastAlertId);
  if (!newAlerts.length && tbody.children.length > 0 && !tbody.children[0].classList.contains('empty')) return;

  if (newAlerts.length) lastAlertId = Math.max(...alerts.map(a => a.id));

  tbody.innerHTML = alerts.slice(0,50).map((a, i) => `
    <tr class="alert-row-${a.severity}${i < newAlerts.length ? ' new-alert' : ''}">
      <td class="mono muted">${String(a.id).padStart(4,'0')}</td>
      <td class="mono muted">${a.timestamp}</td>
      <td><span class="badge badge-${a.severity}">${a.severity}</span></td>
      <td style="color:var(--text);font-weight:600">${a.type}</td>
      <td class="mono" style="color:var(--red)">${a.src_ip}</td>
      <td class="mono muted">${a.dst_ip}</td>
      <td><span class="proto-badge">${a.protocol}</span></td>
      <td class="muted" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${a.detail}">${a.detail}</td>
    </tr>
  `).join('');
}

const TYPE_COLORS = ['#00d4ff','#ff3c5a','#ff8c42','#ffd60a','#00ff9f','#7b5ea7','#4dabf7','#f783ac','#69db7c','#e599f7'];
function updateTypeList(types) {
  const sorted = Object.entries(types).sort((a,b)=>b[1]-a[1]);
  const total = sorted.reduce((s,[,v])=>s+v,0)||1;
  document.getElementById('typeList').innerHTML = sorted.slice(0,10).map(([name,count],i)=>`
    <li>
      <div class="type-dot" style="background:${TYPE_COLORS[i%TYPE_COLORS.length]}"></div>
      <span>${name}</span>
      <div class="ip-bar-wrap"><div class="ip-bar" style="width:${(count/total*100).toFixed(1)}%;background:${TYPE_COLORS[i%TYPE_COLORS.length]}"></div></div>
      <span class="type-count">${count}</span>
    </li>
  `).join('') || '<li><span class="muted">No alerts yet</span></li>';
}

function updateIPList(id, items) {
  const max = items[0]?.[1] || 1;
  document.getElementById(id).innerHTML = items.slice(0,8).map(([ip, count])=>`
    <li>
      <span class="mono" style="font-size:10px;min-width:110px">${ip}</span>
      <div class="ip-bar-wrap"><div class="ip-bar" style="width:${(count/max*100).toFixed(1)}%"></div></div>
      <span class="ip-count">${fmt(count)}</span>
    </li>
  `).join('') || '<li><span class="muted">No data</span></li>';
}

// Clock
function updateClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// Poll every 1.5 seconds
fetchData();
setInterval(fetchData, 1500);
</script>
</body>
</html>
"""

# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/snapshot")
def snapshot():
    return jsonify(state.get_snapshot())

@app.route("/api/alerts")
def alerts():
    snap = state.get_snapshot()
    return jsonify(snap["alerts"])

@app.route("/api/stats")
def stats():
    snap = state.get_snapshot()
    return jsonify(snap["stats"])

# ─── Entry Point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="CodeAlpha NIDS — Network Intrusion Detection System")
    parser.add_argument("--interface", "-i", default=None, help="Network interface to sniff (requires root)")
    parser.add_argument("--simulate", "-s", action="store_true", help="Run in simulation mode (no root required)")
    parser.add_argument("--port", "-p", type=int, default=5000, help="Dashboard port (default: 5000)")
    parser.add_argument("--host", default="0.0.0.0", help="Dashboard host (default: 0.0.0.0)")
    args = parser.parse_args()

    print("""
╔══════════════════════════════════════════════════════╗
║         CodeAlpha NIDS — Intrusion Detection         ║
║              Cybersecurity Internship Task 4         ║
╚══════════════════════════════════════════════════════╝
""")

    # Start capture in background thread
    capture_thread = threading.Thread(
        target=start_capture,
        kwargs={"interface": args.interface, "simulate": args.simulate},
        daemon=True
    )
    capture_thread.start()

    print(f"  🛡  Dashboard:  http://localhost:{args.port}")
    print(f"  📡 Mode:       {'SIMULATION' if args.simulate else 'LIVE CAPTURE'}")
    if not args.simulate:
        print(f"  🔌 Interface:  {args.interface or 'default'}")
        print(f"  ⚠️  Note: Run with sudo for live packet capture")
    print()

    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
