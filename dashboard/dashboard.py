#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   WEB DASHBOARD - dashboard.py                      ║
║   Flask-based real-time threat dashboard            ║
╚══════════════════════════════════════════════════════╝
Run: python3 dashboard/dashboard.py
Access: http://localhost:5000
"""

import sys
import json
import threading
import time
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from flask import Flask, render_template_string, jsonify, request
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("Flask not installed. Run: pip3 install flask")

from core.threat_engine import ThreatHunter
from core.log_parser import LogParser

# ─── Shared state ─────────────────────────────────────────────────────────────
hunter = ThreatHunter()
log_parser = LogParser(hunter)

# ─── HTML Template ────────────────────────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Hunter Dashboard</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;800&display=swap');
        
        :root {
            --bg: #030712;
            --panel: #0d1117;
            --border: #1a2332;
            --red: #ff3355;
            --orange: #ff8800;
            --yellow: #ffcc00;
            --green: #00ff88;
            --cyan: #00d4ff;
            --blue: #4488ff;
            --text: #c9d1d9;
            --dim: #58697a;
            --critical: #ff0044;
            --high: #ff4400;
            --medium: #ff8800;
            --low: #44aaff;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            background: var(--bg);
            color: var(--text);
            font-family: 'Share Tech Mono', monospace;
            min-height: 100vh;
            overflow-x: hidden;
        }
        
        /* Animated grid background */
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background-image: 
                linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px);
            background-size: 40px 40px;
            pointer-events: none;
            z-index: 0;
        }
        
        .container { position: relative; z-index: 1; padding: 0 20px 20px; }
        
        /* Header */
        header {
            background: linear-gradient(135deg, #0d1117 0%, #0a1628 100%);
            border-bottom: 1px solid var(--cyan);
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 0 30px rgba(0,212,255,0.1);
        }
        
        .logo {
            font-family: 'Exo 2', sans-serif;
            font-weight: 800;
            font-size: 20px;
            color: var(--cyan);
            letter-spacing: 2px;
            text-transform: uppercase;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .logo::before {
            content: '🎯';
            font-size: 22px;
        }
        
        .status-bar {
            display: flex;
            gap: 20px;
            align-items: center;
        }
        
        .status-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 2px;
        }
        
        .status-value {
            font-size: 22px;
            font-weight: bold;
            font-family: 'Exo 2', sans-serif;
        }
        
        .status-label {
            font-size: 10px;
            color: var(--dim);
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        
        .live-indicator {
            display: flex;
            align-items: center;
            gap: 6px;
            color: var(--green);
            font-size: 12px;
        }
        
        .pulse {
            width: 8px; height: 8px;
            background: var(--green);
            border-radius: 50%;
            animation: pulse 1.5s infinite;
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.8); }
        }
        
        /* Stats row */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 16px;
            position: relative;
            overflow: hidden;
            transition: border-color 0.3s;
        }
        
        .stat-card:hover { border-color: var(--cyan); }
        
        .stat-card::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 2px;
        }
        
        .stat-card.red::before { background: var(--red); }
        .stat-card.orange::before { background: var(--orange); }
        .stat-card.yellow::before { background: var(--yellow); }
        .stat-card.green::before { background: var(--green); }
        .stat-card.cyan::before { background: var(--cyan); }
        
        .stat-num {
            font-family: 'Exo 2', sans-serif;
            font-size: 40px;
            font-weight: 800;
            line-height: 1;
            margin: 4px 0;
        }
        
        .stat-card.red .stat-num { color: var(--red); }
        .stat-card.orange .stat-num { color: var(--orange); }
        .stat-card.yellow .stat-num { color: var(--yellow); }
        .stat-card.green .stat-num { color: var(--green); }
        .stat-card.cyan .stat-num { color: var(--cyan); }
        
        .stat-label {
            font-size: 11px;
            color: var(--dim);
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        
        /* Main grid */
        .main-grid {
            display: grid;
            grid-template-columns: 1fr 380px;
            gap: 16px;
        }
        
        @media (max-width: 1100px) {
            .main-grid { grid-template-columns: 1fr; }
        }
        
        /* Panels */
        .panel {
            background: var(--panel);
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }
        
        .panel-header {
            padding: 12px 16px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(255,255,255,0.02);
        }
        
        .panel-title {
            font-family: 'Exo 2', sans-serif;
            font-weight: 600;
            font-size: 13px;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--cyan);
        }
        
        .panel-body { padding: 0; }
        
        /* Attacker table */
        .attacker-table { width: 100%; border-collapse: collapse; }
        
        .attacker-table th {
            padding: 8px 12px;
            text-align: left;
            font-size: 10px;
            letter-spacing: 1px;
            color: var(--dim);
            text-transform: uppercase;
            border-bottom: 1px solid var(--border);
        }
        
        .attacker-row {
            border-bottom: 1px solid rgba(26,35,50,0.5);
            transition: background 0.2s;
            cursor: pointer;
        }
        
        .attacker-row:hover { background: rgba(0,212,255,0.04); }
        
        .attacker-row td { padding: 10px 12px; font-size: 13px; }
        
        .threat-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 1px;
        }
        
        .badge-CRITICAL { background: rgba(255,0,68,0.2); color: var(--red); border: 1px solid rgba(255,0,68,0.4); }
        .badge-HIGH     { background: rgba(255,68,0,0.2); color: #ff4400; border: 1px solid rgba(255,68,0,0.4); }
        .badge-MEDIUM   { background: rgba(255,136,0,0.2); color: var(--orange); border: 1px solid rgba(255,136,0,0.4); }
        .badge-LOW      { background: rgba(68,170,255,0.2); color: var(--low); border: 1px solid rgba(68,170,255,0.4); }
        
        /* Score bar */
        .score-bar {
            width: 80px;
            height: 6px;
            background: var(--border);
            border-radius: 3px;
            overflow: hidden;
            display: inline-block;
        }
        
        .score-fill {
            height: 100%;
            border-radius: 3px;
            transition: width 0.5s;
        }
        
        /* Alert feed */
        .alert-feed {
            max-height: 500px;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: var(--border) transparent;
        }
        
        .alert-item {
            padding: 10px 14px;
            border-bottom: 1px solid rgba(26,35,50,0.5);
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from { opacity: 0; transform: translateX(10px); }
            to { opacity: 1; transform: translateX(0); }
        }
        
        .alert-type {
            font-size: 11px;
            font-weight: bold;
            letter-spacing: 0.5px;
        }
        
        .alert-CRITICAL .alert-type { color: var(--red); }
        .alert-HIGH .alert-type     { color: #ff4400; }
        .alert-MEDIUM .alert-type   { color: var(--orange); }
        .alert-LOW .alert-type      { color: var(--low); }
        
        .alert-message { font-size: 11px; color: var(--dim); margin-top: 2px; }
        .alert-meta { font-size: 10px; color: var(--dim); margin-top: 4px; display: flex; gap: 10px; }
        
        /* Timeline */
        .timeline {
            padding: 16px;
            max-height: 400px;
            overflow-y: auto;
        }
        
        .timeline-event {
            display: flex;
            gap: 12px;
            margin-bottom: 16px;
            position: relative;
        }
        
        .timeline-event::before {
            content: '';
            position: absolute;
            left: 5px;
            top: 18px;
            bottom: -16px;
            width: 1px;
            background: var(--border);
        }
        
        .timeline-event:last-child::before { display: none; }
        
        .timeline-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            flex-shrink: 0;
            margin-top: 3px;
            border: 2px solid;
        }
        
        .dot-CRITICAL { background: var(--red); border-color: var(--red); box-shadow: 0 0 6px var(--red); }
        .dot-HIGH     { background: #ff4400; border-color: #ff4400; }
        .dot-MEDIUM   { background: var(--orange); border-color: var(--orange); }
        .dot-LOW      { background: var(--low); border-color: var(--low); }
        
        .timeline-content { flex: 1; }
        .timeline-type { font-size: 11px; font-weight: bold; color: var(--cyan); }
        .timeline-detail { font-size: 11px; color: var(--text); margin-top: 2px; word-break: break-all; }
        .timeline-ts { font-size: 10px; color: var(--dim); margin-top: 2px; }
        .timeline-mitre { 
            display: inline-block;
            font-size: 9px;
            padding: 1px 5px;
            background: rgba(68,136,255,0.15);
            color: var(--blue);
            border-radius: 2px;
            margin-top: 2px;
        }
        
        /* Controls */
        .controls {
            display: flex;
            gap: 8px;
            padding: 12px 16px;
            border-top: 1px solid var(--border);
            flex-wrap: wrap;
        }
        
        button {
            background: rgba(0,212,255,0.1);
            color: var(--cyan);
            border: 1px solid rgba(0,212,255,0.3);
            padding: 6px 14px;
            border-radius: 4px;
            cursor: pointer;
            font-family: 'Share Tech Mono', monospace;
            font-size: 12px;
            letter-spacing: 1px;
            transition: all 0.2s;
        }
        
        button:hover {
            background: rgba(0,212,255,0.2);
            border-color: var(--cyan);
        }
        
        button.danger {
            color: var(--red);
            background: rgba(255,51,85,0.1);
            border-color: rgba(255,51,85,0.3);
        }
        
        .ip-select {
            background: var(--panel);
            color: var(--text);
            border: 1px solid var(--border);
            padding: 6px 10px;
            border-radius: 4px;
            font-family: 'Share Tech Mono', monospace;
            font-size: 12px;
        }
        
        /* TTP tags */
        .ttp-tag {
            display: inline-block;
            padding: 2px 6px;
            background: rgba(68,136,255,0.15);
            color: var(--blue);
            border: 1px solid rgba(68,136,255,0.3);
            border-radius: 3px;
            font-size: 10px;
            margin: 2px;
        }
        
        .no-data { padding: 30px; text-align: center; color: var(--dim); }
        
        #clock { font-size: 13px; color: var(--dim); }
    </style>
</head>
<body>
<header>
    <div class="logo">Active Threat Hunter</div>
    <div class="status-bar">
        <div class="status-item">
            <span class="status-value" id="h-events" style="color:var(--cyan)">0</span>
            <span class="status-label">Events</span>
        </div>
        <div class="status-item">
            <span class="status-value" id="h-alerts" style="color:var(--red)">0</span>
            <span class="status-label">Alerts</span>
        </div>
        <div class="status-item">
            <span class="status-value" id="h-actors" style="color:var(--yellow)">0</span>
            <span class="status-label">Actors</span>
        </div>
        <div class="live-indicator">
            <div class="pulse"></div>
            LIVE
        </div>
        <span id="clock"></span>
    </div>
</header>

<div class="container">
    <!-- Stats -->
    <div class="stats-grid" id="stats-grid"></div>
    
    <div class="main-grid">
        <!-- Left: Attacker table + timeline -->
        <div>
            <div class="panel" style="margin-bottom:16px">
                <div class="panel-header">
                    <span class="panel-title">🎯 Threat Actors</span>
                    <span style="font-size:11px;color:var(--dim)" id="actor-count">0 tracked</span>
                </div>
                <div class="panel-body">
                    <div id="attacker-table-container">
                        <div class="no-data">No attackers detected yet. Run the demo or start monitoring.</div>
                    </div>
                </div>
            </div>
            
            <div class="panel">
                <div class="panel-header">
                    <span class="panel-title">📋 Attack Timeline</span>
                    <select class="ip-select" id="timeline-ip" onchange="loadTimeline()">
                        <option value="">Select IP...</option>
                    </select>
                </div>
                <div class="timeline" id="timeline-container">
                    <div class="no-data">Select an attacker to view timeline</div>
                </div>
            </div>
        </div>
        
        <!-- Right: Alert feed -->
        <div class="panel">
            <div class="panel-header">
                <span class="panel-title">🚨 Alert Feed</span>
                <span style="font-size:11px;color:var(--dim)" id="alert-count">0 alerts</span>
            </div>
            <div class="alert-feed" id="alert-feed">
                <div class="no-data">Waiting for alerts...</div>
            </div>
            <div class="controls">
                <button onclick="triggerDemo()">▶ Run Demo</button>
                <button onclick="refreshData()">⟳ Refresh</button>
                <button onclick="exportReport()">⬇ Export</button>
                <button class="danger" onclick="clearData()">✕ Clear</button>
            </div>
        </div>
    </div>
</div>

<script>
let lastAlertCount = 0;
let alertsData = [];

function updateClock() {
    document.getElementById('clock').textContent = new Date().toLocaleTimeString();
}

setInterval(updateClock, 1000);
updateClock();

async function fetchData() {
    try {
        const r = await fetch('/api/state');
        const data = await r.json();
        updateDashboard(data);
    } catch(e) {
        console.error('Fetch error:', e);
    }
}

function updateDashboard(data) {
    // Header stats
    document.getElementById('h-events').textContent = data.stats.total_events_processed;
    document.getElementById('h-alerts').textContent = data.stats.total_alerts;
    document.getElementById('h-actors').textContent = data.stats.attackers_tracked;
    
    // Stats cards
    const actors = Object.values(data.attackers);
    const critical = actors.filter(a => a.threat_level === 'CRITICAL').length;
    const high = actors.filter(a => a.threat_level === 'HIGH').length;
    
    document.getElementById('stats-grid').innerHTML = `
        <div class="stat-card red">
            <div class="stat-label">Critical Threats</div>
            <div class="stat-num">${critical}</div>
        </div>
        <div class="stat-card orange">
            <div class="stat-label">High Threats</div>
            <div class="stat-num">${high}</div>
        </div>
        <div class="stat-card yellow">
            <div class="stat-label">Total Actors</div>
            <div class="stat-num">${actors.length}</div>
        </div>
        <div class="stat-card cyan">
            <div class="stat-label">Total Events</div>
            <div class="stat-num">${data.stats.total_events_processed}</div>
        </div>
        <div class="stat-card green">
            <div class="stat-label">Total Alerts</div>
            <div class="stat-num">${data.stats.total_alerts}</div>
        </div>
    `;
    
    // Attacker table
    const container = document.getElementById('attacker-table-container');
    document.getElementById('actor-count').textContent = actors.length + ' tracked';
    
    if (actors.length === 0) {
        container.innerHTML = '<div class="no-data">No attackers detected. Run demo to see the system in action.</div>';
    } else {
        const sorted = actors.sort((a,b) => b.threat_score - a.threat_score);
        container.innerHTML = `
            <table class="attacker-table">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Threat</th>
                        <th>Score</th>
                        <th>Events</th>
                        <th>TTPs</th>
                        <th>Last Seen</th>
                    </tr>
                </thead>
                <tbody>
                    ${sorted.map(a => `
                        <tr class="attacker-row" onclick="selectIP('${a.ip}')">
                            <td style="font-family:monospace;color:var(--cyan)">${a.ip}</td>
                            <td><span class="threat-badge badge-${a.threat_level}">${a.threat_level}</span></td>
                            <td>
                                <div style="display:flex;align-items:center;gap:6px">
                                    <span>${a.threat_score}</span>
                                    <div class="score-bar">
                                        <div class="score-fill" style="width:${a.threat_score}%;background:${scoreColor(a.threat_score)}"></div>
                                    </div>
                                </div>
                            </td>
                            <td>${a.attack_timeline.length}</td>
                            <td>${a.ttps.length}</td>
                            <td style="color:var(--dim);font-size:11px">${a.last_seen.substring(11,19)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    }
    
    // Update IP selector
    const select = document.getElementById('timeline-ip');
    const currentVal = select.value;
    const ips = Object.keys(data.attackers);
    select.innerHTML = '<option value="">Select IP...</option>' + 
        ips.map(ip => `<option value="${ip}" ${ip===currentVal?'selected':''}>${ip}</option>`).join('');
    
    // Alerts
    alertsData = data.alerts || [];
    updateAlertFeed(alertsData);
}

function updateAlertFeed(alerts) {
    const feed = document.getElementById('alert-feed');
    document.getElementById('alert-count').textContent = alerts.length + ' alerts';
    
    if (alerts.length === 0) {
        feed.innerHTML = '<div class="no-data">No alerts yet</div>';
        return;
    }
    
    const recent = [...alerts].reverse().slice(0, 50);
    feed.innerHTML = recent.map(a => `
        <div class="alert-item alert-${a.severity}">
            <div class="alert-type">[${a.id}] ${a.type}</div>
            <div class="alert-message">${a.message.substring(0,120)}</div>
            <div class="alert-meta">
                <span style="color:var(--cyan)">${a.ip}</span>
                <span>${a.mitre_technique}</span>
                <span>${a.timestamp.substring(11,19)}</span>
            </div>
        </div>
    `).join('');
}

function scoreColor(score) {
    if (score >= 75) return 'var(--red)';
    if (score >= 50) return '#ff4400';
    if (score >= 25) return 'var(--orange)';
    return 'var(--low)';
}

function selectIP(ip) {
    document.getElementById('timeline-ip').value = ip;
    loadTimeline();
}

async function loadTimeline() {
    const ip = document.getElementById('timeline-ip').value;
    if (!ip) return;
    
    try {
        const r = await fetch(`/api/timeline/${ip}`);
        const data = await r.json();
        
        if (!data.profile) {
            document.getElementById('timeline-container').innerHTML = '<div class="no-data">IP not found</div>';
            return;
        }
        
        const p = data.profile;
        const ttps = p.ttps.map(t => `<span class="ttp-tag">${t}</span>`).join('');
        
        const events = p.attack_timeline.map(e => `
            <div class="timeline-event">
                <div class="timeline-dot dot-${e.severity}"></div>
                <div class="timeline-content">
                    <div class="timeline-type">${e.type}</div>
                    <div class="timeline-detail">${e.detail.substring(0,100)}</div>
                    <span class="timeline-mitre">${e.mitre}</span>
                    <div class="timeline-ts">${e.timestamp.substring(0,19)}</div>
                </div>
            </div>
        `).join('');
        
        document.getElementById('timeline-container').innerHTML = `
            <div style="padding:12px 16px;border-bottom:1px solid var(--border)">
                <div style="font-size:11px;color:var(--dim);margin-bottom:4px">SESSION: ${p.session_id}</div>
                <div style="display:flex;gap:20px;font-size:12px">
                    <span>Score: <strong style="color:${scoreColor(p.threat_score)}">${p.threat_score}/100</strong></span>
                    <span>Logins: <strong style="color:var(--red)">${p.failed_logins} failed</strong> / <strong style="color:var(--green)">${p.successful_logins} success</strong></span>
                    <span>Hosts: <strong style="color:var(--cyan)">${p.endpoints_accessed.length}</strong></span>
                </div>
                <div style="margin-top:8px">${ttps}</div>
            </div>
            <div style="padding:16px">${events || '<div class="no-data">No events</div>'}</div>
        `;
    } catch(e) {
        console.error(e);
    }
}

async function triggerDemo() {
    document.getElementById('alert-feed').innerHTML = '<div class="no-data" style="color:var(--cyan)">Running APT simulation...</div>';
    await fetch('/api/demo', {method: 'POST'});
    setTimeout(fetchData, 1000);
    setTimeout(fetchData, 3000);
    setTimeout(fetchData, 6000);
    setTimeout(fetchData, 10000);
}

async function exportReport() {
    const r = await fetch('/api/export', {method: 'POST'});
    const data = await r.json();
    alert('Report saved: ' + data.path);
}

async function clearData() {
    if (!confirm('Clear all tracked data?')) return;
    await fetch('/api/clear', {method: 'POST'});
    fetchData();
}

function refreshData() { fetchData(); }

// Auto-refresh
setInterval(fetchData, 3000);
fetchData();
</script>
</body>
</html>
"""

if FLASK_AVAILABLE:
    app = Flask(__name__)
    
    @app.route("/")
    def index():
        return render_template_string(DASHBOARD_HTML)
    
    @app.route("/api/state")
    def api_state():
        return jsonify({
            "stats": hunter.stats,
            "attackers": {ip: p.to_dict() for ip, p in hunter.attackers.items()},
            "alerts": hunter.alerts[-100:]
        })
    
    @app.route("/api/timeline/<ip>")
    def api_timeline(ip):
        if ip in hunter.attackers:
            return jsonify({"profile": hunter.attackers[ip].to_dict()})
        return jsonify({"profile": None})
    
    @app.route("/api/demo", methods=["POST"])
    def api_demo():
        """Trigger demo in background thread"""
        def run():
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from main import run_demo_scenario
            run_demo_scenario(hunter)
        
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        return jsonify({"status": "started"})
    
    @app.route("/api/export", methods=["POST"])
    def api_export():
        path = hunter.export_report()
        return jsonify({"path": path})
    
    @app.route("/api/clear", methods=["POST"])
    def api_clear():
        hunter.attackers.clear()
        hunter.alerts.clear()
        hunter.stats["total_events_processed"] = 0
        hunter.stats["total_alerts"] = 0
        hunter.stats["attackers_tracked"] = 0
        return jsonify({"status": "cleared"})
    
    @app.route("/api/parse_logs", methods=["POST"])
    def api_parse_logs():
        thread = threading.Thread(target=log_parser.parse_all_logs, daemon=True)
        thread.start()
        return jsonify({"status": "parsing"})


def start_dashboard(port: int = 5000):
    if not FLASK_AVAILABLE:
        print("Install Flask first: pip3 install flask")
        return
    
    print(f"\n{'─'*50}")
    print(f"  🌐 Web Dashboard starting...")
    print(f"  Access: http://localhost:{port}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'─'*50}\n")
    
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    start_dashboard()
