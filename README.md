# 🎯 Active Threat Hunting System
### SOC Level 2 | Attack Attribution Engine | Kali Linux

## System Architecture

```
threat_hunter/
├── main.py                    ← Entry point, interactive CLI + all modes
├── setup.sh                   ← One-command setup on Kali
├── core/
│   ├── threat_engine.py       ← Core detection + attribution engine
│   │   ├── AttackerProfile    ← Per-IP attacker dossier
│   │   └── ThreatHunter       ← Detection + correlation engine
│   ├── log_parser.py          ← Parses auth.log, syslog, apache, audit.log
│   └── network_monitor.py     ← Live packet capture + connection tracking
├── dashboard/
│   └── dashboard.py           ← Flask web dashboard (real-time UI)
├── data/                      ← Runtime state
├── logs/                      ← Alert logs (JSON)
└── reports/                   ← Exported threat reports (JSON)
```

---

## Quick Start

```bash
# 1. Install dependencies
chmod +x setup.sh && ./setup.sh

# 2. Run the full APT simulation demo
python3 main.py --demo

# 3. Or start the interactive menu
python3 main.py

# 4. Or launch the web dashboard
python3 dashboard/dashboard.py
# Open browser: http://localhost:5000

# 5. Live monitoring (needs root for pcap)
sudo python3 main.py --live

# 6. Analyze your actual system logs
sudo python3 main.py --parse-logs

# 7. Parse a specific log file
python3 main.py --log /var/log/auth.log
```

---

## Detection Capabilities

| Detection Module | What It Catches | MITRE Technique |
|---|---|---|
| Brute Force Detector | SSH/FTP/HTTP login storms | T1110 |
| Credential Stuffing | Successful login after failures | T1110.004 |
| Port Scan Detector | TCP SYN sweeps, service discovery | T1046 |
| Lateral Movement | SSH/RDP/SMB pivoting between hosts | T1021 |
| Suspicious Commands | Reverse shells, download cradles, privesc | T1059 |
| Web Attack Detector | SQLi, XSS, path traversal, RCE | T1190 |
| Data Exfiltration | Large outbound transfers | T1041 |
| Privilege Escalation | Sudo abuse, SUID exploitation | T1548 |

---

## Log Sources Parsed

- `/var/log/auth.log` — SSH logins, sudo, PAM
- `/var/log/syslog` — System events
- `/var/log/fail2ban.log` — Fail2ban bans
- `/var/log/apache2/access.log` — Web requests
- `/var/log/nginx/access.log` — Nginx requests
- `/var/log/audit/audit.log` — Kernel audit (execve, syscalls)

---

## Attacker Profile (What Gets Tracked Per IP)

```json
{
  "ip": "45.33.32.156",
  "session_id": "a3f2b891",
  "threat_score": 87,
  "threat_level": "CRITICAL",
  "first_seen": "2024-01-15T14:32:11",
  "last_seen": "2024-01-15T14:45:33",
  "ttps": ["T1110.001", "T1059.004", "T1021.004", "T1041"],
  "endpoints_accessed": ["10.0.0.5", "10.0.0.10", "10.0.0.20"],
  "ports_probed": [22, 80, 443, 3306, 3389],
  "failed_logins": 47,
  "successful_logins": 1,
  "commands_executed": ["whoami", "sudo -l", "wget http://...", "bash -i >& /dev/tcp/..."],
  "lateral_movement": [
    {"from": "web01", "to": "db01", "method": "SSH"},
    {"from": "db01", "to": "fileserver", "method": "SMB"}
  ],
  "attack_timeline": [
    {"type": "PORT_SCAN", "severity": "HIGH", "mitre": "T1046", ...},
    {"type": "BRUTE_FORCE", "severity": "HIGH", "mitre": "T1110", ...},
    {"type": "LATERAL_MOVEMENT", "severity": "CRITICAL", "mitre": "T1021.004", ...}
  ]
}
```

---

## APT Kill Chain Simulation (Demo Mode)

The `--demo` flag runs a full **APT attack simulation** showing all 6 phases:

1. **Reconnaissance** — Port scanning across multiple hosts
2. **Initial Access** — SSH brute force → credential stuffing success
3. **Execution** — Post-compromise command execution (reverse shell)
4. **Privilege Escalation** — sudo abuse, SUID exploitation
5. **Lateral Movement** — Pivot chain: web01 → db01 → fileserver → backup
6. **Data Exfiltration** — 650MB exfiltrated to C2 server

---

## Tech Stack

- **Python 3.8+** — Core engine, log parsing, correlation
- **Flask** — Web dashboard
- **tcpdump** — Live packet capture
- **/proc/net/tcp** — Connection tracking without root
- **JSON** — Alert storage and report export
- **Threading** — Parallel log monitoring

---

## Adding Wazuh Integration

To connect to a real Wazuh instance, add to `log_parser.py`:
```python
# Parse Wazuh alerts API
import requests
WAZUH_URL = "https://localhost:55000"
WAZUH_TOKEN = "your-token"

def fetch_wazuh_alerts():
    r = requests.get(f"{WAZUH_URL}/alerts", 
                     headers={"Authorization": f"Bearer {WAZUH_TOKEN}"},
                     verify=False)
    for alert in r.json()["data"]["affected_items"]:
        src_ip = alert.get("agent", {}).get("ip")
        if src_ip:
            hunter.detect_suspicious_command(src_ip, "wazuh", alert["rule"]["description"], alert["agent"]["name"])
```

---

