#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   ACTIVE THREAT HUNTING ENGINE - THREAT_ENGINE.PY   ║
║   SOC Level 2 | Attack Attribution & Correlation    ║
╚══════════════════════════════════════════════════════╝
Author: Threat Hunter System
Purpose: Core detection, correlation, and attribution engine
"""

import re
import json
import time
import socket
import hashlib
import ipaddress
import threading
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict, deque
from pathlib import Path
import sys
import os

# ─── Color output for terminal ───────────────────────────────────────────────
class Colors:
    RED     = '\033[91m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    BLUE    = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN    = '\033[96m'
    WHITE   = '\033[97m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'
    DIM     = '\033[2m'

def banner():
    print(f"""
{Colors.RED}{Colors.BOLD}
 ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
 ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║   ███████║██████╔╝█████╗  ███████║   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Colors.RESET}
{Colors.CYAN}{'═'*100}
{Colors.YELLOW}   Active Threat Hunting System  |  Attack Attribution Engine  |  SOC Level 2 Operations
{Colors.CYAN}{'═'*100}{Colors.RESET}
""")

# ─── Configuration ────────────────────────────────────────────────────────────
CONFIG = {
    "BRUTE_FORCE_THRESHOLD": 5,       # Failed attempts before alert
    "BRUTE_FORCE_WINDOW": 60,          # Seconds to track attempts
    "PORT_SCAN_THRESHOLD": 10,         # Unique ports in window
    "PORT_SCAN_WINDOW": 30,
    "LATERAL_MOVEMENT_WINDOW": 300,    # 5 min to detect lateral movement
    "DATA_DIR": Path("data"),
    "LOG_DIR": Path("logs"),
    "REPORT_DIR": Path("reports"),
    "ALERT_SEVERITY": {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1
    }
}

# ─── Threat Intelligence Database (simulated IOCs) ───────────────────────────
KNOWN_MALICIOUS_IPS = {
    "192.168.1.100": "Known Botnet C2",
    "10.0.0.99":     "Internal Pivot Node",
    "172.16.0.50":   "Pentest Infrastructure",
}

SUSPICIOUS_COMMANDS = [
    r'wget\s+http', r'curl\s+-o', r'chmod\s+[0-7]*7[0-7]*\s+',
    r'python\s+-c', r'bash\s+-i', r'nc\s+-e', r'netcat',
    r'/bin/sh', r'base64\s+--decode', r'dd\s+if=',
    r'nmap', r'masscan', r'hydra', r'john', r'hashcat',
    r'msfconsole', r'msfvenom', r'empire', r'cobalt',
    r'whoami', r'id\s*$', r'uname\s+-a', r'cat\s+/etc/passwd',
    r'sudo\s+-l', r'find\s+/\s+-perm', r'crontab\s+-e',
    r'ssh\s+.*@', r'scp\s+', r'rsync\s+',
]

# ─── Data Structures ──────────────────────────────────────────────────────────
class AttackerProfile:
    """Builds a complete profile of an attacker based on their activity"""
    
    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.attack_timeline = []        # Chronological list of events
        self.endpoints_accessed = set()  # Which hosts they hit
        self.ports_probed = set()        # Which ports they scanned
        self.commands_executed = []      # Commands run (if we can see them)
        self.failed_logins = 0
        self.successful_logins = 0
        self.lateral_movement = []       # Pivoting attempts
        self.threat_score = 0            # 0-100 danger rating
        self.ttps = set()                # MITRE ATT&CK tactics used
        self.alert_history = []          # Alerts generated
        self.geo_info = {}               # Geolocation data
        self.session_id = hashlib.md5(f"{ip}{time.time()}".encode()).hexdigest()[:8]
        
    def add_event(self, event_type: str, detail: str, severity: str = "MEDIUM", mitre_tactic: str = None):
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "detail": detail,
            "severity": severity,
            "mitre": mitre_tactic or "T?????"
        }
        self.attack_timeline.append(event)
        self.last_seen = datetime.now()
        
        if mitre_tactic:
            self.ttps.add(mitre_tactic)
            
        # Update threat score
        severity_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
        self.threat_score = min(100, self.threat_score + severity_weights.get(severity, 5))
        
    def get_threat_level(self) -> str:
        if self.threat_score >= 75:   return "CRITICAL"
        if self.threat_score >= 50:   return "HIGH"
        if self.threat_score >= 25:   return "MEDIUM"
        return "LOW"
        
    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "ip": self.ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "threat_score": self.threat_score,
            "threat_level": self.get_threat_level(),
            "endpoints_accessed": list(self.endpoints_accessed),
            "ports_probed": list(self.ports_probed),
            "commands_executed": self.commands_executed,
            "failed_logins": self.failed_logins,
            "successful_logins": self.successful_logins,
            "lateral_movement": self.lateral_movement,
            "ttps": list(self.ttps),
            "geo_info": self.geo_info,
            "attack_timeline": self.attack_timeline,
            "alert_count": len(self.alert_history)
        }


# ─── Core Detection Engine ────────────────────────────────────────────────────
class ThreatHunter:
    """
    Main threat hunting and correlation engine.
    Detects, tracks, and attributes attacks in real-time.
    """
    
    def __init__(self):
        self.attackers: dict[str, AttackerProfile] = {}
        self.failed_login_tracker: dict[str, deque] = defaultdict(deque)
        self.port_scan_tracker: dict[str, deque] = defaultdict(deque)
        self.connection_graph: dict[str, set] = defaultdict(set)  # lateral movement
        self.alerts: list = []
        self.lock = threading.Lock()
        self.stats = {
            "total_events_processed": 0,
            "total_alerts": 0,
            "attackers_tracked": 0,
            "start_time": datetime.now().isoformat()
        }
        
        # Ensure directories exist
        for d in [CONFIG["DATA_DIR"], CONFIG["LOG_DIR"], CONFIG["REPORT_DIR"]]:
            d.mkdir(exist_ok=True)
            
        print(f"{Colors.GREEN}[+] ThreatHunter Engine initialized{Colors.RESET}")
        print(f"{Colors.DIM}    Session started: {self.stats['start_time']}{Colors.RESET}")
    
    def _get_or_create_profile(self, ip: str) -> AttackerProfile:
        """Get existing attacker profile or create new one"""
        if ip not in self.attackers:
            self.attackers[ip] = AttackerProfile(ip)
            self.attackers[ip].geo_info = self._geolocate(ip)
            # Check threat intel
            if ip in KNOWN_MALICIOUS_IPS:
                self.attackers[ip].add_event(
                    "THREAT_INTEL_HIT",
                    f"IP found in threat intel: {KNOWN_MALICIOUS_IPS[ip]}",
                    "HIGH",
                    "T1590"  # Gather Victim Network Information
                )
            self.stats["attackers_tracked"] += 1
            print(f"\n{Colors.YELLOW}[!] New attacker profile created: {ip}{Colors.RESET}")
        return self.attackers[ip]
    
    def _geolocate(self, ip: str) -> dict:
        """
        Attempt IP geolocation. 
        In production: use MaxMind GeoIP2 or ip-api.com
        """
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                return {
                    "country": "INTERNAL",
                    "city": "Local Network",
                    "org": "Internal Infrastructure",
                    "is_private": True,
                    "asn": "RFC-1918"
                }
        except ValueError:
            pass
        
        # Simulated geo data for demonstration
        # In real deployment: requests.get(f"http://ip-api.com/json/{ip}")
        return {
            "country": "Unknown",
            "city": "Unknown",
            "org": "Unknown ISP",
            "is_private": False,
            "asn": "AS????",
            "note": "Install geoip2 library for real geolocation: pip install geoip2"
        }
    
    def _raise_alert(self, ip: str, alert_type: str, message: str, severity: str, mitre: str = None):
        """Generate and log a security alert"""
        alert = {
            "id": f"ALERT-{len(self.alerts)+1:04d}",
            "timestamp": datetime.now().isoformat(),
            "ip": ip,
            "type": alert_type,
            "message": message,
            "severity": severity,
            "mitre_technique": mitre or "N/A",
            "session": self.attackers.get(ip, AttackerProfile(ip)).session_id
        }
        
        self.alerts.append(alert)
        self.stats["total_alerts"] += 1
        
        if ip in self.attackers:
            self.attackers[ip].alert_history.append(alert["id"])
        
        # Color-coded terminal output
        color = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH":     Colors.RED,
            "MEDIUM":   Colors.YELLOW,
            "LOW":      Colors.CYAN
        }.get(severity, Colors.WHITE)
        
        print(f"\n{color}{'─'*70}")
        print(f"  🚨 ALERT [{alert['id']}] [{severity}] - {alert_type}")
        print(f"  📍 Attacker IP: {ip}")
        print(f"  📝 {message}")
        print(f"  🎯 MITRE ATT&CK: {mitre or 'N/A'}")
        print(f"  ⏰ Time: {alert['timestamp']}")
        print(f"{'─'*70}{Colors.RESET}")
        
        # Save alert to file
        self._save_alert(alert)
        return alert
    
    def _save_alert(self, alert: dict):
        """Persist alert to disk"""
        alert_file = CONFIG["LOG_DIR"] / "alerts.json"
        alerts_data = []
        if alert_file.exists():
            try:
                alerts_data = json.loads(alert_file.read_text())
            except:
                alerts_data = []
        alerts_data.append(alert)
        alert_file.write_text(json.dumps(alerts_data, indent=2))
    
    # ── DETECTION MODULES ────────────────────────────────────────────────────
    
    def detect_brute_force(self, ip: str, username: str, success: bool, service: str = "SSH"):
        """
        Detect brute-force login attacks.
        MITRE: T1110 - Brute Force
        """
        self.stats["total_events_processed"] += 1
        
        with self.lock:
            profile = self._get_or_create_profile(ip)
            now = time.time()
            
            if not success:
                profile.failed_logins += 1
                tracker = self.failed_login_tracker[ip]
                
                # Remove old attempts outside window
                while tracker and now - tracker[0] > CONFIG["BRUTE_FORCE_WINDOW"]:
                    tracker.popleft()
                
                tracker.append(now)
                profile.add_event("FAILED_LOGIN", f"Failed {service} login for user '{username}'", "LOW", "T1110")
                
                if len(tracker) >= CONFIG["BRUTE_FORCE_THRESHOLD"]:
                    self._raise_alert(
                        ip,
                        "BRUTE_FORCE_DETECTED",
                        f"{len(tracker)} failed {service} logins for user '{username}' in {CONFIG['BRUTE_FORCE_WINDOW']}s",
                        "HIGH" if len(tracker) < 20 else "CRITICAL",
                        "T1110.001"  # Password Guessing
                    )
                    profile.add_event("BRUTE_FORCE", f"Brute force threshold exceeded: {len(tracker)} attempts", "HIGH", "T1110.001")
                    
            else:
                profile.successful_logins += 1
                
                # Successful login after failures = credential stuffing success
                if profile.failed_logins > 0:
                    self._raise_alert(
                        ip,
                        "CREDENTIAL_STUFFING_SUCCESS",
                        f"Successful {service} login as '{username}' after {profile.failed_logins} failures — ACCOUNT COMPROMISED",
                        "CRITICAL",
                        "T1110.004"  # Credential Stuffing
                    )
                    profile.add_event("SUCCESSFUL_LOGIN", f"Gained access as '{username}' on {service}", "CRITICAL", "T1110.004")
                else:
                    profile.add_event("SUCCESSFUL_LOGIN", f"Login as '{username}' on {service}", "MEDIUM", "T1078")
    
    def detect_port_scan(self, src_ip: str, dst_ip: str, dst_port: int, protocol: str = "TCP"):
        """
        Detect port scanning activity.
        MITRE: T1046 - Network Service Discovery
        """
        self.stats["total_events_processed"] += 1
        
        with self.lock:
            profile = self._get_or_create_profile(src_ip)
            profile.endpoints_accessed.add(dst_ip)
            profile.ports_probed.add(dst_port)
            now = time.time()
            
            tracker = self.port_scan_tracker[src_ip]
            while tracker and now - tracker[0]["time"] > CONFIG["PORT_SCAN_WINDOW"]:
                tracker.popleft()
            
            tracker.append({"time": now, "port": dst_port, "dst": dst_ip})
            
            # Count unique ports in window
            unique_ports = len(set(e["port"] for e in tracker))
            
            if unique_ports >= CONFIG["PORT_SCAN_THRESHOLD"]:
                profile.add_event("PORT_SCAN", f"Scanning {dst_ip} — {unique_ports} ports in {CONFIG['PORT_SCAN_WINDOW']}s", "HIGH", "T1046")
                
                # Detect scan type
                scan_type = self._identify_scan_type(list(profile.ports_probed))
                
                self._raise_alert(
                    src_ip,
                    f"PORT_SCAN_DETECTED",
                    f"{scan_type} detected: {unique_ports} unique ports on {dst_ip} in {CONFIG['PORT_SCAN_WINDOW']}s | Total ports: {len(profile.ports_probed)}",
                    "HIGH",
                    "T1046"
                )
    
    def _identify_scan_type(self, ports: list) -> str:
        """Identify what kind of scan is happening based on ports targeted"""
        common_ports = {22, 23, 25, 53, 80, 443, 445, 3389, 8080}
        web_ports = {80, 443, 8080, 8443, 8888}
        db_ports = {1433, 1521, 3306, 5432, 6379, 27017}
        
        port_set = set(ports)
        
        if port_set & db_ports and len(port_set & db_ports) > 2:
            return "DATABASE ENUMERATION SCAN"
        if port_set & web_ports and len(port_set & web_ports) > 2:
            return "WEB SERVICE SCAN"
        if len(ports) > 100:
            return "FULL PORT SWEEP"
        if port_set <= common_ports:
            return "COMMON SERVICES SCAN"
        
        # Check for sequential scan (TCP SYN sweep)
        sorted_ports = sorted(ports)
        is_sequential = all(sorted_ports[i+1] - sorted_ports[i] == 1 
                          for i in range(min(5, len(sorted_ports)-1)))
        if is_sequential:
            return "SEQUENTIAL PORT SCAN (SYN SWEEP)"
        
        return "TARGETED PORT SCAN"
    
    def detect_suspicious_command(self, ip: str, username: str, command: str, hostname: str):
        """
        Detect execution of suspicious commands.
        MITRE: T1059 - Command and Scripting Interpreter
        """
        self.stats["total_events_processed"] += 1
        
        with self.lock:
            profile = self._get_or_create_profile(ip)
            
            for pattern in SUSPICIOUS_COMMANDS:
                if re.search(pattern, command, re.IGNORECASE):
                    severity = "CRITICAL" if any(c in command for c in ["bash -i", "nc -e", "python -c", "/bin/sh"]) else "HIGH"
                    
                    profile.commands_executed.append({
                        "timestamp": datetime.now().isoformat(),
                        "host": hostname,
                        "user": username,
                        "command": command,
                        "matched_pattern": pattern
                    })
                    
                    # Determine MITRE technique
                    mitre = "T1059"
                    if "wget" in command or "curl" in command:
                        mitre = "T1105"  # Ingress Tool Transfer
                    elif any(x in command for x in ["bash -i", "nc -e", "python -c"]):
                        mitre = "T1059.004"  # Unix Shell
                    elif "crontab" in command or "cron" in command:
                        mitre = "T1053.003"  # Cron
                    elif "sudo" in command:
                        mitre = "T1548.003"  # Sudo and Sudo Caching
                    
                    profile.add_event("SUSPICIOUS_CMD", f"[{hostname}] {username}$ {command[:80]}", severity, mitre)
                    
                    self._raise_alert(
                        ip,
                        "SUSPICIOUS_COMMAND_EXECUTED",
                        f"User '{username}' on {hostname} ran: `{command[:100]}`",
                        severity,
                        mitre
                    )
                    break
    
    def detect_lateral_movement(self, src_ip: str, src_host: str, dst_ip: str, dst_host: str, 
                                 method: str, username: str = "unknown"):
        """
        Detect lateral movement between hosts.
        MITRE: T1021 - Remote Services
        """
        self.stats["total_events_processed"] += 1
        
        with self.lock:
            profile = self._get_or_create_profile(src_ip)
            
            # Build connection graph
            self.connection_graph[src_host].add(dst_host)
            profile.endpoints_accessed.add(dst_ip)
            
            movement = {
                "timestamp": datetime.now().isoformat(),
                "from": f"{src_host} ({src_ip})",
                "to": f"{dst_host} ({dst_ip})",
                "method": method,
                "user": username
            }
            profile.lateral_movement.append(movement)
            
            # Check for pivot chains (attacker moving through multiple hosts)
            pivot_chain = self._trace_pivot_chain(src_host)
            
            mitre_map = {
                "SSH":  "T1021.004",
                "RDP":  "T1021.001",
                "SMB":  "T1021.002",
                "WMI":  "T1021.003",
                "WINRM": "T1021.006",
            }
            mitre = mitre_map.get(method.upper(), "T1021")
            
            alert_msg = f"{method} lateral movement: {src_host} → {dst_host} as '{username}'"
            if len(pivot_chain) > 2:
                alert_msg += f"\n  ⚡ PIVOT CHAIN DETECTED: {' → '.join(pivot_chain)}"
                severity = "CRITICAL"
            else:
                severity = "HIGH"
            
            profile.add_event("LATERAL_MOVEMENT", movement["from"] + " ➜ " + movement["to"], severity, mitre)
            
            self._raise_alert(src_ip, "LATERAL_MOVEMENT_DETECTED", alert_msg, severity, mitre)
    
    def _trace_pivot_chain(self, start_host: str, visited: set = None) -> list:
        """Trace the full pivot chain from initial access to current position"""
        if visited is None:
            visited = set()
        if start_host in visited:
            return [start_host]
        visited.add(start_host)
        
        chain = [start_host]
        for next_host in self.connection_graph.get(start_host, []):
            chain.extend(self._trace_pivot_chain(next_host, visited))
        return chain
    
    def detect_data_exfiltration(self, ip: str, src_host: str, dst_ip: str, 
                                  bytes_transferred: int, protocol: str):
        """
        Detect potential data exfiltration.
        MITRE: T1041 - Exfiltration Over C2 Channel
        """
        self.stats["total_events_processed"] += 1
        
        MB = bytes_transferred / (1024 * 1024)
        
        with self.lock:
            profile = self._get_or_create_profile(ip)
            
            severity = "CRITICAL" if MB > 100 else "HIGH" if MB > 10 else "MEDIUM"
            
            profile.add_event(
                "DATA_EXFILTRATION",
                f"{MB:.2f} MB sent from {src_host} to {dst_ip} via {protocol}",
                severity,
                "T1041"
            )
            
            self._raise_alert(
                ip,
                "DATA_EXFILTRATION_DETECTED",
                f"Large data transfer: {MB:.2f} MB from {src_host} to {dst_ip} via {protocol}",
                severity,
                "T1041"
            )
    
    # ── REPORTING & OUTPUT ───────────────────────────────────────────────────
    
    def get_attacker_timeline(self, ip: str) -> None:
        """Print a formatted attack timeline for a specific IP"""
        if ip not in self.attackers:
            print(f"{Colors.RED}[!] No profile found for {ip}{Colors.RESET}")
            return
        
        profile = self.attackers[ip]
        threat_colors = {
            "CRITICAL": Colors.RED + Colors.BOLD,
            "HIGH":     Colors.RED,
            "MEDIUM":   Colors.YELLOW,
            "LOW":      Colors.CYAN
        }
        tc = threat_colors.get(profile.get_threat_level(), Colors.WHITE)
        
        print(f"\n{Colors.CYAN}{'═'*80}")
        print(f"  ATTACK TIMELINE: {ip}")
        print(f"{'═'*80}{Colors.RESET}")
        print(f"  Session ID  : {Colors.YELLOW}{profile.session_id}{Colors.RESET}")
        print(f"  First Seen  : {profile.first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Last Seen   : {profile.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Threat Level: {tc}{profile.get_threat_level()} (Score: {profile.threat_score}/100){Colors.RESET}")
        print(f"  Geo Info    : {profile.geo_info.get('country', 'Unknown')} / {profile.geo_info.get('city', 'Unknown')}")
        print(f"  Org/ASN     : {profile.geo_info.get('org', 'Unknown')} | {profile.geo_info.get('asn', 'Unknown')}")
        print(f"\n  {Colors.BOLD}MITRE ATT&CK TTPs Observed:{Colors.RESET}")
        for ttp in sorted(profile.ttps):
            print(f"    • {Colors.MAGENTA}{ttp}{Colors.RESET}")
        
        print(f"\n  {Colors.BOLD}Endpoints Targeted ({len(profile.endpoints_accessed)}):{Colors.RESET}")
        for ep in sorted(profile.endpoints_accessed):
            print(f"    → {ep}")
        
        if profile.ports_probed:
            print(f"\n  {Colors.BOLD}Ports Probed ({len(profile.ports_probed)}):{Colors.RESET}")
            print(f"    {', '.join(str(p) for p in sorted(profile.ports_probed))}")
        
        print(f"\n  {Colors.BOLD}{'─'*70}")
        print(f"  CHRONOLOGICAL ATTACK TIMELINE ({len(profile.attack_timeline)} events):{Colors.RESET}")
        
        for i, event in enumerate(profile.attack_timeline, 1):
            sev_color = threat_colors.get(event['severity'], Colors.WHITE)
            ts = event['timestamp'][:19]
            print(f"\n  {Colors.DIM}[{i:03d}]{Colors.RESET} {Colors.CYAN}{ts}{Colors.RESET}")
            print(f"        {sev_color}[{event['severity']:8s}]{Colors.RESET} {event['type']}")
            print(f"        {Colors.DIM}MITRE: {event['mitre']}{Colors.RESET}")
            print(f"        {event['detail']}")
        
        if profile.lateral_movement:
            print(f"\n  {Colors.BOLD}LATERAL MOVEMENT CHAIN:{Colors.RESET}")
            for move in profile.lateral_movement:
                print(f"    {Colors.RED}{move['from']} ──{move['method']}──► {move['to']}{Colors.RESET}")
        
        if profile.commands_executed:
            print(f"\n  {Colors.BOLD}COMMANDS EXECUTED ({len(profile.commands_executed)}):{Colors.RESET}")
            for cmd in profile.commands_executed[-5:]:  # last 5
                print(f"    {Colors.RED}[{cmd['host']}] {cmd['user']}${Colors.RESET} {cmd['command'][:80]}")
        
        print(f"\n{Colors.CYAN}{'═'*80}{Colors.RESET}\n")
    
    def print_dashboard(self):
        """Print current threat hunting dashboard"""
        print(f"\n{Colors.BLUE}{'═'*80}")
        print(f"  THREAT HUNTING DASHBOARD  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'═'*80}{Colors.RESET}")
        print(f"  Events Processed : {Colors.GREEN}{self.stats['total_events_processed']}{Colors.RESET}")
        print(f"  Total Alerts     : {Colors.RED}{self.stats['total_alerts']}{Colors.RESET}")
        print(f"  Attackers Tracked: {Colors.YELLOW}{self.stats['attackers_tracked']}{Colors.RESET}")
        
        if self.attackers:
            print(f"\n  {Colors.BOLD}Active Threat Actors:{Colors.RESET}")
            print(f"  {'IP Address':<20} {'Score':<8} {'Level':<10} {'Events':<8} {'TTPs':<6} {'Last Seen'}")
            print(f"  {'─'*70}")
            
            for ip, profile in sorted(self.attackers.items(), 
                                        key=lambda x: x[1].threat_score, reverse=True):
                level = profile.get_threat_level()
                color = {"CRITICAL": Colors.RED+Colors.BOLD, "HIGH": Colors.RED, 
                         "MEDIUM": Colors.YELLOW, "LOW": Colors.CYAN}.get(level, Colors.WHITE)
                print(f"  {ip:<20} {color}{profile.threat_score:<8}{Colors.RESET} "
                      f"{color}{level:<10}{Colors.RESET} "
                      f"{len(profile.attack_timeline):<8} "
                      f"{len(profile.ttps):<6} "
                      f"{profile.last_seen.strftime('%H:%M:%S')}")
        
        print(f"\n{Colors.BLUE}{'═'*80}{Colors.RESET}\n")
    
    def export_report(self, ip: str = None) -> str:
        """Export full threat report as JSON"""
        if ip:
            data = {ip: self.attackers[ip].to_dict()} if ip in self.attackers else {}
        else:
            data = {ip: profile.to_dict() for ip, profile in self.attackers.items()}
        
        report = {
            "report_generated": datetime.now().isoformat(),
            "system": "Active Threat Hunting System v1.0",
            "stats": self.stats,
            "threat_actors": data,
            "total_alerts": len(self.alerts),
            "alerts": self.alerts[-50:]  # Last 50 alerts
        }
        
        filename = CONFIG["REPORT_DIR"] / f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filename.write_text(json.dumps(report, indent=2, default=str))
        print(f"{Colors.GREEN}[+] Report exported: {filename}{Colors.RESET}")
        return str(filename)
