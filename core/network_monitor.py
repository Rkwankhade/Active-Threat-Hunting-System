#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   NETWORK MONITOR - network_monitor.py              ║
║   Live packet capture + port scan detection         ║
╚══════════════════════════════════════════════════════╝
Uses: tcpdump (always available on Kali) or scapy
Detects: Port scans, suspicious connections, exfil
"""

import os
import sys
import time
import json
import socket
import struct
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.threat_engine import ThreatHunter, Colors


class NetworkMonitor:
    """
    Real-time network traffic analyzer.
    Uses tcpdump subprocess for compatibility on Kali Linux.
    Falls back to /proc/net for connection tracking.
    """
    
    def __init__(self, hunter: ThreatHunter, interface: str = None):
        self.hunter = hunter
        self.interface = interface or self._detect_interface()
        self.running = False
        self.stop_event = threading.Event()
        self.connection_state = {}    # Track established connections
        self.bytes_tracker = defaultdict(int)  # Track data per IP
        self.EXFIL_THRESHOLD = 50 * 1024 * 1024  # 50MB
        self.LOCAL_IP = self._get_local_ip()
        
    def _detect_interface(self) -> str:
        """Auto-detect active network interface"""
        try:
            result = subprocess.run(
                ["ip", "route", "get", "8.8.8.8"],
                capture_output=True, text=True, timeout=5
            )
            for word in result.stdout.split():
                if word == "dev":
                    idx = result.stdout.split().index(word)
                    return result.stdout.split()[idx + 1]
        except:
            pass
        return "eth0"
    
    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _parse_tcpdump_line(self, line: str):
        """Parse a tcpdump output line for threat detection"""
        # tcpdump format: HH:MM:SS.microsec IP src.port > dst.port: flags [S]
        
        # Detect SYN packets (connection attempts / port scans)
        if " S " in line or "[S]" in line or "Flags [S]" in line:
            parts = line.split()
            try:
                # Find IP addresses
                for i, part in enumerate(parts):
                    if ">" in part and "." in parts[max(0,i-1)]:
                        src = parts[i-1]
                        dst = parts[i+1].rstrip(":")
                        
                        # Parse src/dst into IP and port
                        src_parts = src.rsplit(".", 1)
                        dst_parts = dst.rsplit(".", 1)
                        
                        if len(src_parts) == 2 and len(dst_parts) == 2:
                            src_ip, src_port = src_parts
                            dst_ip, dst_port_str = dst_parts
                            
                            # Ignore local traffic
                            if src_ip not in ("127.0.0.1", self.LOCAL_IP, "::1"):
                                try:
                                    dst_port = int(dst_port_str)
                                    self.hunter.detect_port_scan(
                                        src_ip, dst_ip, dst_port, "TCP"
                                    )
                                except ValueError:
                                    pass
                        break
            except (IndexError, ValueError):
                pass
        
        # Detect large data transfers (potential exfil)
        if "length" in line.lower():
            try:
                idx = line.lower().index("length")
                length_str = line[idx+7:].split()[0].rstrip(")")
                length = int(length_str)
                
                if length > 10000:  # >10KB in single packet
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if ">" in part:
                            try:
                                dst = parts[i+1].rstrip(":")
                                dst_ip = dst.rsplit(".", 1)[0]
                                src = parts[i-1]
                                src_ip = src.rsplit(".", 1)[0]
                                
                                self.bytes_tracker[src_ip] += length
                                
                                if self.bytes_tracker[src_ip] > self.EXFIL_THRESHOLD:
                                    self.hunter.detect_data_exfiltration(
                                        src_ip, self.LOCAL_IP, dst_ip,
                                        self.bytes_tracker[src_ip], "TCP"
                                    )
                                    self.bytes_tracker[src_ip] = 0  # Reset after alert
                            except (IndexError, ValueError):
                                pass
                            break
            except (ValueError, IndexError):
                pass
    
    def start_tcpdump_capture(self):
        """
        Launch tcpdump as subprocess and parse output.
        This works on Kali Linux without additional dependencies.
        """
        # Check if we can run tcpdump
        check = subprocess.run(["which", "tcpdump"], capture_output=True)
        if check.returncode != 0:
            print(f"{Colors.RED}[!] tcpdump not found. Install: apt install tcpdump{Colors.RESET}")
            return
        
        cmd = [
            "tcpdump",
            "-i", self.interface,
            "-l",           # Line-buffered output
            "-n",           # Don't resolve hostnames (faster)
            "-q",           # Quiet mode
            "--no-promiscuous-mode",  # Less intrusive
            "tcp",          # Only TCP traffic
        ]
        
        print(f"{Colors.GREEN}[+] Starting packet capture on {self.interface}...{Colors.RESET}")
        print(f"{Colors.DIM}    Command: {' '.join(cmd)}{Colors.RESET}")
        print(f"{Colors.YELLOW}[!] Note: Requires root/sudo for raw packet capture{Colors.RESET}\n")
        
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.running = True
            packet_count = 0
            
            while not self.stop_event.is_set():
                line = proc.stdout.readline()
                if line:
                    packet_count += 1
                    self._parse_tcpdump_line(line)
                    
                    if packet_count % 100 == 0:
                        print(f"{Colors.DIM}[~] Packets analyzed: {packet_count}{Colors.RESET}", end='\r')
                else:
                    time.sleep(0.01)
            
            proc.terminate()
            
        except PermissionError:
            print(f"{Colors.RED}[!] Permission denied. Run with: sudo python3 main.py{Colors.RESET}")
        except FileNotFoundError:
            print(f"{Colors.RED}[!] tcpdump not found{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[!] Capture error: {e}{Colors.RESET}")
        finally:
            self.running = False
    
    def monitor_connections_proc(self):
        """
        Monitor /proc/net/tcp for connection tracking.
        Works WITHOUT root privileges.
        """
        print(f"{Colors.GREEN}[+] Monitoring network connections via /proc/net/tcp{Colors.RESET}")
        
        known_connections = set()
        
        while not self.stop_event.is_set():
            try:
                connections = self._read_proc_net_tcp()
                
                for conn in connections:
                    conn_id = f"{conn['remote_ip']}:{conn['remote_port']}->{conn['local_port']}"
                    
                    if conn_id not in known_connections and conn["state"] == "ESTABLISHED":
                        known_connections.add(conn_id)
                        remote_ip = conn["remote_ip"]
                        
                        # Skip local/loopback
                        if remote_ip.startswith(("127.", "0.0.0.", "::1")):
                            continue
                        
                        print(f"{Colors.DIM}[~] New connection: {remote_ip}:{conn['remote_port']} → :{conn['local_port']}{Colors.RESET}")
                        
                        # Detect scanning (rapid new connections)
                        self.hunter.detect_port_scan(
                            remote_ip, self.LOCAL_IP, conn["local_port"], "TCP"
                        )
                
                # Clean up closed connections
                current_ids = {
                    f"{c['remote_ip']}:{c['remote_port']}->{c['local_port']}"
                    for c in connections
                }
                known_connections = known_connections & current_ids
                
            except Exception as e:
                pass
            
            time.sleep(2)  # Check every 2 seconds
    
    def _read_proc_net_tcp(self) -> list:
        """Read TCP connection table from /proc/net/tcp"""
        connections = []
        
        for proc_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
            try:
                with open(proc_file) as f:
                    lines = f.readlines()[1:]  # Skip header
                
                for line in lines:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    
                    local = parts[1]
                    remote = parts[2]
                    state_hex = parts[3]
                    
                    # Parse hex addresses
                    local_port = int(local.split(":")[1], 16)
                    remote_addr, remote_port_hex = remote.split(":")
                    remote_port = int(remote_port_hex, 16)
                    
                    # Convert hex IP to dotted notation
                    remote_ip = self._hex_to_ip(remote_addr)
                    
                    # State: 01=ESTABLISHED, 0A=LISTEN
                    state_map = {
                        "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
                        "04": "FIN_WAIT1", "0A": "LISTEN", "06": "TIME_WAIT"
                    }
                    state = state_map.get(state_hex, state_hex)
                    
                    connections.append({
                        "local_port": local_port,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "state": state
                    })
            except (FileNotFoundError, PermissionError):
                pass
        
        return connections
    
    def _hex_to_ip(self, hex_addr: str) -> str:
        """Convert /proc/net/tcp hex address to dotted IP"""
        try:
            if len(hex_addr) == 8:
                # IPv4: little-endian
                packed = bytes.fromhex(hex_addr)
                return socket.inet_ntoa(packed[::-1])
            else:
                # IPv6
                return "::1"
        except:
            return "0.0.0.0"
    
    def scan_active_connections(self) -> dict:
        """Snapshot of all current network connections"""
        connections = self._read_proc_net_tcp()
        summary = {
            "total": len(connections),
            "established": [],
            "listening": [],
            "suspicious": []
        }
        
        suspicious_ports = {4444, 1337, 31337, 8888, 9999, 6666}  # Common reverse shell ports
        
        for conn in connections:
            if conn["state"] == "ESTABLISHED":
                summary["established"].append(conn)
                if conn["remote_port"] in suspicious_ports or conn["local_port"] in suspicious_ports:
                    summary["suspicious"].append(conn)
                    self.hunter._raise_alert(
                        conn["remote_ip"],
                        "SUSPICIOUS_PORT_DETECTED",
                        f"Connection on suspicious port {conn['remote_port']} or {conn['local_port']} (possible reverse shell)",
                        "HIGH",
                        "T1059"
                    )
            elif conn["state"] == "LISTEN":
                summary["listening"].append(conn)
        
        return summary
    
    def start(self, use_tcpdump: bool = True):
        """Start network monitoring"""
        if use_tcpdump and os.geteuid() == 0:  # Root check
            thread = threading.Thread(
                target=self.start_tcpdump_capture,
                daemon=True,
                name="packet-capture"
            )
        else:
            if use_tcpdump and os.geteuid() != 0:
                print(f"{Colors.YELLOW}[!] Not root — using /proc/net monitoring (limited){Colors.RESET}")
            thread = threading.Thread(
                target=self.monitor_connections_proc,
                daemon=True,
                name="proc-net-monitor"
            )
        
        thread.start()
        return thread
    
    def stop(self):
        self.stop_event.set()
        self.running = False
