#!/bin/bash
# ╔══════════════════════════════════════════════════════╗
# ║   SETUP SCRIPT - setup.sh                          ║
# ║   Installs all dependencies on Kali Linux          ║
# ╚══════════════════════════════════════════════════════╝

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}"
echo "  ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ "
echo "  ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗"
echo "     ██║   ███████║██████╔╝█████╗  ███████║   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝"
echo "     ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗"
echo "     ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║"
echo "     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
echo -e "${RESET}"
echo -e "${BOLD}  Active Threat Hunting System - Setup Script${RESET}"
echo -e "${CYAN}  ═══════════════════════════════════════════════════${RESET}"
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux"* ]]; then
    echo -e "${RED}[!] This script is designed for Kali Linux${RESET}"
    exit 1
fi

echo -e "${CYAN}[*] Checking Python version...${RESET}"
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo -e "${RED}[!] Python 3.8+ required (found: Python $PYTHON_VERSION)${RESET}"
    exit 1
fi

echo -e "${GREEN}[+] Python $PYTHON_VERSION found${RESET}"

echo ""
echo -e "${CYAN}[*] Installing Python packages...${RESET}"

pip3 install flask --quiet && echo -e "${GREEN}[+] flask installed${RESET}" || echo -e "${YELLOW}[!] flask install failed${RESET}"

# Optional packages for enhanced features
echo ""
echo -e "${CYAN}[*] Installing optional packages (enhanced geolocation/analysis)...${RESET}"

pip3 install requests --quiet && echo -e "${GREEN}[+] requests installed${RESET}"
pip3 install colorama --quiet && echo -e "${GREEN}[+] colorama installed${RESET}"

echo ""
echo -e "${CYAN}[*] Checking system tools...${RESET}"

check_tool() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}[+] $1 found${RESET}"
    else
        echo -e "${YELLOW}[!] $1 not found - install with: apt install $2${RESET}"
    fi
}

check_tool "tcpdump" "tcpdump"
check_tool "nmap" "nmap"
check_tool "fail2ban-client" "fail2ban"
check_tool "wazuh-manager" "wazuh-manager"

echo ""
echo -e "${CYAN}[*] Creating directory structure...${RESET}"
mkdir -p data logs reports dashboard core
touch core/__init__.py dashboard/__init__.py
echo -e "${GREEN}[+] Directories created${RESET}"

echo ""
echo -e "${CYAN}[*] Setting permissions...${RESET}"
chmod +x main.py 2>/dev/null
chmod +x setup.sh 2>/dev/null
echo -e "${GREEN}[+] Permissions set${RESET}"

echo ""
echo -e "${CYAN}[*] Checking log file access...${RESET}"

check_log() {
    if [ -r "$1" ]; then
        echo -e "${GREEN}[+] Readable: $1${RESET}"
    else
        echo -e "${YELLOW}[~] Not readable: $1 (run with sudo for full access)${RESET}"
    fi
}

check_log "/var/log/auth.log"
check_log "/var/log/syslog"
check_log "/var/log/fail2ban.log"
check_log "/var/log/apache2/access.log"
check_log "/var/log/audit/audit.log"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║  SETUP COMPLETE! How to run:                   ║${RESET}"
echo -e "${GREEN}${BOLD}╠══════════════════════════════════════════════════╣${RESET}"
echo -e "${GREEN}${BOLD}║                                                  ║${RESET}"
echo -e "${GREEN}${BOLD}║  Demo (recommended first):                      ║${RESET}"
echo -e "${GREEN}${BOLD}║    python3 main.py --demo                       ║${RESET}"
echo -e "${GREEN}${BOLD}║                                                  ║${RESET}"
echo -e "${GREEN}${BOLD}║  Interactive menu:                               ║${RESET}"
echo -e "${GREEN}${BOLD}║    python3 main.py                               ║${RESET}"
echo -e "${GREEN}${BOLD}║                                                  ║${RESET}"
echo -e "${GREEN}${BOLD}║  Live monitoring (requires root):                ║${RESET}"
echo -e "${GREEN}${BOLD}║    sudo python3 main.py --live                  ║${RESET}"
echo -e "${GREEN}${BOLD}║                                                  ║${RESET}"
echo -e "${GREEN}${BOLD}║  Web dashboard:                                  ║${RESET}"
echo -e "${GREEN}${BOLD}║    python3 dashboard/dashboard.py               ║${RESET}"
echo -e "${GREEN}${BOLD}║    Open: http://localhost:5000                   ║${RESET}"
echo -e "${GREEN}${BOLD}║                                                  ║${RESET}"
echo -e "${GREEN}${BOLD}║  Parse system logs:                              ║${RESET}"
echo -e "${GREEN}${BOLD}║    sudo python3 main.py --parse-logs            ║${RESET}"
echo -e "${GREEN}${BOLD}║                                                  ║${RESET}"
echo -e "${GREEN}${BOLD}║  Parse specific log file:                        ║${RESET}"
echo -e "${GREEN}${BOLD}║    python3 main.py --log /var/log/auth.log      ║${RESET}"
echo -e "${GREEN}${BOLD}║                                                  ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
echo ""
