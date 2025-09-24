#!/usr/bin/env python3
import subprocess
import xml.etree.ElementTree as ET
import hashlib
import os
import sys
import platform
from colorama import init, Fore

# Colorama init
init(autoreset=True)

# -----------------------------
# CONFIG (changeable)
TARGET = "127.0.0.1"  # target IP
HIGH_RISK_PORTS = [135, 445, 3826, 5357]  # ports to block via firewall
# -----------------------------

# 0️⃣ Privilege check
def check_privileges():
    system = platform.system()
    if system == "Linux":
        if os.geteuid() != 0:
            print(Fore.RED + "[!] Linux: Script requires root privileges. Run with sudo.")
            sys.exit(1)
    elif system == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                print(Fore.RED + "[!] Windows: Script must be run as Administrator.")
                sys.exit(1)
        except Exception:
            print(Fore.YELLOW + "[!] Windows: Admin check failed, continuing anyway.")
check_privileges()

# 1️⃣ Nmap scan
print(Fore.CYAN + f"[+] Running Nmap scan on {TARGET}...")
nmap_cmd = ["nmap", "-sV", "-oX", "scan.xml", TARGET]
try:
    subprocess.run(nmap_cmd, check=True)
except subprocess.CalledProcessError:
    print(Fore.RED + "[-] Nmap scan failed. Is Nmap installed?")
    sys.exit(1)

# 2️⃣ XML parsing
tree = ET.parse("scan.xml")
root = tree.getroot()

found_services = []

for host in root.findall("host"):
    for port in host.findall("ports/port"):
        port_id = port.get("portid")
        service = port.find("service")
        if service is not None:
            service_name = service.get("name")
            found_services.append((int(port_id), service_name))

# 3️⃣ Hash and console output
print(Fore.GREEN + "[+] Found services and hashes:")
for port, service_name in found_services:
    raw_info = f"{TARGET}:{port}:{service_name}"
    hashed = hashlib.sha256(raw_info.encode()).hexdigest()
    print(Fore.YELLOW + f"Port {port} - Service: {service_name} - Hash: {hashed}")

# 4️⃣ Add firewall rules
system = platform.system()
print(Fore.CYAN + "[+] Adding firewall rules for high-risk ports...")
for port, service_name in found_services:
    if port in HIGH_RISK_PORTS:
        print(Fore.RED + f"[!] Blocking port {port} ({service_name})")
        if system == "Windows":
            cmd = f'netsh advfirewall firewall add rule name="Block Port {port}" protocol=TCP dir=in localport={port} action=block'
            os.system(cmd)
        elif system == "Linux":
            ufw_check = subprocess.run(["which", "ufw"], stdout=subprocess.DEVNULL)
            if ufw_check.returncode == 0:
                os.system(f"ufw deny {port}/tcp")
            else:
                os.system(f"iptables -A INPUT -p tcp --dport {port} -j DROP")

print(Fore.GREEN + "[+] Checker finished successfully!")
