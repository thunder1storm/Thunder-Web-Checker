#!/usr/bin/env python3

import subprocess
import requests
import socket
import ssl
import sys
import re
import json
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

headers = {
    'User-Agent': 'Mozilla/5.0 (WebSecurityScanner/1.0 ThunderWebChecker)'
}

BANNER = r"""
   ▄▄▄█████▓██░ ██ █    ██ ███▄    █▓█████▄▓█████ ██▀███      █     █▓█████ ▄▄▄▄       ▄████▄  ██░ ██▓█████ ▄████▄  ██ ▄█▓█████ ██▀███  
   ▓  ██▒ ▓▓██░ ██▒██  ▓██▒██ ▀█   █▒██▀ ██▓█   ▀▓██ ▒ ██▒   ▓█░ █ ░█▓█   ▀▓█████▄    ▒██▀ ▀█ ▓██░ ██▓█   ▀▒██▀ ▀█  ██▄█▒▓█   ▀▓██ ▒ ██▒
   ▒ ▓██░ ▒▒██▀▀██▓██  ▒██▓██  ▀█ ██░██   █▒███  ▓██ ░▄█ ▒   ▒█░ █ ░█▒███  ▒██▒ ▄██   ▒▓█    ▄▒██▀▀██▒███  ▒▓█    ▄▓███▄░▒███  ▓██ ░▄█ ▒
   ░ ▓██▓ ░░▓█ ░██▓▓█  ░██▓██▒  ▐▌██░▓█▄   ▒▓█  ▄▒██▀▀█▄     ░█░ █ ░█▒▓█  ▄▒██░█▀     ▒▓▓▄ ▄██░▓█ ░██▒▓█  ▄▒▓▓▄ ▄██▓██ █▄▒▓█  ▄▒██▀▀█▄  
     ▒██▒ ░░▓█▒░██▒▒█████▓▒██░   ▓██░▒████▓░▒████░██▓ ▒██▒   ░░██▒██▓░▒████░▓█  ▀█▓   ▒ ▓███▀ ░▓█▒░██░▒████▒ ▓███▀ ▒██▒ █░▒████░██▓ ▒██▒
     ▒ ░░   ▒ ░░▒░░▒▓▒ ▒ ▒░ ▒░   ▒ ▒ ▒▒▓  ▒░░ ▒░ ░ ▒▓ ░▒▓░   ░ ▓░▒ ▒ ░░ ▒░ ░▒▓███▀▒   ░ ░▒ ▒  ░▒ ░░▒░░░ ▒░ ░ ░▒ ▒  ▒ ▒▒ ▓░░ ▒░ ░ ▒▓ ░▒▓░
       ░    ▒ ░▒░ ░░▒░ ░ ░░ ░░   ░ ▒░░ ▒  ▒ ░ ░  ░ ░▒ ░ ▒░     ▒ ░ ░  ░ ░  ▒░▒   ░      ░  ▒   ▒ ░▒░ ░░ ░  ░ ░  ▒  ░ ░▒ ▒░░ ░  ░ ░▒ ░ ▒░
     ░      ░  ░░ ░░░░ ░ ░   ░   ░ ░ ░ ░  ░   ░    ░░   ░      ░   ░    ░   ░    ░    ░        ░  ░░ ░  ░  ░ ░     ░ ░░ ░   ░    ░░   ░ 
            ░  ░  ░  ░             ░   ░      ░  ░  ░            ░      ░  ░░         ░ ░      ░  ░  ░  ░  ░ ░     ░  ░     ░  ░  ░     
                                     ░                                           ░    ░                    ░                            
"""

def get_hosting_details(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=isp,org,country,regionName,city,as,query", timeout=8)
        data = response.json()
        return {
            'isp': data.get('isp', 'Unknown'),
            'org': data.get('org', 'Unknown'),
            'location': f"{data.get('city')}, {data.get('regionName')}, {data.get('country')}",
            'asn': data.get('as', 'Unknown'),
            'cloud': any(cloud in data.get('org', '').lower() for cloud in ['amazon', 'google', 'azure', 'cloudflare'])
        }
    except Exception:
        return {
            'isp': 'Unknown', 'org': 'Unknown', 'location': 'Unknown', 'asn': 'Unknown', 'cloud': False
        }

def run_service_scan(target):
    try:
        host = urlparse(target).hostname
        print(Fore.CYAN + "\n[+] Service and Version Detection")
        print(Fore.YELLOW + "Running: nmap -sV --version-light <host>\n")
        result = subprocess.check_output(["nmap", "-sV", "--version-light", host], stderr=subprocess.DEVNULL).decode()
        print(Fore.GREEN + result)
        outdated = re.findall(r"(\d+/tcp).*?open.*?([\w-]+)\s+(\d+[\.\d+]*)", result)
        if outdated:
            print(Fore.RED + "[!] Possible outdated services detected:")
            for port, service, version in outdated:
                print(Fore.RED + f"    {port} → {service} {version}")
        else:
            print(Fore.GREEN + "[+] No obviously outdated versions detected.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to scan services: {e}")

def scan_summary(ip, hosting):
    print(Fore.YELLOW + "\n] Scan Summary")
    print(Fore.CYAN + f"🔍 Domain: {socket.getfqdn(ip)}")
    print(Fore.CYAN + f"📡 Resolved IP: {ip}")
    print(Fore.CYAN + f"🌍 Location: {hosting['location']}")
    print(Fore.CYAN + f"☁ Hosted in Cloud: {'Yes (' + hosting['org'] + ')' if hosting['cloud'] else 'No'}")
    print(Fore.CYAN + f"🏢 Hosting Org: {hosting['org']}")
    print(Fore.CYAN + f"🛰️ ISP: {hosting['isp']}")
    print(Fore.CYAN + f"🔗 ASN: {hosting['asn']}")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 thunder_web_checker.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    print(BANNER)
    try:
        ip = socket.gethostbyname(urlparse(target).hostname)
        hosting_info = get_hosting_details(ip)
        scan_summary(ip, hosting_info)
        run_service_scan(target)
    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")
