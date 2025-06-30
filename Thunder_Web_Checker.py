#!/usr/bin/env python3

import subprocess
import requests
import socket
import ssl
import sys
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

BANNER = r"""
   ▄▄▄█████▓██░ ██ █    ██ ███▄    █▓█████▄▓█████ ██▀███      █     █▓█████ ▄▄▄▄       ▄████▄  ██░ ██▓█████ ▄████▄  ██ ▄█▓█████ ██▀███  
   ▓  ██▒ ▓▓██░ ██▒██  ▓██▒██ ▀█   █▒██▀ ██▓█   ▀▓██ ▒ ██▒   ▓█░ █ ░█▓█   ▀▓█████▄    ▒██▀ ▀█ ▓██░ ██▓█   ▀▒██▀ ▀█  ██▄█▒▓█   ▀▓██ ▒ ██▒
   ▒ ▓██░ ▒▒██▀▀██▓██  ▒██▓██  ▀█ ██░██   █▒███  ▓██ ░▄█ ▒   ▒█░ █ ░█▒███  ▒██▒ ▄██   ▒▓█    ▄▒██▀▀██▒███  ▒▓█    ▄▓███▄░▒███  ▓██ ░▄█ ▒
   ░ ▓██▓ ░░▓█ ░██▓▓█  ░██▓██▒  ▐▌██░▓█▄   ▒▓█  ▄▒██▀▀█▄     ░█░ █ ░█▒▓█  ▄▒██░█▀     ▒▓▓▄ ▄██░▓█ ░██▒▓█  ▄▒▓▓▄ ▄██▓██ █▄▒▓█  ▄▒██▀▀█▄  
     ▒██▒ ░░▓█▒░██▒▒█████▓▒██░   ▓██░▒████▓░▒████░██▓ ▒██▒   ░░██▒██▓░▒████░▓█  ▀█▓   ▒ ▓███▀ ░▓█▒░██░▒████▒ ▓███▀ ▒██▒ █░▒████░██▓ ▒██▒
"""

headers = {
    'User-Agent': 'Mozilla/5.0 (WebSecurityScanner/1.0 ThunderWebChecker)'
}

def get_ip(target):
    try:
        return socket.gethostbyname(urlparse(target).hostname)
    except:
        return None

def check_ssl_expiry(target):
    hostname = urlparse(target).hostname
    port = 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert['notAfter']
    except Exception as e:
        return f"SSL error: {e}"

def check_x_frame(target):
    try:
        r = requests.get(target, headers=headers, timeout=10)
        return 'X-Frame-Options' in r.headers
    except:
        return False

def check_csrf_forms(target):
    try:
        r = requests.get(target, headers=headers, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        forms = soup.find_all('form')
        no_csrf = []
        for form in forms:
            if not form.find('input', {'type': 'hidden', 'name': re.compile('csrf', re.I)}):
                signature = str(form)[:100]  # Shortened for cleaner output
                if signature not in no_csrf:
                    no_csrf.append(signature)
        return no_csrf
    except:
        return []

def check_tech_and_versions(target):
    try:
        ww_out = subprocess.check_output(["whatweb", target], stderr=subprocess.DEVNULL).decode()
        matches = re.findall(r'([a-zA-Z0-9\-]+)\[(.*?)\]', ww_out)
        tech_versions = {}
        for name, version in matches:
            name = name.strip()
            version = version.strip()
            if name not in tech_versions:
                tech_versions[name] = set()
            tech_versions[name].add(version)
        return tech_versions
    except:
        return {}

def check_ip_loading(target):
    try:
        ip = get_ip(target)
        r1 = requests.get(target, headers=headers, timeout=10)
        ip_url = f"http://{ip}"
        r2 = requests.get(ip_url, headers=headers, timeout=10)
        return r1.text.strip() == r2.text.strip()
    except:
        return False

def run_sslscan(target):
    try:
        return subprocess.check_output(["sslscan", urlparse(target).hostname], stderr=subprocess.DEVNULL).decode()
    except:
        return "sslscan failed or not installed"

def run_testssl(target):
    try:
        return subprocess.check_output(["testssl.sh", "--quiet", target], stderr=subprocess.DEVNULL).decode()
    except:
        return "testssl.sh failed or not installed"

def run_nmap_ports(target):
    try:
        hostname = urlparse(target).hostname
        nmap_cmd = ["nmap", "-Pn", "-T4", "-F", hostname]
        output = subprocess.check_output(nmap_cmd, stderr=subprocess.DEVNULL).decode()
        return output
    except:
        return "Nmap scan failed or not installed"

def scan(target):
    print(BANNER)
    print(f"\n[+] Thunder Web Checker scanning: {target}\n")

    print("🔒 SSL Certificate Expiry Date:")
    print("   ", check_ssl_expiry(target), "\n")

    print("🧪 Running sslscan:")
    print(run_sslscan(target), "\n")

    print("🧪 Running testssl.sh:")
    print(run_testssl(target), "\n")

    print("🛡️  X-Frame-Options header present:")
    print("   ", check_x_frame(target), "\n")

    print("🔐 Forms without CSRF protection:")
    forms = check_csrf_forms(target)
    print(f"   Found {len(forms)} potential forms missing CSRF tokens.\n")

    print("🔍 Web Technologies and Versions:")
    techs = check_tech_and_versions(target)
    for k, v_set in techs.items():
        versions = ", ".join(sorted(v_set))
        print(f"   {k}: {versions}")
    print()

    print("🌐 Website loads identically via IP:")
    print("   ", check_ip_loading(target), "\n")

    print("📡 Nmap Fast Port Scan Results:")
    print(run_nmap_ports(target), "\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 thunder_web_checker.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    scan(target)
