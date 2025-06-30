#!/usr/bin/env python3

import subprocess
import requests
import socket
import ssl
import sys
import json
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

BANNER = r"""
   ▄▄▄█████▓██░ ██ █    ██ ███▄    █▓█████▄▓█████ ██▀███      █     █▓█████ ▄▄▄▄       ▄████▄  ██░ ██▓█████ ▄████▄  ██ ▄█▓█████ ██▀███  
   ▓  ██▒ ▓▓██░ ██▒██  ▓██▒██ ▀█   █▒██▀ ██▓█   ▀▓██ ▒ ██▒   ▓█░ █ ░█▓█   ▀▓█████▄    ▒██▀ ▀█ ▓██░ ██▓█   ▀▒██▀ ▀█  ██▄█▒▓█   ▀▓██ ▒ ██▒
   ▒ ▓██░ ▒▒██▀▀██▓██  ▒██▓██  ▀█ ██░██   █▒███  ▓██ ░▄█ ▒   ▒█░ █ ░█▒███  ▒██▒ ▄██   ▒▓█    ▄▒██▀▀██▒███  ▒▓█    ▄▓███▄░▒███  ▓██ ░▄█ ▒
   ░ ▓██▓ ░░▓█ ░██▓▓█  ░██▓██▒  ▐▌██░▓█▄   ▒▓█  ▄▒██▀▀█▄     ░█░ █ ░█▒▓█  ▄▒██░█▀     ▒▓▓▄ ▄██░▓█ ░██▒▓█  ▄▒▓▓▄ ▄██▓██ █▄▒▓█  ▄▒██▀▀█▄  
     ▒██▒ ░░▓█▒░██▒▒█████▓▒██░   ▓██░▒████▓░▒████░██▓ ▒██▒   ░░██▒██▓░▒████░▓█  ▀█▓   ▒ ▓███▀ ░▓█▒░██░▒████▒ ▓███▀ ▒██▒ █░▒████░██▓ ▒██▒
     ▒ ░░   ▒ ░░▒░░▒▓▒ ▒ ▒░ ▒░   ▒ ▒ ▒▒▓  ▒░░ ▒░ ░ ▒▓ ░▒▓░   ░ ▓░▒ ▒ ░░ ▒░ ░▒▓███▀▒   ░ ░▒ ▒  ░▒ ░░▒░░░ ▒░ ░ ░▒ ▒  ▒ ▒▒ ▓░░ ▒░ ░ ▒▓ ░▒▓░
       ░    ▒ ░▒░ ░░▒░ ░ ░░ ░░   ░ ▒░░ ▒  ▒ ░ ░  ░ ░▒ ░ ▒░     ▒ ░ ░  ░ ░  ▒░▒   ░      ░  ▒   ▒ ░▒░ ░░ ░  ░ ░  ▒  ░ ░▒ ▒░░ ░  ░ ░▒ ░ ▒░
     ░      ░  ░░ ░░░░ ░ ░   ░   ░ ░ ░ ░  ░   ░    ░░   ░      ░   ░    ░   ░    ░    ░        ░  ░░ ░  ░  ░       ░ ░░ ░   ░    ░░   ░ 
            ░  ░  ░  ░             ░   ░      ░  ░  ░            ░      ░  ░░         ░ ░      ░  ░  ░  ░  ░ ░     ░  ░     ░  ░  ░     
                                     ░                                           ░    ░                    ░                            
"""

headers = {
    'User-Agent': 'Mozilla/5.0 (WebSecurityScanner/1.0 KaliGPT)'
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
                no_csrf.append(str(form))
        return no_csrf
    except:
        return []

def check_tech_and_versions(target):
    try:
        ww_out = subprocess.check_output(["whatweb", target], stderr=subprocess.DEVNULL).decode()
        matches = re.findall(r'([a-zA-Z0-9\-]+)\[(.*?)\]', ww_out)
        tech_versions = {name: version for name, version in matches}
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
        output = subprocess.check_output(["sslscan", urlparse(target).hostname], stderr=subprocess.DEVNULL).decode()
        return output
    except:
        return "sslscan failed or not installed"

def run_testssl(target):
    try:
        output = subprocess.check_output(["testssl.sh", "--quiet", target], stderr=subprocess.DEVNULL).decode()
        return output
    except:
        return "testssl.sh failed or not installed"

def scan(target):
    print(BANNER)
    print(f"[+] Thunder Web Checker scanning {target}\n")

    print("[*] SSL Certificate Expiry Date:")
    print(check_ssl_expiry(target), "\n")

    print("[*] Running sslscan:")
    print(run_sslscan(target), "\n")

    print("[*] Running testssl.sh:")
    print(run_testssl(target), "\n")

    print("[*] X-Frame-Options header present:")
    print(check_x_frame(target), "\n")

    print("[*] Forms without CSRF protection:")
    forms = check_csrf_forms(target)
    print(f"Found {len(forms)} forms without CSRF tokens.\n")

    print("[*] Web Technologies and Versions:")
    techs = check_tech_and_versions(target)
    for k, v in techs.items():
        print(f"  {k}: {v}")
    print()

    print("[*] Website loads identically via IP:")
    print(check_ip_loading(target))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 thunder_web_checker.py <target_url>")
        sys.exit(1)

    target = sys.argv[1]
    scan(target)
