#!/usr/bin/env python3

import subprocess
import requests
import socket
import ssl
import sys
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

headers = {
    'User-Agent': 'Mozilla/5.0 (WebSecurityScanner/1.0 ThunderWebChecker)'
}

BANNER = r"""
   ▀▀▀▀█████═██▒ ██ █    ██ ███▄    █████▄█████ ██═███      █     █████ ▀▀▀▀       ▀███▀█  ██▒ █████ ▀████▀  ██ ▀▄█████ ██═███
"""

def print_header(title):
    print(Fore.CYAN + f"\n[+] {title}")

def get_ip(target):
    try:
        return socket.gethostbyname(urlparse(target).hostname)
    except:
        return None

def check_ssl_expiry_short(target):
    hostname = urlparse(target).hostname
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert['notAfter']
    except:
        return "Unavailable"

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
        no_csrf = 0
        for form in forms:
            if not form.find('input', {'type': 'hidden', 'name': re.compile('csrf', re.I)}):
                no_csrf += 1
        return no_csrf
    except:
        return -1

def check_ip_loading(target):
    try:
        ip = get_ip(target)
        r1 = requests.get(target, headers=headers, timeout=10)
        r2 = requests.get(f"http://{ip}", headers=headers, timeout=10)
        return r1.text.strip() == r2.text.strip()
    except:
        return False

def run_nmap_ports(target):
    try:
        hostname = urlparse(target).hostname
        output = subprocess.check_output(["nmap", "-T4", "-F", hostname], stderr=subprocess.DEVNULL).decode()
        ports = re.findall(r"(\d+/tcp)\s+open\s+([\w\-]+)", output)
        return ports
    except:
        return []

def is_behind_cloudflare(target):
    try:
        ip = socket.gethostbyname(urlparse(target).hostname)
        cf_ranges = ["104.", "172.", "198.", "190.", "162.", "188.", "203.", "141."]
        return any(ip.startswith(r) for r in cf_ranges)
    except:
        return False

def get_hosting_info(domain):
    result = {
        "IP": "Unavailable",
        "Reverse DNS": "Unavailable",
        "Hosting Org": "Unavailable",
        "Country": "Unavailable"
    }
    try:
        ip = socket.gethostbyname(domain)
        result["IP"] = ip
        try:
            result["Reverse DNS"] = socket.gethostbyaddr(ip)[0]
        except:
            result["Reverse DNS"] = "N/A"
        whois_out = subprocess.check_output(["whois", domain], stderr=subprocess.DEVNULL).decode()
        for line in whois_out.splitlines():
            if any(x in line.lower() for x in ["orgname", "org-name", "organization", "org"]):
                result["Hosting Org"] = line.split(":")[-1].strip()
            elif "country" in line.lower():
                result["Country"] = line.split(":")[-1].strip()
    except:
        pass
    return result

def extract_contact_info(target):
    try:
        r = requests.get(target, headers=headers, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        text = soup.get_text()
        email_matches = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        phone_matches = re.findall(r'\+?\d[\d\-\(\) ]{6,}\d', text)
        addresses = [addr.get_text(strip=True) for addr in soup.find_all('address')]
        return {
            "Emails": list(set(email_matches)),
            "Phones": list(set(phone_matches)),
            "Addresses": addresses
        }
    except:
        return {
            "Emails": [],
            "Phones": [],
            "Addresses": []
        }

def run_wappalyzer(target):
    try:
        output = subprocess.check_output([
            "node", "wappalyzer/src/drivers/npm/cli.js", target
        ], stderr=subprocess.DEVNULL).decode()
        return output
    except Exception as e:
        return f"Wappalyzer failed: {e}"

def scan(target):
    print(Fore.MAGENTA + BANNER)
    print(Fore.YELLOW + f"Target: {target}\n")

    ip = get_ip(target)
    ssl_expiry = check_ssl_expiry_short(target)
    cloudflare = is_behind_cloudflare(target)
    x_frame = check_x_frame(target)
    csrf_forms = check_csrf_forms(target)
    ip_match = check_ip_loading(target)
    open_ports = run_nmap_ports(target)

    print_header("Scan Summary")
    print(f"{Fore.GREEN}📡 Resolved IP: {ip if ip else Fore.RED + 'Unavailable'}")
    print(f"{Fore.GREEN}🔒 SSL Expiry: {Fore.WHITE}{ssl_expiry}")
    print(f"{Fore.GREEN}☁️ Behind Cloudflare: {Fore.GREEN if cloudflare else Fore.RED}{'Yes' if cloudflare else 'No'}")
    print(f"{Fore.GREEN}🛡️ X-Frame-Options: {Fore.GREEN if x_frame else Fore.RED}{'Present' if x_frame else 'Missing'}")

    if csrf_forms >= 0:
        color = Fore.RED if csrf_forms > 0 else Fore.GREEN
        print(f"{Fore.GREEN}🔐 CSRF Protection: {color}{'Forms missing CSRF: ' + str(csrf_forms) if csrf_forms else 'All forms have CSRF tokens'}")
    else:
        print(f"{Fore.YELLOW}🔐 CSRF Protection: Unable to verify")

    print(f"{Fore.GREEN}🌍 Same content via IP: {Fore.GREEN if ip_match else Fore.RED}{'Yes' if ip_match else 'No'}")

    print(f"{Fore.GREEN}📡 Open Ports:")
    if not open_ports:
        print(Fore.RED + "   No open ports found or Nmap not installed.")
    else:
        for port, service in open_ports:
            print(f"   {Fore.CYAN}{port} → {Fore.WHITE}{service}")

    print_header("🧠 Technologies Detected (Wappalyzer)")
    print(run_wappalyzer(target))

    print_header("🌐 Hosting & Network Info")
    hostinfo = get_hosting_info(urlparse(target).hostname)
    for k, v in hostinfo.items():
        print(f"{Fore.CYAN}{k}: {Fore.WHITE}{v}")

    print_header("📞 Contact Info From Site")
    contact = extract_contact_info(target)
    if not any([contact["Emails"], contact["Phones"], contact["Addresses"]]):
        print(Fore.YELLOW + "No contact info found on site.")
    else:
        if contact["Emails"]:
            print(f"{Fore.GREEN}Emails: {Fore.WHITE}{', '.join(contact['Emails'])}")
        if contact["Phones"]:
            print(f"{Fore.GREEN}Phones: {Fore.WHITE}{', '.join(contact['Phones'])}")
        if contact["Addresses"]:
            print(f"{Fore.GREEN}Addresses: {Fore.WHITE}{'; '.join(contact['Addresses'])}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 thunder_web_checker.py <target_url>")
        sys.exit(1)
    scan(sys.argv[1])
