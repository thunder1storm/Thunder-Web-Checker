#!/usr/bin/env python3

import subprocess
import requests
import socket
import ssl
import sys
import re
import json
import argparse
import urllib3
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
··································································
:    ____  _  _  _  _  _  _  ___  ___  ___     _    _  ___  ___  :
:   (_  _)( )( )( )( )( \( )(   \(  _)(  ,)   ( \/\/ )(  _)(  ,) :
:     )(   )__(  )()(  )  (  ) ) )) _) )  \    \    /  ) _) ) ,\ :
:    (__) (_)(_) \__/ (_)\_)(___/(___)(_)\_)    \/\/  (___)(___/ :
:   __  _  _  ___   __  _ _   ___  ___                           :
:  / _)( )( )(  _) / _)( ) ) (  _)(  ,)                          :
: ( (_  )__(  ) _)( (_  )  \  ) _) )  \                          :
:  \__)(_)(_)(___) \__)(_)\_)(___)(_)\_)                         :
··································································
"""

USER_AGENT = 'Mozilla/5.0 (WebSecurityScanner/1.0 ThunderWebChecker)'
DEFAULT_HEADERS = {
    'User-Agent': USER_AGENT
}

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

def run_service_scan(host):
    print(Fore.CYAN + "\n[+] Service and Version Detection (nmap)")
    print(Fore.YELLOW + f"Running: nmap -sV --version-light {host}\n")
    try:
        result = subprocess.check_output(["nmap", "-sV", "--version-light", host], stderr=subprocess.DEVNULL).decode()
        print(Fore.GREEN + result)
        # Basic outdated version detection: (improve this with CVE mapping if needed)
        outdated = re.findall(r"(\d+/tcp).*?open.*?([\w-]+)\s+(\d+[\.\d+]*)", result)
        if outdated:
            print(Fore.RED + "[!] Possible outdated services detected:")
            for port, service, version in outdated:
                print(Fore.RED + f"    {port} → {service} {version}")
        else:
            print(Fore.GREEN + "[+] No obviously outdated versions detected.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to scan services: {e}")

def scan_summary(domain, ip, hosting):
    print(Fore.YELLOW + "\n] Scan Summary")
    print(Fore.CYAN + f"🔍 Domain: {domain}")
    print(Fore.CYAN + f"📡 Resolved IP: {ip}")
    print(Fore.CYAN + f"🌍 Location: {hosting['location']}")
    print(Fore.CYAN + f"☁ Hosted in Cloud: {'Yes (' + hosting['org'] + ')' if hosting['cloud'] else 'No'}")
    print(Fore.CYAN + f"🏢 Hosting Org: {hosting['org']}")
    print(Fore.CYAN + f"🛰️ ISP: {hosting['isp']}")
    print(Fore.CYAN + f"🔗 ASN: {hosting['asn']}")

def check_clickjacking_protection(target):
    print(Fore.CYAN + "\n[+] Checking Clickjacking Protection (X-Frame-Options / CSP)")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        xfo = response.headers.get("X-Frame-Options", "")
        csp = response.headers.get("Content-Security-Policy", "")

        if "DENY" in xfo.upper() or "SAMEORIGIN" in xfo.upper():
            print(Fore.GREEN + f"[✓] X-Frame-Options is set properly: {xfo}")
        elif "frame-ancestors" in csp.lower():
            print(Fore.GREEN + f"[✓] Content-Security-Policy frame-ancestors directive found: {csp}")
        else:
            print(Fore.RED + "[✗] Clickjacking protection NOT detected!")
            print(Fore.YELLOW + "    ➤ Consider setting 'X-Frame-Options: DENY' or using 'frame-ancestors' in CSP.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check Clickjacking protection: {e}")

def check_hsts_header(target):
    print(Fore.CYAN + "\n[+] Checking Strict-Transport-Security (HSTS) Header")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
        hsts = response.headers.get("Strict-Transport-Security", "")
        if hsts:
            print(Fore.GREEN + f"[✓] Strict-Transport-Security is set: {hsts}")
        else:
            print(Fore.RED + "[✗] HSTS header NOT found!")
            print(Fore.YELLOW + "    ➤ Consider adding 'Strict-Transport-Security: max-age=31536000; includeSubDomains'")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check HSTS header: {e}")

def check_csrf_token(target):
    print(Fore.CYAN + "\n[+] Checking for CSRF Token in Forms")
    try:
        res = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            print(Fore.YELLOW + "[-] No forms found to check CSRF tokens.")
            return

        found_token = False
        for form in forms:
            inputs = form.find_all("input")
            for i in inputs:
                name = i.get("name", "").lower()
                if "csrf" in name or "token" in name:
                    found_token = True
                    print(Fore.GREEN + f"[✓] CSRF token field found in form: {i.get('name')}")
                    action = form.get("action") or target
                    method = form.get("method", "get").lower()
                    url = urlparse(action).netloc and action or urlparse(target)._replace(path=action).geturl()
                    payload = {i.get("name"): "test_token_value"}
                    dummy_post = requests.post(url, data=payload, headers=DEFAULT_HEADERS, timeout=10)
                    if dummy_post.status_code in [403, 400]:
                        print(Fore.GREEN + "[✓] Server appears to validate CSRF token (test request blocked).")
                    else:
                        print(Fore.RED + "[✗] CSRF token might not be validated (response not blocked).")
                    break
            if found_token:
                break

        if not found_token:
            print(Fore.RED + "[✗] No CSRF token fields found in forms!")
            print(Fore.YELLOW + "    ➤ Consider adding anti-CSRF tokens to all sensitive forms.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check CSRF token: {e}")

def check_ip_direct_access(target):
    print(Fore.CYAN + "\n[+] Checking Direct IP Access to Web Page")
    try:
        parsed = urlparse(target)
        domain = parsed.hostname
        scheme = parsed.scheme or "http"
        ip = socket.gethostbyname(domain)

        test_url = f"{scheme}://{ip}"
        headers_ip = DEFAULT_HEADERS.copy()
        headers_ip["Host"] = domain

        response = requests.get(test_url, headers=headers_ip, timeout=10, verify=False, allow_redirects=False)

        if response.status_code in [200, 301, 302]:
            print(Fore.YELLOW + f"[!] Web page loads via IP: {test_url}")
            print(Fore.YELLOW + "    ➤ Possible virtual host misconfiguration or Cloud bypass risk.")
        else:
            print(Fore.GREEN + f"[✓] Server blocked direct IP access (status {response.status_code}).")
    except requests.exceptions.SSLError:
        print(Fore.RED + "[✗] SSL Certificate mismatch on direct IP access (as expected).")
    except Exception as e:
        print(Fore.GREEN + f"[✓] Direct IP access blocked or not responding: {e}")

def main():
    parser = argparse.ArgumentParser(description="Thunder Web Checker - Web Security Recon Tool")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    args = parser.parse_args()

    target = args.target
    print(BANNER)

    try:
        parsed_url = urlparse(target)
        if not parsed_url.scheme:
            target = "http://" + target
            parsed_url = urlparse(target)

        domain = parsed_url.hostname
        ip = socket.gethostbyname(domain)

        hosting_info = get_hosting_details(ip)
        scan_summary(domain, ip, hosting_info)
        run_service_scan(domain)
        check_clickjacking_protection(target)
        check_hsts_header(target)
        check_csrf_token(target)
        check_ip_direct_access(target)

    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")

if __name__ == "__main__":
    main()
