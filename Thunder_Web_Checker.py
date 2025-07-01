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
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from datetime import datetime
import random
from fpdf import FPDF
import os

# Initialize colorama
init(autoreset=True)

# Disable insecure request warnings for https with invalid certs (if any)
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

USER_AGENT = 'Mozilla/5.0 (WebSecurityScanner/1.0 ThunderWebChecker-AI)'
DEFAULT_HEADERS = {
    'User-Agent': USER_AGENT
}

# Risk levels for AI output
RISK_LEVELS = {
    "low": "🟢 Low",
    "medium": "🟡 Medium",
    "high": "🔴 High"
}

# Global containers for reports
report_json = []
pdf = FPDF()
pdf.add_page()
pdf.set_font("Arial", size=12)
pdf.cell(200, 10, txt="Thunder Web Checker AI Report", ln=True, align='C')

def add_result(title, risk, summary):
    entry = {
        "title": title,
        "risk_level": RISK_LEVELS[risk],
        "summary": summary
    }
    report_json.append(entry)
    pdf.cell(200, 10, txt=f"{title} - {RISK_LEVELS[risk]}", ln=True)
    pdf.multi_cell(0, 10, summary)
    print(Fore.CYAN + f"[AI Risk] {title} → {RISK_LEVELS[risk]}")
    print(Fore.WHITE + f"         Summary: {summary}\n")

def ai_insight():
    tips = [
        "Consider enabling HTTP security headers like X-XSS-Protection.",
        "Check if outdated JS libraries like jQuery are used.",
        "If no WAF is detected, consider deploying ModSecurity.",
        "Look for exposed .git or .env files on directory scan.",
        "Subdomain enumeration may reveal staging servers."
    ]
    return random.choice(tips)

def ai_summary():
    print(Fore.MAGENTA + "\n[AI Summary] Final Recommendations:")
    tips = random.sample([
        "Use Content-Security-Policy to mitigate XSS.",
        "Use a vulnerability scanner like Nikto or OpenVAS for deep scanning.",
        "Ensure login forms are protected with rate limiting and CAPTCHA.",
        "If direct IP access works, set up host validation in the backend.",
        "Store sensitive configs securely using environment variables."
    ], 3)
    for tip in tips:
        print(Fore.MAGENTA + f"  • {tip}")
        pdf.multi_cell(0, 10, f"[AI Final Tip] {tip}")

def export_report():
    with open("thunder_report.json", "w") as f:
        json.dump(report_json, f, indent=2)
    pdf.output("thunder_report.pdf")
    print(Fore.YELLOW + "\n[✓] JSON report saved to thunder_report.json")
    print(Fore.YELLOW + "[✓] PDF report saved to thunder_report.pdf")

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

def scan_summary(domain, ip, hosting):
    print(Fore.YELLOW + "\n] Scan Summary")
    print(Fore.CYAN + f"🔍 Domain: {domain}")
    print(Fore.CYAN + f"📡 Resolved IP: {ip}")
    print(Fore.CYAN + f"🌍 Location: {hosting['location']}")
    print(Fore.CYAN + f"☁ Hosted in Cloud: {'Yes (' + hosting['org'] + ')' if hosting['cloud'] else 'No'}")
    print(Fore.CYAN + f"🏢 Hosting Org: {hosting['org']}")
    print(Fore.CYAN + f"🛰️ ISP: {hosting['isp']}")
    print(Fore.CYAN + f"🔗 ASN: {hosting['asn']}")

def run_nmap_scan(host):
    print(Fore.CYAN + "\n[+] Service and Version Detection (nmap)")
    print(Fore.YELLOW + f"Running: nmap -sV --version-light {host}\n")
    try:
        result = subprocess.check_output(["nmap", "-sV", "--version-light", host], stderr=subprocess.DEVNULL).decode()
        print(Fore.GREEN + result)
        # Just show 'Yes' if outdated versions found, else No
        outdated_found = bool(re.search(r"(\d+\.\d+)", result))
        add_result("Nmap Service Scan", "medium" if outdated_found else "low",
                   "Outdated service versions detected." if outdated_found else "No outdated service versions detected.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to scan services: {e}")
        add_result("Nmap Service Scan", "high", f"Failed to run nmap: {e}")

def run_whatweb_scan(target):
    print(Fore.CYAN + "\n[+] Running WhatWeb Technology Detection")
    try:
        result = subprocess.check_output(["whatweb", "--no-color", "--log-json=-", target], stderr=subprocess.DEVNULL)
        lines = result.decode().strip().split('\n')
        if lines:
            data = json.loads(lines[0])
            plugins = data.get('plugins', [])
            if plugins:
                print(Fore.GREEN + f"[✓] Technologies detected ({len(plugins)}):")
                tech_list = []
                for plugin in plugins:
                    name = plugin.get('name', 'unknown')
                    version = plugin.get('version', '')
                    ver_str = f" v{version}" if version else ""
                    tech_list.append(f"{name}{ver_str}")
                    print(f"  - {name}{ver_str}")
                add_result("Technology Detection (WhatWeb)", "low",
                           f"Detected technologies: {', '.join(tech_list)}")
            else:
                print(Fore.YELLOW + "[!] No technologies detected by WhatWeb.")
                add_result("Technology Detection (WhatWeb)", "low", "No technologies detected.")
        else:
            print(Fore.YELLOW + "[!] WhatWeb returned no data.")
            add_result("Technology Detection (WhatWeb)", "medium", "No data returned by WhatWeb.")
    except FileNotFoundError:
        print(Fore.RED + "[-] WhatWeb not installed or not found in PATH. Skipping WhatWeb scan.")
        add_result("Technology Detection (WhatWeb)", "high", "WhatWeb not installed or not found.")
    except Exception as e:
        print(Fore.RED + f"[-] WhatWeb scan failed: {e}")
        add_result("Technology Detection (WhatWeb)", "high", f"Error: {e}")

def run_wafw00f_scan(target):
    print(Fore.CYAN + "\n[+] Running WAF Detection (wafw00f)")
    try:
        result = subprocess.check_output(["wafw00f", target], stderr=subprocess.DEVNULL)
        output = result.decode()
        # Simple detection
        waf_detected = "No WAF detected" not in output
        print(Fore.GREEN + (f"[✓] WAF detected:\n{output}" if waf_detected else "[✗] No WAF detected."))
        add_result("WAF Detection", "medium" if waf_detected else "low",
                   "WAF detected." if waf_detected else "No WAF detected.")
    except FileNotFoundError:
        print(Fore.RED + "[-] wafw00f not installed or not found. Skipping WAF scan.")
        add_result("WAF Detection", "high", "wafw00f not installed or not found.")
    except Exception as e:
        print(Fore.RED + f"[-] wafw00f scan failed: {e}")
        add_result("WAF Detection", "high", f"Error: {e}")

def check_clickjacking_protection(target):
    print(Fore.CYAN + "\n[+] Checking Clickjacking Protection (X-Frame-Options / CSP)")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        xfo = response.headers.get("X-Frame-Options", "")
        csp = response.headers.get("Content-Security-Policy", "")

        protected = False
        summary = ""
        if "DENY" in xfo.upper() or "SAMEORIGIN" in xfo.upper():
            protected = True
            summary = f"X-Frame-Options set properly: {xfo}"
        elif "frame-ancestors" in csp.lower():
            protected = True
            summary = f"Content-Security-Policy frame-ancestors directive found: {csp}"
        else:
            summary = "Clickjacking protection NOT detected."

        print(Fore.GREEN + f"[{'✓' if protected else '✗'}] {summary}")
        add_result("Clickjacking Protection", "low" if protected else "high", summary)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check Clickjacking protection: {e}")
        add_result("Clickjacking Protection", "high", f"Error: {e}")

def check_hsts_header(target):
    print(Fore.CYAN + "\n[+] Checking Strict-Transport-Security (HSTS) Header")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
        hsts = response.headers.get("Strict-Transport-Security", "")
        if hsts:
            print(Fore.GREEN + f"[✓] Strict-Transport-Security is set: {hsts}")
            add_result("HSTS Header", "low", f"Strict-Transport-Security header found: {hsts}")
        else:
            print(Fore.RED + "[✗] HSTS header NOT found!")
            add_result("HSTS Header", "high", "Strict-Transport-Security header NOT found!")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check HSTS header: {e}")
        add_result("HSTS Header", "high", f"Error: {e}")

def check_csrf_token(target):
    print(Fore.CYAN + "\n[+] Checking for CSRF Token in Forms")
    try:
        res = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            print(Fore.YELLOW + "[-] No forms found to check CSRF tokens.")
            add_result("CSRF Token Detection", "medium", "No forms found to check CSRF tokens.")
            return

        found_token = False
        validated = False

        for form in forms:
            inputs = form.find_all("input")
            for i in inputs:
                name = i.get("name", "").lower()
                if "csrf" in name or "token" in name:
                    found_token = True
                    print(Fore.GREEN + f"[✓] CSRF token field found in form: {i.get('name')}")
                    action = form.get("action") or target
                    method = form.get("method", "get").lower()
                    # Construct full URL if action is relative
                    if not urlparse(action).netloc:
                        action = urljoin(target, action)
                    # Send dummy post to test validation
                    payload = {i.get("name"): "test_token_value"}
                    dummy_post = requests.post(action, data=payload, headers=DEFAULT_HEADERS, timeout=10)
                    if dummy_post.status_code in [403, 400]:
                        validated = True
                        print(Fore.GREEN + "[✓] Server appears to validate CSRF token (test request blocked).")
                    else:
                        print(Fore.RED + "[✗] CSRF token might not be validated (response not blocked).")
                    break
            if found_token:
                break

        if not found_token:
            print(Fore.RED + "[✗] No CSRF token fields found in forms!")
            add_result("CSRF Token Detection", "high", "No CSRF token fields found in forms.")
        else:
            risk = "low" if validated else "medium"
            add_result("CSRF Token Detection", risk, "CSRF token found and validated." if validated else "CSRF token found but might not be validated.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check CSRF token: {e}")
        add_result("CSRF Token Detection", "high", f"Error: {e}")

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
            add_result("Direct IP Access", "high", "Web page loads directly via IP, possible misconfiguration.")
        else:
            print(Fore.GREEN + f"[✓] Server blocked direct IP access (status {response.status_code}).")
            add_result("Direct IP Access", "low", "Server blocks direct IP access.")
    except requests.exceptions.SSLError:
        print(Fore.RED + "[✗] SSL Certificate mismatch on direct IP access (as expected).")
        add_result("Direct IP Access", "low", "SSL Certificate mismatch on direct IP access (expected).")
    except Exception as e:
        print(Fore.GREEN + f"[✓] Direct IP access blocked or not responding: {e}")
        add_result("Direct IP Access", "low", "Direct IP access blocked or not responding.")

def run_nuclei_scan(target):
    print(Fore.CYAN + "\n[+] Running Nuclei Vulnerability Scan")
    try:
        result = subprocess.check_output(["nuclei", "-json", "-silent", "-u", target], stderr=subprocess.DEVNULL)
        findings = [json.loads(line) for line in result.decode().splitlines()]
        if findings:
            print(Fore.RED + f"[!] Nuclei found {len(findings)} potential vulnerabilities:")
            for f in findings:
                print(f"  - {f.get('info', {}).get('name', 'Unknown')} (Severity: {f.get('info', {}).get('severity', 'unknown')})")
            add_result("Nuclei Vulnerability Scan", "high",
                       f"Found {len(findings)} potential vulnerabilities via Nuclei scan.")
        else:
            print(Fore.GREEN + "[✓] No vulnerabilities found by Nuclei.")
            add_result("Nuclei Vulnerability Scan", "low", "No vulnerabilities found.")
    except FileNotFoundError:
        print(Fore.RED + "[-] nuclei not installed or not found. Skipping Nuclei scan.")
        add_result("Nuclei Vulnerability Scan", "high", "Nuclei not installed or not found.")
    except Exception as e:
        print(Fore.RED + f"[-] Nuclei scan failed: {e}")
        add_result("Nuclei Vulnerability Scan", "high", f"Error: {e}")

def run_hydra_login_bruteforce(target, login_url, usernames_file, passwords_file):
    print(Fore.CYAN + "\n[+] Running Login Brute-force Check (Hydra)")
    if not login_url or not usernames_file or not passwords_file:
        print(Fore.YELLOW + "[!] Missing parameters for Hydra login brute-force (login_url, usernames, passwords). Skipping.")
        add_result("Login Brute-force Check", "medium", "Login URL or wordlists not provided, skipped brute-force.")
        return
    if not os.path.isfile(usernames_file) or not os.path.isfile(passwords_file):
        print(Fore.RED + "[!] Username or password word
