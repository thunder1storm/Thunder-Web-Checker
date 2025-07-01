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
import random
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from datetime import datetime
from fpdf import FPDF
import os

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

USER_AGENT = 'Mozilla/5.0 (WebSecurityScanner/1.0 ThunderWebChecker-AI)'
DEFAULT_HEADERS = {
    'User-Agent': USER_AGENT
}

RISK_LEVELS = {
    "low": "🟢 Low",
    "medium": "🟡 Medium",
    "high": "🔴 High"
}

AI_TIPS_GENERAL = [
    "Consider enabling HTTP security headers like X-XSS-Protection.",
    "Check if outdated JS libraries like jQuery are used.",
    "If no WAF is detected, consider deploying ModSecurity.",
    "Look for exposed .git or .env files on directory scan.",
    "Subdomain enumeration may reveal staging servers.",
    "Use Content-Security-Policy headers to mitigate XSS and clickjacking.",
    "Implement rate limiting and CAPTCHA on login forms.",
    "Avoid direct IP access to prevent virtual host bypass.",
    "Keep server software and dependencies up to date to avoid vulnerabilities."
]

report_json = []
pdf = FPDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()
pdf.set_font("Arial", size=14)
pdf.cell(0, 10, "Thunder Web Checker AI Security Report", ln=True, align='C')
pdf.set_font("Arial", size=11)
pdf.ln(10)

def add_result(title, risk, summary):
    entry = {
        "title": title,
        "risk_level": RISK_LEVELS[risk],
        "summary": summary
    }
    report_json.append(entry)
    pdf.set_text_color(0, 0, 128)  # Dark Blue
    pdf.cell(0, 10, f"{title} - {RISK_LEVELS[risk]}", ln=True)
    pdf.set_text_color(0, 0, 0)  # Black
    pdf.multi_cell(0, 10, summary)
    print(Fore.CYAN + f"[AI Risk] {title} → {RISK_LEVELS[risk]}")
    print(Fore.WHITE + f"         Summary: {summary}\n")

def ai_score_and_tip(issue_found):
    # Return risk level and a random tip based on issue presence
    if issue_found:
        risk = random.choices(["medium", "high"], weights=[40, 60])[0]
    else:
        risk = "low"
    tip = random.choice(AI_TIPS_GENERAL)
    return risk, tip

def export_report(json_only=False, pdf_only=False):
    if not pdf_only:
        with open("thunder_report.json", "w") as f:
            json.dump(report_json, f, indent=2)
        print(Fore.YELLOW + "[✓] JSON report saved to thunder_report.json")
    if not json_only:
        pdf.output("thunder_report.pdf")
        print(Fore.YELLOW + "[✓] PDF report saved to thunder_report.pdf")

def print_banner():
    print(Fore.GREEN + BANNER)

def get_hosting_details(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=isp,org,country,regionName,city,as,query", timeout=8)
        data = response.json()
        cloud_providers = ['amazon', 'google', 'azure', 'cloudflare']
        cloud = any(cloud in data.get('org', '').lower() for cloud in cloud_providers)
        return {
            'isp': data.get('isp', 'Unknown'),
            'org': data.get('org', 'Unknown'),
            'location': f"{data.get('city')}, {data.get('regionName')}, {data.get('country')}",
            'asn': data.get('as', 'Unknown'),
            'cloud': cloud
        }
    except Exception:
        return {
            'isp': 'Unknown', 'org': 'Unknown', 'location': 'Unknown', 'asn': 'Unknown', 'cloud': False
        }

def scan_summary(domain, ip, hosting):
    summary = (
        f"Domain: {domain}\n"
        f"Resolved IP: {ip}\n"
        f"Location: {hosting['location']}\n"
        f"Cloud Hosted: {'Yes (' + hosting['org'] + ')' if hosting['cloud'] else 'No'}\n"
        f"Organization: {hosting['org']}\n"
        f"ISP: {hosting['isp']}\n"
        f"ASN: {hosting['asn']}"
    )
    print(Fore.YELLOW + "\n[Scan Summary]")
    print(Fore.CYAN + summary)
    add_result("Scan Summary", "low", summary)

def run_service_scan(host):
    print(Fore.CYAN + "\n[+] Service and Version Detection (nmap)")
    try:
        result = subprocess.check_output(["nmap", "-sV", "--version-light", host], stderr=subprocess.DEVNULL).decode()
        print(Fore.GREEN + result)
        outdated = False
        # Detect outdated based on dummy heuristic (could be improved)
        matches = re.findall(r"(\d+/tcp).*?open.*?([\w\-]+)\s+([\d\.]+)", result)
        for port, service, version in matches:
            # Simple outdated version check example for demonstration:
            if service.lower() == "apache" and version.startswith("2.2"):
                outdated = True
                print(Fore.RED + f"[!] Outdated service detected: {service} {version} on {port}")
        risk, tip = ai_score_and_tip(outdated)
        summary = "Outdated services detected." if outdated else "No obviously outdated versions detected."
        summary += f"\nAI Tip: {tip}"
        add_result("Service Scan", risk, summary)
    except Exception as e:
        print(Fore.RED + f"[-] Service scan failed: {e}")
        add_result("Service Scan", "high", f"Failed to run nmap scan: {e}")

def run_whatweb_scan(target):
    print(Fore.CYAN + "\n[+] Running WhatWeb Technology Detection")
    try:
        result = subprocess.check_output(["whatweb", "--no-color", "--log-json=-", target], stderr=subprocess.DEVNULL)
        lines = result.decode().strip().split('\n')
        if not lines:
            raise Exception("WhatWeb returned no data")
        data = json.loads(lines[0])
        plugins = data.get('plugins', [])
        if plugins:
            techs = [f"{p.get('name', '')} {p.get('version', '')}".strip() for p in plugins]
            print(Fore.GREEN + f"[✓] Technologies detected ({len(techs)}):")
            for tech in techs:
                print(" -", tech)
            summary = "Technologies detected:\n" + "\n".join(techs)
            add_result("Technology Fingerprint", "low", summary)
        else:
            print(Fore.YELLOW + "[!] No technologies detected by WhatWeb.")
            add_result("Technology Fingerprint", "medium", "No technologies detected by WhatWeb.")
    except FileNotFoundError:
        print(Fore.RED + "[-] WhatWeb not found. Skipping technology detection.")
        add_result("Technology Fingerprint", "medium", "WhatWeb tool not installed.")
    except Exception as e:
        print(Fore.RED + f"[-] WhatWeb scan failed: {e}")
        add_result("Technology Fingerprint", "high", f"WhatWeb scan failed: {e}")

def check_waf(target):
    print(Fore.CYAN + "\n[+] Checking WAF Detection (wafw00f)")
    try:
        result = subprocess.check_output(["wafw00f", target], stderr=subprocess.DEVNULL).decode()
        detected = False
        waf_name = None
        for line in result.splitlines():
            if " is " in line and "waf" in line.lower():
                detected = True
                waf_name = line.split(" is ")[-1].strip()
                break
        if detected:
            print(Fore.GREEN + f"[✓] WAF Detected: {waf_name}")
            add_result("WAF Detection", "medium", f"WAF Detected: {waf_name}")
        else:
            print(Fore.YELLOW + "[!] No WAF detected.")
            add_result("WAF Detection", "low", "No WAF detected.")
    except FileNotFoundError:
        print(Fore.RED + "[-] wafw00f not found. Skipping WAF detection.")
        add_result("WAF Detection", "medium", "wafw00f not installed.")
    except Exception as e:
        print(Fore.RED + f"[-] WAF detection failed: {e}")
        add_result("WAF Detection", "high", f"WAF detection failed: {e}")

def check_clickjacking_protection(target):
    print(Fore.CYAN + "\n[+] Checking Clickjacking Protection")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        xfo = response.headers.get("X-Frame-Options", "")
        csp = response.headers.get("Content-Security-Policy", "")
        protected = False
        if "DENY" in xfo.upper() or "SAMEORIGIN" in xfo.upper():
            protected = True
            print(Fore.GREEN + f"[✓] X-Frame-Options set: {xfo}")
        elif "frame-ancestors" in csp.lower():
            protected = True
            print(Fore.GREEN + f"[✓] CSP frame-ancestors directive set")
        else:
            print(Fore.RED + "[✗] Clickjacking protection NOT detected!")
        risk, tip = ai_score_and_tip(not protected)
        summary = f"X-Frame-Options: {xfo}\nContent-Security-Policy: {csp}\nAI Tip: {tip}"
        add_result("Clickjacking Protection", risk, summary)
    except Exception as e:
        print(Fore.RED + f"[-] Clickjacking check failed: {e}")
        add_result("Clickjacking Protection", "high", f"Failed to check: {e}")

def check_hsts_header(target):
    print(Fore.CYAN + "\n[+] Checking HSTS Header")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
        hsts = response.headers.get("Strict-Transport-Security", "")
        if hsts:
            print(Fore.GREEN + f"[✓] HSTS header set: {hsts}")
            risk = "low"
        else:
            print(Fore.RED + "[✗] HSTS header NOT found!")
            risk = "medium"
        tip = "Consider adding 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
        summary = f"Strict-Transport-Security: {hsts if hsts else 'Not set'}\nAI Tip: {tip}"
        add_result("HSTS Header", risk, summary)
    except Exception as e:
        print(Fore.RED + f"[-] HSTS check failed: {e}")
        add_result("HSTS Header", "high", f"Failed to check: {e}")

def check_csrf_token(target):
    print(Fore.CYAN + "\n[+] Checking for CSRF Token in Forms")
    try:
        res = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            print(Fore.YELLOW + "[-] No forms found on page.")
            add_result("CSRF Token", "medium", "No forms found to check CSRF tokens.")
            return
        found_token = False
        validation_success = False
        for form in forms:
            inputs = form.find_all("input")
            for i in inputs:
                name = i.get("name", "").lower()
                if "csrf" in name or "token" in name:
                    found_token = True
                    print(Fore.GREEN + f"[✓] CSRF token found in form field: {i.get('name')}")
                    # Test validation with dummy POST (simplified)
                    action = form.get("action") or target
                    method = form.get("method", "get").lower()
                    url = urlparse(action).netloc and action or urlparse(target)._replace(path=action).geturl()
                    payload = {i.get("name"): "testtoken"}
                    try:
                        if method == "post":
                            test_res = requests.post(url, data=payload, headers=DEFAULT_HEADERS, timeout=10)
                        else:
                            test_res = requests.get(url, params=payload, headers=DEFAULT_HEADERS, timeout=10)
                        if test_res.status_code in [400, 403]:
                            validation_success = True
                            print(Fore.GREEN + "[✓] Server appears to validate CSRF tokens (blocked test request).")
                        else:
                            print(Fore.RED + "[✗] CSRF token might not be validated properly.")
                    except Exception:
                        print(Fore.YELLOW + "[!] Could not fully validate CSRF token via test request.")
                    break
            if found_token:
                break
        if not found_token:
            print(Fore.RED + "[✗] No CSRF tokens found in forms!")
            add_result("CSRF Token", "high", "No CSRF tokens detected in any form.")
        else:
            risk, tip = ai_score_and_tip(not validation_success)
            summary = f"CSRF token found: {found_token}\nValidation effective: {validation_success}\nAI Tip: {tip}"
            add_result("CSRF Token", risk, summary)
    except Exception as e:
        print(Fore.RED + f"[-] CSRF check failed: {e}")
        add_result("CSRF Token", "high", f"Failed to check: {e}")

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
            print(Fore.YELLOW + f"[!] Web page loads via direct IP: {test_url}")
            risk = "high"
            summary = f"Direct IP access allowed, status code: {response.status_code}\n" \
                      f"Possible virtual host bypass or misconfiguration."
        else:
            print(Fore.GREEN + f"[✓] Direct IP access blocked, status code: {response.status_code}")
            risk = "low"
            summary = f"Direct IP access blocked with status code: {response.status_code}"
        add_result("Direct IP Access", risk, summary)
    except requests.exceptions.SSLError:
        print(Fore.RED + "[✗] SSL Certificate mismatch on direct IP access (expected).")
        add_result("Direct IP Access", "low", "SSL Certificate mismatch on direct IP access (expected).")
    except Exception as e:
        print(Fore.GREEN + f"[✓] Direct IP access test failed or blocked: {e}")
        add_result("Direct IP Access", "low", f"Direct IP access test failed or blocked: {e}")

def run_nuclei_scan(target):
    print(Fore.CYAN + "\n[+] Running Nuclei Vulnerability Scan")
    try:
        result = subprocess.check_output(["nuclei", "-silent", "-json", "-u", target], stderr=subprocess.DEVNULL).decode()
        vulns = []
        for line in result.splitlines():
            data = json.loads(line)
            vulns.append({
                "name": data.get("info", {}).get("name", "Unknown"),
                "severity": data.get("info", {}).get("severity", "unknown"),
                "cve": data.get("info", {}).get("cve", "N/A"),
                "description": data.get("info", {}).get("description", "")
            })
        if vulns:
            print(Fore.RED + f"[!] Vulnerabilities detected by Nuclei: {len(vulns)}")
            for v in vulns:
                print(f" - {v['name']} (Severity: {v['severity']}, CVE: {v['cve']})")
            summary = "Vulnerabilities:\n" + "\n".join([f"{v['name']} ({v['severity']}, CVE: {v['cve']})" for v in vulns])
            add_result("Nuclei CVE Scan", "high", summary)
        else:
            print(Fore.GREEN + "[✓] No vulnerabilities detected by Nuclei.")
            add_result("Nuclei CVE Scan", "low", "No vulnerabilities detected by Nuclei.")
    except FileNotFoundError:
        print(Fore.RED + "[-] Nuclei not found. Skipping vulnerability scan.")
        add_result("Nuclei CVE Scan", "medium", "Nuclei tool not installed.")
    except Exception as e:
        print(Fore.RED + f"[-] Nuclei scan failed: {e}")
        add_result("Nuclei CVE Scan", "high", f"Nuclei scan failed: {e}")

def run_hydra_bruteforce(target, login_url, usernames_file, passwords_file):
    print(Fore.CYAN + "\n[+] Running Hydra Login Brute-force Test")
    if not (os.path.exists(usernames_file) and os.path.exists(passwords_file)):
        print(Fore.RED + "[-] Username or password file missing, skipping brute-force.")
        add_result("Login Brute-force", "medium", "Username or password file missing.")
        return
    try:
        # Hydra CLI example: hydra -L users.txt -P pass.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"
        # We'll keep it simple here: assume standard post form with 'user' and 'pass' fields and 'incorrect' in fail message
        cmd = [
            "hydra", "-L", usernames_file, "-P", passwords_file, target,
            "http-post-form", f"{login_url}:user=^USER^&pass=^PASS^:F=incorrect"
        ]
        print(Fore.YELLOW + "Running Hydra command, this may take some time...")
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        if "login:" in output or "password:" in output:
            print(Fore.GREEN + "[✓] No valid login found during brute-force.")
            add_result("Login Brute-force", "low", "No successful brute-force login found.")
        else:
            print(Fore.RED + "[!] Possible successful login detected!")
            add_result("Login Brute-force", "high", "Potential successful login detected during brute-force.")
    except FileNotFoundError:
        print(Fore.RED + "[-] Hydra tool not found. Skipping brute-force test.")
        add_result("Login Brute-force", "medium", "Hydra tool not installed.")
    except Exception as e:
        print(Fore.RED + f"[-] Hydra brute-force failed: {e}")
        add_result("Login Brute-force", "high", f"Hydra brute-force failed: {e}")

def run_gobuster_dir_bruteforce(target, wordlist):
    print(Fore.CYAN + "\n[+] Running Directory Bruteforce (Gobuster)")
    if not os.path.exists(wordlist):
        print(Fore.RED + "[-] Wordlist file missing, skipping directory bruteforce.")
        add_result("Directory Bruteforce", "medium", "Directory wordlist missing.")
        return
    try:
        cmd = [
            "gobuster", "dir", "-u", target, "-w", wordlist, "-q"
        ]
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        dirs_found = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                path = parts[0]
                status = parts[-1]
                dirs_found.append({"path": path, "status": status})
        if dirs_found:
            print(Fore.GREEN + f"[✓] Found {len(dirs_found)} directories:")
            for d in dirs_found[:10]:  # show first 10
                print(f" - {d['path']} ({d['status']})")
            summary = "Directories found:\n" + "\n".join([f"{d['path']} ({d['status']})" for d in dirs_found])
            add_result("Directory Bruteforce", "medium", summary)
        else:
            print(Fore.YELLOW + "[!] No directories found.")
            add_result("Directory Bruteforce", "low", "No directories found during brute-force.")
    except FileNotFoundError:
        print(Fore.RED + "[-] Gobuster tool not found. Skipping directory bruteforce.")
        add_result("Directory Bruteforce", "medium", "Gobuster tool not installed.")
    except Exception as e:
        print(Fore.RED + f"[-] Gobuster bruteforce failed: {e}")
        add_result("Directory Bruteforce", "high", f"Gobuster bruteforce failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Thunder Web Checker AI-enhanced pentest tool")
    parser.add_argument("target", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--json-only", action="store_true", help="Only output JSON report")
    parser.add_argument("--pdf-only", action="store_true", help="Only output PDF report")
    parser.add_argument("--login-url", help="Login page URL for brute-force test (e.g. /login)")
    parser.add_argument("--usernames", default="usernames.txt", help="Username file for brute-force")
    parser.add_argument("--passwords", default="passwords.txt", help="Password file for brute-force")
    parser.add_argument("--dir-wordlist", default="common_dirs.txt", help="Wordlist for directory brute-force")
    args = parser.parse_args()

    print_banner()

    # Parse target
    target = args.target.rstrip("/")
    parsed = urlparse(target)
    domain = parsed.hostname
    scheme = parsed.scheme or "http"
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        print(Fore.RED + f"Failed to resolve {domain}: {e}")
        sys.exit(1)

    # Hosting info
    hosting = get_hosting_details(ip)
    scan_summary(domain, ip, hosting)

    # Run modules
    run_service_scan(ip)
    run_whatweb_scan(target)
    check_waf(target)
    check_clickjacking_protection(target)
    check_hsts_header(target)
    check_csrf_token(target)
    check_ip_direct_access(target)
    run_nuclei_scan(target)

    if args.login_url:
        run_hydra_bruteforce(domain, args.login_url, args.usernames, args.passwords)
    else:
        print(Fore.YELLOW + "[!] Login brute-force skipped (no login URL provided).")

    if args.dir_wordlist:
        run_gobuster_dir_bruteforce(target, args.dir_wordlist)
    else:
        print(Fore.YELLOW + "[!] Directory bruteforce skipped (no wordlist provided).")

    # AI Summary tips
    print(Fore.MAGENTA + "\n[AI Summary] Final Recommendations:")
    for tip in random.sample(AI_TIPS_GENERAL, 4):
        print(Fore.MAGENTA + f"  • {tip}")
        pdf.multi_cell(0, 10, f"[AI Final Tip] {tip}")

    export_report(json_only=args.json_only, pdf_only=args.pdf_only)

if __name__ == "__main__":
    main()
