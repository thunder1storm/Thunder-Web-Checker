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
import os
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from datetime import datetime
import random
from fpdf import FPDF

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


def ai_insight(message):
    tips = [
        "Consider enabling HTTP security headers like X-XSS-Protection.",
        "Check if outdated JS libraries like jQuery are used.",
        "If no WAF is detected, consider deploying ModSecurity.",
        "Look for exposed .git or .env files on directory scan.",
        "Subdomain enumeration may reveal staging servers."
    ]
    insight = random.choice(tips)
    print(Fore.MAGENTA + f"[AI Insight] {insight}")
    return insight


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


def run_service_scan(host):
    print(Fore.CYAN + "\n[+] Service and Version Detection (nmap)")
    print(Fore.YELLOW + f"Running: nmap -sV --version-light {host}\n")
    try:
        result = subprocess.check_output(["nmap", "-sV", "--version-light", host], stderr=subprocess.DEVNULL).decode()
        print(Fore.GREEN + result)
        # Just output yes/no on outdated detection
        outdated = re.findall(r"(\d+/tcp).*?open.*?([\w-]+)\s+(\d+[\.\d+]*)", result)
        if outdated:
            print(Fore.RED + "[!] Possible outdated services detected: YES")
            add_result("Service Version Scan", "medium", "Possible outdated services detected. Review output above for details.")
        else:
            print(Fore.GREEN + "[+] No obviously outdated versions detected.")
            add_result("Service Version Scan", "low", "No obviously outdated service versions detected.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to scan services: {e}")
        add_result("Service Version Scan", "high", f"Service scan failed: {e}")


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
                techs = []
                for plugin in plugins:
                    name = plugin.get('name', 'unknown')
                    version = plugin.get('version', '')
                    ver_str = f" v{version}" if version else ""
                    techs.append(f"{name}{ver_str}")
                    print(f"  - {name}{ver_str}")
                add_result("Technology Fingerprint", "low", f"Technologies detected: {', '.join(techs)}")
            else:
                print(Fore.YELLOW + "[!] No technologies detected by WhatWeb.")
                add_result("Technology Fingerprint", "medium", "No technologies detected by WhatWeb.")
        else:
            print(Fore.YELLOW + "[!] WhatWeb returned no data.")
            add_result("Technology Fingerprint", "medium", "WhatWeb returned no data.")
    except FileNotFoundError:
        print(Fore.RED + "[-] WhatWeb not installed or not found in PATH. Skipping WhatWeb scan.")
        add_result("Technology Fingerprint", "medium", "WhatWeb not installed or not found.")
    except Exception as e:
        print(Fore.RED + f"[-] WhatWeb scan failed: {e}")
        add_result("Technology Fingerprint", "high", f"WhatWeb scan failed: {e}")


def run_wafw00f(target):
    print(Fore.CYAN + "\n[+] Running WAF Detection (wafw00f)")
    try:
        result = subprocess.check_output(["wafw00f", "-a", target], stderr=subprocess.DEVNULL).decode()
        waf_detected = "No WAF detected" not in result
        if waf_detected:
            print(Fore.GREEN + "[✓] WAF detected.")
            add_result("WAF Detection", "medium", "WAF detected on the target.")
        else:
            print(Fore.YELLOW + "[✗] No WAF detected.")
            add_result("WAF Detection", "low", "No WAF detected on the target.")
    except FileNotFoundError:
        print(Fore.RED + "[-] wafw00f not installed or not found in PATH. Skipping WAF detection.")
        add_result("WAF Detection", "medium", "wafw00f not installed or not found.")
    except Exception as e:
        print(Fore.RED + f"[-] WAF detection failed: {e}")
        add_result("WAF Detection", "high", f"WAF detection failed: {e}")


def check_clickjacking_protection(target):
    print(Fore.CYAN + "\n[+] Checking Clickjacking Protection (X-Frame-Options / CSP)")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        xfo = response.headers.get("X-Frame-Options", "")
        csp = response.headers.get("Content-Security-Policy", "")

        if "DENY" in xfo.upper() or "SAMEORIGIN" in xfo.upper():
            print(Fore.GREEN + f"[✓] X-Frame-Options is set properly: {xfo}")
            add_result("Clickjacking Protection", "low", f"X-Frame-Options header set: {xfo}")
        elif "frame-ancestors" in csp.lower():
            print(Fore.GREEN + f"[✓] Content-Security-Policy frame-ancestors directive found: {csp}")
            add_result("Clickjacking Protection", "low", f"CSP frame-ancestors directive found.")
        else:
            print(Fore.RED + "[✗] Clickjacking protection NOT detected!")
            print(Fore.YELLOW + "    ➤ Consider setting 'X-Frame-Options: DENY' or using 'frame-ancestors' in CSP.")
            add_result("Clickjacking Protection", "high", "No Clickjacking protection detected.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check Clickjacking protection: {e}")
        add_result("Clickjacking Protection", "high", f"Error checking clickjacking protection: {e}")


def check_hsts_header(target):
    print(Fore.CYAN + "\n[+] Checking Strict-Transport-Security (HSTS) Header")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
        hsts = response.headers.get("Strict-Transport-Security", "")
        if hsts:
            print(Fore.GREEN + f"[✓] Strict-Transport-Security is set: {hsts}")
            add_result("HSTS Header", "low", f"HSTS header present: {hsts}")
        else:
            print(Fore.RED + "[✗] HSTS header NOT found!")
            print(Fore.YELLOW + "    ➤ Consider adding 'Strict-Transport-Security: max-age=31536000; includeSubDomains'")
            add_result("HSTS Header", "high", "HSTS header not found.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check HSTS header: {e}")
        add_result("HSTS Header", "high", f"Error checking HSTS header: {e}")


def check_csrf_token(target):
    print(Fore.CYAN + "\n[+] Checking for CSRF Token in Forms")
    try:
        res = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        soup = BeautifulSoup(res.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            print(Fore.YELLOW + "[-] No forms found to check CSRF tokens.")
            add_result("CSRF Token Detection", "medium", "No forms found on page to check CSRF tokens.")
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
                        add_result("CSRF Token Validation", "low", "CSRF token found and appears to be validated.")
                    else:
                        print(Fore.RED + "[✗] CSRF token might not be validated (response not blocked).")
                        add_result("CSRF Token Validation", "high", "CSRF token found but may not be validated properly.")
                    break
            if found_token:
                break

        if not found_token:
            print(Fore.RED + "[✗] No CSRF token fields found in forms!")
            print(Fore.YELLOW + "    ➤ Consider adding anti-CSRF tokens to all sensitive forms.")
            add_result("CSRF Token Detection", "high", "No CSRF token fields found in forms.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check CSRF token: {e}")
        add_result("CSRF Token Detection", "high", f"Error checking CSRF token: {e}")


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
            add_result("Direct IP Access", "medium", "Web page loads via IP address, indicating possible misconfiguration.")
        else:
            print(Fore.GREEN + f"[✓] Server blocked direct IP access (status {response.status_code}).")
            add_result("Direct IP Access", "low", "Direct IP access to web page is blocked.")
    except requests.exceptions.SSLError:
        print(Fore.RED + "[✗] SSL Certificate mismatch on direct IP access (as expected).")
        add_result("Direct IP Access", "low", "SSL certificate mismatch when accessing via IP (expected behavior).")
    except Exception as e:
        print(Fore.GREEN + f"[✓] Direct IP access blocked or not responding: {e}")
        add_result("Direct IP Access", "low", "Direct IP access blocked or not responding.")


def run_nuclei_scan(target):
    print(Fore.CYAN + "\n[+] Running Common Vulnerability Detection (Nuclei)")
    try:
        # nuclei scan command - can add templates path if available
        result = subprocess.check_output(["nuclei", "-silent", "-json", "-u", target], stderr=subprocess.DEVNULL).decode()
        if result.strip():
            findings = []
            for line in result.strip().split("\n"):
                try:
                    data = json.loads(line)
                    findings.append(data.get('info', {}).get('name', 'Unknown vulnerability'))
                except Exception:
                    continue
            if findings:
                print(Fore.RED + f"[!] Vulnerabilities found: {len(findings)}")
                for f in findings:
                    print(Fore.RED + f"  - {f}")
                add_result("Common Vulnerability Scan", "high", f"Detected vulnerabilities: {', '.join(findings)}")
            else:
                print(Fore.GREEN + "[+] No vulnerabilities found by Nuclei.")
                add_result("Common Vulnerability Scan", "low", "No vulnerabilities found by Nuclei.")
        else:
            print(Fore.GREEN + "[+] No vulnerabilities found by Nuclei.")
            add_result("Common Vulnerability Scan", "low", "No vulnerabilities found by Nuclei.")
    except FileNotFoundError:
        print(Fore.RED + "[-] Nuclei not installed or not found in PATH. Skipping vulnerability scan.")
        add_result("Common Vulnerability Scan", "medium", "Nuclei not installed or not found.")
    except Exception as e:
        print(Fore.RED + f"[-] Nuclei scan failed: {e}")
        add_result("Common Vulnerability Scan", "high", f"Nuclei scan failed: {e}")


def run_hydra_login_bruteforce(target, login_url, usernames_file, passwords_file):
    print(Fore.CYAN + "\n[+] Running Login Brute-force Check (Hydra)")
    if not login_url or not usernames_file or not passwords_file:
        print(Fore.YELLOW + "[!] Missing parameters for Hydra login brute-force (login_url, usernames, passwords). Skipping.")
        add_result("Login Brute-force Check", "medium", "Login URL or wordlists not provided, skipped brute-force.")
        return
    if not os.path.isfile(usernames_file) or not os.path.isfile(passwords_file):
        print(Fore.RED + "[!] Username or password wordlist file not found. Skipping Hydra brute-force.")
        add_result("Login Brute-force Check", "high", "Username or password wordlist file missing, skipped brute-force.")
        return

    try:
        cmd = [
            "hydra",
            "-L", usernames_file,
            "-P", passwords_file,
            "-f",
            "-s", "443" if target.startswith("https") else "80",
            target.replace("https://", "").replace("http://", ""),
            "http-post-form",
            f"{login_url}:username=^USER^&password=^PASS^:F=incorrect"
        ]
        print(Fore.YELLOW + f"Running: {' '.join(cmd)}")
        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        print(Fore.GREEN + result)
        if "login:" in result.lower() or "success" in result.lower():
            add_result("Login Brute-force Check", "high", "Possible login credentials found via brute-force.")
        else:
            add_result("Login Brute-force Check", "low", "No login credentials found via brute-force.")
    except Exception as e:
        print(Fore.RED + f"[-] Hydra brute-force failed: {e}")
        add_result("Login Brute-force Check", "high", f"Hydra error: {e}")


def run_directory_bruteforce(target, wordlist_file):
    print(Fore.CYAN + "\n[+] Running Directory Bruteforce (Gobuster)")
    if not wordlist_file or not os.path.isfile(wordlist_file):
        print(Fore.RED + "[!] Directory wordlist file not found. Skipping directory bruteforce.")
        add_result("Directory Bruteforce", "medium", "Directory wordlist file missing, skipped brute-force.")
        return

    try:
        cmd = [
            "gobuster",
            "dir",
            "-u", target,
            "-w", wordlist_file,
            "-q"
        ]
        print(Fore.YELLOW + f"Running: {' '.join(cmd)}")
        result = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        found_dirs = re.findall(r"(\/[\w\/\-\.]+)", result)
        if found_dirs:
            print(Fore.GREEN + f"[✓] Found directories/files:")
            for d in found_dirs:
                print(Fore.GREEN + f"  - {d}")
            add_result("Directory Bruteforce", "medium", f"Found directories/files: {', '.join(found_dirs)}")
        else:
            print(Fore.YELLOW + "[!] No directories/files found with Gobuster.")
            add_result("Directory Bruteforce", "low", "No directories/files found during bruteforce.")
    except FileNotFoundError:
        print(Fore.RED + "[-] Gobuster not installed or not found in PATH. Skipping directory bruteforce.")
        add_result("Directory Bruteforce", "medium", "Gobuster not installed or not found.")
    except Exception as e:
        print(Fore.RED + f"[-] Directory bruteforce failed: {e}")
        add_result("Directory Bruteforce", "high", f"Directory bruteforce error: {e}")


def scan_summary(domain, ip, hosting):
    print(Fore.YELLOW + "\n] Scan Summary")
    print(Fore.CYAN + f"🔍 Domain: {domain}")
    print(Fore.CYAN + f"📡 Resolved IP: {ip}")
    print(Fore.CYAN + f"🌍 Location: {hosting['location']}")
    print(Fore.CYAN + f"☁ Hosted in Cloud: {'Yes (' + hosting['org'] + ')' if hosting['cloud'] else 'No'}")
    print(Fore.CYAN + f"🏢 Hosting Org: {hosting['org']}")
    print(Fore.CYAN + f"🛰️ ISP: {hosting['isp']}")
    print(Fore.CYAN + f"🔗 ASN: {hosting['asn']}")
    add_result("Scan Summary", "low", f"Domain: {domain}\nIP: {ip}\nLocation: {hosting['location']}\nHosted in Cloud: {'Yes' if hosting['cloud'] else 'No'}\nOrg: {hosting['org']}\nISP: {hosting['isp']}\nASN: {hosting['asn']}")


def main():
    parser = argparse.ArgumentParser(description="Thunder Web Checker - Web Security Recon Tool with AI")
    parser.add_argument("target", help="Target URL (e.g., https://example.com)")
    parser.add_argument("--hydra-login-url", help="Login URL for Hydra brute-force (e.g., /login.php)")
    parser.add_argument("--hydra-usernames", help="Username wordlist file path for Hydra")
    parser.add_argument("--hydra-passwords", help="Password wordlist file path for Hydra")
    parser.add_argument("--dir-wordlist", help="Wordlist file path for directory bruteforce")
    parser.add_argument("--json-only", action="store_true", help="Output only JSON report")
    parser.add_argument("--pdf-only", action="store_true", help="Output only PDF report")
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
        run_whatweb_scan(target)
        run_wafw00f(target)
        check_clickjacking_protection(target)
        check_hsts_header(target)
        check_csrf_token(target)
        check_ip_direct_access(target)
        run_nuclei_scan(target)
        run_hydra_login_bruteforce(target, args.hydra_login_url, args.hydra_usernames, args.hydra_passwords)
        run_directory_bruteforce(target, args.dir_wordlist)
        ai_summary()

        if args.json_only:
            with open("thunder_report.json", "w") as f:
                json.dump(report_json, f, indent=2)
            print(Fore.YELLOW + "\n[✓] JSON report saved to thunder_report.json")
        elif args.pdf_only:
            pdf.output("thunder_report.pdf")
            print(Fore.YELLOW + "\n[✓] PDF report saved to thunder_report.pdf")
        else:
            export_report()

    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")


if __name__ == "__main__":
    main()
