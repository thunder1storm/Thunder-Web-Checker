#!/usr/bin/env python3
import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from fpdf import FPDF

init(autoreset=True)

BANNER = r"""
 .    _                        _                                  _     
_/_   /      ,   . , __     ___/   ___  .___       ,  _  /   ___  \ ___ 
 |    |,---. |   | |'  `.  /   | .'   ` /   \      |  |  | .'   ` |/   \
 |    |'   ` |   | |    | ,'   | |----' |   '      `  ^  ' |----' |    `
 \__/ /    | `._/| /    | `___,' `.___, /           \/ \/  `.___, `___,'
                               `                                        
       _                    \                                           
  ___  /        ___    ___  |   ,   ___  .___                           
.'   ` |,---. .'   ` .'   ` |  /  .'   ` /   \                          
|      |'   ` |----' |      |-<   |----' |   '                          
 `._.' /    | `.___,  `._.' /  \_ `.___, /                              
"""

DEFAULT_HEADERS = {
    "User-Agent": "ThunderWebCheckerAI/1.0 (+https://github.com/yourrepo)"
}

report_json = []
report_lock = threading.Lock()

def add_result(title, risk_level, summary):
    with report_lock:
        report_json.append({
            "title": title,
            "risk_level": risk_level,
            "summary": summary
        })

def run_command(cmd):
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
        return output
    except Exception as e:
        return f"Error running {' '.join(cmd)}: {e}"

def get_ip_and_hosting(domain):
    print(Fore.CYAN + "[+] Resolving IP and Hosting Info")
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"[✓] IP Address: {ip}")
    except Exception as e:
        print(Fore.RED + f"[-] Could not resolve IP: {e}")
        ip = None

    hosting_info = "Unknown"
    if ip:
        try:
            res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if res.status_code == 200:
                data = res.json()
                hosting_info = data.get("org", "Unknown")
                print(Fore.GREEN + f"[✓] Hosting Info: {hosting_info}")
            else:
                print(Fore.YELLOW + "[!] Could not fetch hosting info from ipinfo.io")
        except Exception as e:
            print(Fore.YELLOW + f"[!] Hosting info fetch error: {e}")
    add_result("IP and Hosting Info", "low", f"IP: {ip}, Hosting: {hosting_info}")
    return ip, hosting_info

def run_nmap_scan(domain):
    print(Fore.CYAN + "\n[+] Running Nmap Service and Version Scan")
    output = run_command(["nmap", "-sV", "-T4", domain])
    print(Fore.GREEN + output)
    add_result("Nmap Scan", "medium", output)

def run_whatweb_scan(target):
    print(Fore.CYAN + "\n[+] Running WhatWeb Scan")
    output = run_command(["whatweb", target])
    print(Fore.GREEN + output)
    add_result("WhatWeb Scan", "medium", output)

def run_wafw00f_scan(target):
    print(Fore.CYAN + "\n[+] Running WAFW00F Scan")
    output = run_command(["wafw00f", target])
    print(Fore.GREEN + output)
    add_result("WAF Detection", "medium", output)

def check_http_security_headers(target):
    print(Fore.CYAN + "\n[+] Checking HTTP Security Headers")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        headers = response.headers

        important_headers = {
            "X-Frame-Options": ["DENY", "SAMEORIGIN"],
            "Content-Security-Policy": None,
            "X-Content-Type-Options": ["nosniff"],
            "Referrer-Policy": ["no-referrer", "strict-origin-when-cross-origin", "same-origin"],
            "Permissions-Policy": None,
            "Expect-CT": None,
        }

        missing = []
        misconfigured = []

        for header, expected_values in important_headers.items():
            value = headers.get(header)
            if not value:
                missing.append(header)
            elif expected_values:
                if not any(ev.lower() in value.lower() for ev in expected_values):
                    misconfigured.append(f"{header} (value: {value})")

        if missing or misconfigured:
            msg = ""
            if missing:
                msg += f"Missing headers: {', '.join(missing)}. "
            if misconfigured:
                msg += f"Misconfigured headers: {', '.join(misconfigured)}."
            print(Fore.YELLOW + "[!] " + msg)
            add_result("HTTP Security Headers", "medium", msg)
        else:
            print(Fore.GREEN + "[✓] All important HTTP security headers are present and properly configured.")
            add_result("HTTP Security Headers", "low", "All important HTTP security headers are present and properly configured.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check HTTP security headers: {e}")
        add_result("HTTP Security Headers", "high", f"Error checking HTTP security headers: {e}")

def check_x_frame_options(target):
    print(Fore.CYAN + "\n[+] Checking X-Frame-Options Header")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        xfo = response.headers.get("X-Frame-Options")
        if xfo:
            print(Fore.GREEN + f"[✓] X-Frame-Options: {xfo}")
            add_result("X-Frame-Options", "low", f"X-Frame-Options header present: {xfo}")
        else:
            print(Fore.YELLOW + "[!] X-Frame-Options header missing - vulnerable to clickjacking")
            add_result("X-Frame-Options", "high", "X-Frame-Options header missing - vulnerable to clickjacking")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking X-Frame-Options: {e}")
        add_result("X-Frame-Options", "high", f"Error checking X-Frame-Options: {e}")

def check_hsts_header(target):
    print(Fore.CYAN + "\n[+] Checking HSTS Header")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        hsts = response.headers.get("Strict-Transport-Security")
        if hsts:
            print(Fore.GREEN + f"[✓] HSTS header present: {hsts}")
            add_result("HSTS Header", "low", f"HSTS header present: {hsts}")
        else:
            print(Fore.YELLOW + "[!] HSTS header missing - HTTPS downgrade attacks possible")
            add_result("HSTS Header", "medium", "HSTS header missing - HTTPS downgrade attacks possible")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking HSTS header: {e}")
        add_result("HSTS Header", "high", f"Error checking HSTS header: {e}")

def check_csrf_token(target):
    print(Fore.CYAN + "\n[+] Checking for CSRF Tokens in Forms")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        forms = soup.find_all("form")
        token_found = False
        for form in forms:
            inputs = form.find_all("input")
            for inp in inputs:
                name = inp.get("name", "").lower()
                if "csrf" in name or "token" in name:
                    token_found = True
                    break
            if token_found:
                break
        if token_found:
            print(Fore.GREEN + "[✓] CSRF token found in at least one form")
            add_result("CSRF Token", "low", "CSRF token found in at least one form")
        else:
            print(Fore.YELLOW + "[!] No CSRF tokens found in forms - potential CSRF vulnerability")
            add_result("CSRF Token", "high", "No CSRF tokens found in forms - potential CSRF vulnerability")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking CSRF tokens: {e}")
        add_result("CSRF Token", "high", f"Error checking CSRF tokens: {e}")

def check_ip_direct_access(target, ip):
    print(Fore.CYAN + "\n[+] Checking if target web page loads from IP directly")
    try:
        parsed = urlparse(target)
        scheme = parsed.scheme or "http"
        url_ip = f"{scheme}://{ip}"
        response = requests.get(url_ip, headers=DEFAULT_HEADERS, timeout=10)
        if response.status_code == 200:
            print(Fore.YELLOW + f"[!] Target loads from IP address directly: {url_ip}")
            add_result("IP Direct Access", "medium", f"Target loads from IP address directly: {url_ip}")
        else:
            print(Fore.GREEN + "[✓] Target does not load from IP address directly")
            add_result("IP Direct Access", "low", "Target does not load from IP address directly")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking IP direct access: {e}")
        add_result("IP Direct Access", "medium", f"Error checking IP direct access: {e}")

def check_ssl_tls(target):
    print(Fore.CYAN + "\n[+] Checking SSL/TLS Configuration")
    parsed = urlparse(target)
    hostname = parsed.hostname
    port = 443

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                print(Fore.GREEN + f"[✓] SSL certificate subject: {subject.get('commonName', 'N/A')}")
                print(Fore.GREEN + f"[✓] SSL certificate issuer: {issuer.get('commonName', 'N/A')}")
                add_result("SSL/TLS Check", "low", f"SSL certificate subject: {subject.get('commonName', 'N/A')}, issuer: {issuer.get('commonName', 'N/A')}")
    except Exception as e:
        print(Fore.RED + f"[-] SSL/TLS check failed: {e}")
        add_result("SSL/TLS Check", "high", f"SSL/TLS check failed: {e}")

def run_subdomain_enum(domain):
    print(Fore.CYAN + "\n[+] Running Subdomain Enumeration")
    try:
        output = run_command(["sublist3r", "-d", domain, "-o", "subdomains.txt"])
        if "Error" in output:
            raise Exception(output)
        with open("subdomains.txt") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        if subdomains:
            print(Fore.GREEN + f"[✓] Found {len(subdomains)} subdomains:")
            for sub in subdomains:
                print(f"  - {sub}")
            add_result("Subdomain Enumeration", "medium", f"Found subdomains: {', '.join(subdomains)}")
        else:
            print(Fore.YELLOW + "[!] No subdomains found.")
            add_result("Subdomain Enumeration", "low", "No subdomains found.")
    except FileNotFoundError:
        print(Fore.RED + "[-] Sublist3r not installed or not found. Skipping subdomain enumeration.")
        add_result("Subdomain Enumeration", "medium", "Sublist3r not installed or not found.")
    except Exception as e:
        print(Fore.RED + f"[-] Subdomain enumeration failed: {e}")
        add_result("Subdomain Enumeration", "high", f"Subdomain enumeration error: {e}")

# --- Common Vulnerability Checks ---

def check_open_redirect(target):
    print(Fore.CYAN + "\n[+] Checking for Open Redirect Vulnerabilities")
    try:
        redirect_params = ["url", "redirect", "next", "dest", "destination", "redir", "callback"]
        test_url = "https://evil.com"
        vulnerable = False

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in redirect_params:
            test_target = f"{base_url}?{param}={test_url}"
            response = requests.get(test_target, headers=DEFAULT_HEADERS, allow_redirects=False, timeout=10)
            location = response.headers.get("Location", "")
            if test_url in location:
                print(Fore.YELLOW + f"[!] Potential open redirect via parameter '{param}'")
                add_result("Open Redirect", "high", f"Open redirect detected via parameter '{param}'")
                vulnerable = True
                break

        if not vulnerable:
            print(Fore.GREEN + "[✓] No open redirect vulnerabilities detected")
            add_result("Open Redirect", "low", "No open redirect vulnerabilities detected")
    except Exception as e:
        print(Fore.RED + f"[-] Open redirect check failed: {e}")
        add_result("Open Redirect", "medium", f"Open redirect check error: {e}")

def check_basic_xss(target):
    print(Fore.CYAN + "\n[+] Checking for Basic Reflected XSS Vulnerabilities")
    try:
        xss_params = ["q", "search", "query", "text", "input", "keyword"]
        xss_payload = "<script>alert(1)</script>"
        vulnerable = False

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in xss_params:
            test_target = f"{base_url}?{param}={xss_payload}"
            response = requests.get(test_target, headers=DEFAULT_HEADERS, timeout=10)
            if xss_payload in response.text:
                print(Fore.YELLOW + f"[!] Potential reflected XSS via parameter '{param}'")
                add_result("Reflected XSS", "high", f"Reflected XSS detected via parameter '{param}'")
                vulnerable = True
                break

        if not vulnerable:
            print(Fore.GREEN + "[✓] No basic reflected XSS vulnerabilities detected")
            add_result("Reflected XSS", "low", "No basic reflected XSS vulnerabilities detected")
    except Exception as e:
        print(Fore.RED + f"[-] XSS check failed: {e}")
        add_result("Reflected XSS", "medium", f"XSS check error: {e}")

def check_basic_sqli(target):
    print(Fore.CYAN + "\n[+] Checking for Basic SQL Injection Vulnerabilities")
    try:
        sqli_params = ["id", "user", "item", "product", "page"]
        sqli_payload = "' OR '1'='1"
        vulnerable = False

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in sqli_params:
            test_target = f"{base_url}?{param}={sqli_payload}"
            response = requests.get(test_target, headers=DEFAULT_HEADERS, timeout=10)
            errors = [
                "you have an error in your sql syntax",
                "warning: mysql",
                "unclosed quotation mark after the character string",
                "quoted string not properly terminated",
                "sql syntax error",
                "mysql_fetch_array()",
                "syntax error",
            ]
            content = response.text.lower()
            if any(err in content for err in errors):
                print(Fore.YELLOW + f"[!] Potential SQL Injection via parameter '{param}'")
                add_result("SQL Injection", "high", f"SQL Injection detected via parameter '{param}'")
                vulnerable = True
                break

        if not vulnerable:
            print(Fore.GREEN + "[✓] No basic SQL Injection vulnerabilities detected")
            add_result("SQL Injection", "low", "No basic SQL Injection vulnerabilities detected")
    except Exception as e:
        print(Fore.RED + f"[-] SQL Injection check failed: {e}")
        add_result("SQL Injection", "medium", f"SQL Injection check error: {e}")

def check_directory_listing(target):
    print(Fore.CYAN + "\n[+] Checking for Directory Listing Enabled")
    try:
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"
        response = requests.get(base_url, headers=DEFAULT_HEADERS, timeout=10)
        if response.status_code == 200 and re.search(r"Index of /", response.text, re.IGNORECASE):
            print(Fore.YELLOW + "[!] Directory listing appears to be enabled on root directory")
            add_result("Directory Listing", "medium", "Directory listing enabled on root directory")
        else:
            print(Fore.GREEN + "[✓] Directory listing not detected on root directory")
            add_result("Directory Listing", "low", "Directory listing not detected on root directory")
    except Exception as e:
        print(Fore.RED + f"[-] Directory listing check failed: {e}")
        add_result("Directory Listing", "medium", f"Directory listing check error: {e}")

def check_subdomain_takeover(domain):
    print(Fore.CYAN + "\n[+] Checking for Potential Subdomain Takeover")
    try:
        subdomains_file = "subdomains.txt"
        if not os.path.exists(subdomains_file):
            print(Fore.YELLOW + "[!] Subdomains file not found, skipping subdomain takeover check")
            add_result("Subdomain Takeover", "medium", "Subdomains file not found, skipping check")
            return

        # Placeholder: full DNS CNAME analysis not implemented here
        print(Fore.YELLOW + "[!] Subdomain takeover check requires DNS CNAME analysis - not fully implemented")
        add_result("Subdomain Takeover", "medium", "Subdomain takeover check requires DNS CNAME analysis - not fully implemented")
    except Exception as e:
        print(Fore.RED + f"[-] Subdomain takeover check failed: {e}")
        add_result("Subdomain Takeover", "medium", f"Subdomain takeover check error: {e}")

def aidef ai_analysis():
    print(Fore.CYAN + "\n[+] Running AI-based Analysis (Placeholder)")
    # This is a placeholder for AI analysis integration.
    # You can integrate with an AI model or API here to analyze collected data.
    add_result("AI Analysis", "low", "AI analysis placeholder - no issues detected")

def generate_report_json(filename="thunder_web_checker_report.json"):
    print(Fore.CYAN + f"\n[+] Generating JSON report: {filename}")
    try:
        with open(filename, "w") as f:
            json.dump(report_json, f, indent=4)
        print(Fore.GREEN + f"[✓] JSON report saved to {filename}")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to save JSON report: {e}")

def generate_report_pdf(filename="thunder_web_checker_report.pdf"):
    print(Fore.CYAN + f"\n[+] Generating PDF report: {filename}")
    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Thunder Web Checker Report", ln=True, align="C")
        pdf.ln(10)

        pdf.set_font("Arial", "B", 12)
        for item in report_json:
            pdf.cell(0, 10, f"Title: {item['title']}", ln=True)
            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 8, f"Risk Level: {item['risk_level'].capitalize()}")
            pdf.multi_cell(0, 8, f"Summary: {item['summary']}")
            pdf.ln(5)
            pdf.set_font("Arial", "B", 12)

        pdf.output(filename)
        print(Fore.GREEN + f"[✓] PDF report saved to {filename}")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to save PDF report: {e}")

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Thunder Web Checker AI - Comprehensive Web Security Scanner")
    parser.add_argument("target", help="Target URL or domain to scan (e.g. https://example.com)")
    args = parser.parse_args()

    target = args.target
    if not target.startswith("http"):
        target = "http://" + target

    parsed = urlparse(target)
    domain = parsed.netloc or parsed.path

    ip, hosting = get_ip_and_hosting(domain)

    # Run scans and checks
    run_nmap_scan(domain)
    run_whatweb_scan(target)
    run_wafw00f_scan(target)
    check_http_security_headers(target)
    check_x_frame_options(target)
    check_hsts_header(target)
    check_csrf_token(target)
    if ip:
        check_ip_direct_access(target, ip)
    check_ssl_tls(target)
    run_subdomain_enum(domain)

    # Common vulnerability checks
    check_open_redirect(target)
    check_basic_xss(target)
    check_basic_sqli(target)
    check_directory_listing(target)
    check_subdomain_takeover(domain)

    # AI analysis placeholder
    ai_analysis()

    # Generate reports
    generate_report_json()
    generate_report_pdf()

if __name__ == "__main__":
    main()
