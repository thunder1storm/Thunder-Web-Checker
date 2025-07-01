#!/usr/bin/env python3
import argparse
import json
import os
import re
import socket
import ssl
import subprocess
import threading
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from fpdf import FPDF
import openai

init(autoreset=True)

# === Configure your OpenAI API key here ===
openai.api_key = os.getenv("OPENAI_API_KEY")
if not openai.api_key:
    print(Fore.YELLOW + "[!] Warning: OPENAI_API_KEY environment variable not set. AI analysis will be skipped.")

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

def get_ai_risk_score_and_advice(title, summary):
    if not openai.api_key:
        # Skip AI if no key
        return 1, "No AI analysis performed (API key missing).", ""
    prompt = f"""
You are a cybersecurity analyst. Given this security check result:

Title: {title}
Details: {summary}

Please provide:
- A risk score from 1 (lowest) to 10 (critical),
- A brief explanation of the risk,
- Practical suggestions to mitigate or investigate.

Respond ONLY in JSON format like:
{{
  "risk_score": <number>,
  "explanation": "<explanation>",
  "suggestions": "<suggestions>"
}}
"""
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful cybersecurity assistant."},
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=200,
        )
        text = response.choices[0].message.content.strip()
        # Attempt to parse JSON response
        data = json.loads(text)
        return data.get("risk_score", 1), data.get("explanation", ""), data.get("suggestions", "")
    except Exception as e:
        print(Fore.YELLOW + f"[!] AI analysis failed: {e}")
        return 1, "AI analysis failed or returned invalid data.", ""

def add_result(title, summary):
    risk_score, explanation, suggestions = get_ai_risk_score_and_advice(title, summary)
    if risk_score >= 7:
        risk_level = "high"
    elif risk_score >= 4:
        risk_level = "medium"
    else:
        risk_level = "low"
    entry = {
        "title": title,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "summary": summary,
        "explanation": explanation,
        "suggestions": suggestions,
    }
    with report_lock:
        report_json.append(entry)

    print(Fore.CYAN + f"[AI Risk] {title} → Score: {risk_score} / 10, Level: {risk_level.upper()}")
    print(Fore.WHITE + f"Summary: {summary}")
    print(Fore.MAGENTA + f"Explanation: {explanation}")
    if suggestions:
        print(Fore.GREEN + f"Suggestions: {suggestions}")
    print()

# Below here, keep your existing functions like run_nmap_scan(), check_http_security_headers(), etc.
# Wherever you currently do add_result(title, risk, summary), replace with add_result(title, summary) only.

# Example snippet for one function adapted:
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
            add_result("HTTP Security Headers", msg)
        else:
            print(Fore.GREEN + "[✓] All important HTTP security headers are present and properly configured.")
            add_result("HTTP Security Headers", "All important HTTP security headers are present and properly configured.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to check HTTP security headers: {e}")
        add_result("HTTP Security Headers", f"Error checking HTTP security headers: {e}")

# (Continue adapting all add_result calls similarly in other checks)

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
        pdf.cell(0, 10, "Thunder Web Checker AI Report", ln=True, align="C")
        pdf.ln(10)

        pdf.set_font("Arial", "B", 12)
        for item in report_json:
            pdf.cell(0, 10, f"Title: {item['title']}", ln=True)
            pdf.set_font("Arial", "", 11)
            pdf.multi_cell(0, 8, f"Risk Score: {item['risk_score']}/10")
            pdf.multi_cell(0, 8, f"Risk Level: {item['risk_level'].capitalize()}")
            pdf.multi_cell(0, 8, f"Summary: {item['summary']}")
            pdf.multi_cell(0, 8, f"Explanation: {item['explanation']}")
            pdf.multi_cell(0, 8, f"Suggestions: {item['suggestions']}")
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

    # Implement all your scans here, e.g.:
    # ip, hosting = get_ip_and_hosting(domain)
    # run_nmap_scan(domain)
    # run_whatweb_scan(target)
    # ... call add_result() with only title & summary in all

    # For demo:
    add_result("Demo Check", "This is a demo summary for AI risk scoring and advice.")

    generate_report_json()
    generate_report_pdf()

if __name__ == "__main__":
    main()
