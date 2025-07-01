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
from datetime import datetime
import random
from fpdf import FPDF
import os

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = r"""
··································································
:    ____  _  _  _  _  _  _  ___  ___  ___     _    _  ___  ___  :
:   (_  _)( )( )( )( )( \( )(   \(  _)(  ,)   ( \/\/ )(  _)(  ,) :
:     )(   )__(  )()(  )  (  ) ) )) _) )  \    \    /  ) _) ) ,\ :
:    (__) (_)(_) \__/ (_)\_)(___/(___)(_)")    \/\/  (___)(___/ :
:   __  _  _  ___   __  _ _   ___  ___                           :
:  / _)( )( )(  _) / _)( ) ) (  _)(  ,)                          :
: ( (_  )__(  ) _)( (_  )  \  ) _) )  \                          :
:  \__)(_)(_)(___) \__)(_)\_)(___)(_)")                         :
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


def add_result(title, risk, summary, score=None):
    entry = {
        "title": title,
        "risk_level": RISK_LEVELS[risk],
        "summary": summary
    }
    if score:
        entry["ai_score"] = score
        summary += f"\nAI Risk Score: {score}/10"
    report_json.append(entry)
    pdf.cell(200, 10, txt=f"{title} - {RISK_LEVELS[risk]}", ln=True)
    pdf.multi_cell(0, 10, summary)
    print(Fore.CYAN + f"[AI Risk] {title} → {RISK_LEVELS[risk]}")
    if score:
        print(Fore.CYAN + f"         AI Risk Score: {score}/10")
    print(Fore.WHITE + f"         Summary: {summary}\n")


def ai_insight(context):
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


def export_report(json_only=False, pdf_only=False):
    if not pdf_only:
        with open("thunder_report.json", "w") as f:
            json.dump(report_json, f, indent=2)
        print(Fore.YELLOW + "\n[✓] JSON report saved to thunder_report.json")

    if not json_only:
        pdf.output("thunder_report.pdf")
        print(Fore.YELLOW + "[✓] PDF report saved to thunder_report.pdf")
