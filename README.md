# Thunder Web Checker

**Thunder Web Checker** is a powerful command-line web security reconnaissance tool designed to help penetration testers and security analysts quickly gather essential information about a target website and detect common security misconfigurations.

---

## Features

- 🔍 **Domain and IP Resolution:** Resolves domain names to IP addresses and retrieves hosting information such as ISP, organization, location, ASN, and cloud hosting detection.
- ⚙️ **Service and Version Detection:** Performs service discovery and version detection using `nmap` with a lightweight scan.
- 🛡️ **Security Header Checks:**
  - **Clickjacking Protection:** Checks for `X-Frame-Options` and Content Security Policy `frame-ancestors` headers.
  - **Strict-Transport-Security (HSTS):** Verifies if HSTS is enabled.
- 🔐 **CSRF Token Detection and Validation:** Parses forms on the web page to find CSRF tokens and tests basic validation by sending a dummy request.
- 🌐 **Direct IP Access Check:** Tests if the web server allows access via the raw IP address, which may indicate virtual host misconfigurations or potential Cloudflare bypass.
- 📝 **Colorful and Clear CLI Output:** Uses `colorama` for easy-to-read color-coded output.
- 🚀 Easy to extend for additional features like subdomain enumeration, directory brute-forcing, vulnerability scanning, and reporting.

---

## Requirements

- Python 3.6+
- [nmap](https://nmap.org/) installed and accessible in your system's PATH
- Python packages (install via pip):
  - `requests`
  - `beautifulsoup4`
  - `colorama`

---

## Installation

1. Clone or download this repository.

2. Install the Python dependencies:

```bash
pip install requests beautifulsoup4 colorama
