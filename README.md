
# Thunder Web Checker

A multi-tool web security scanner aggregating SSL checks, technology detection, CSRF form analysis, and header security checks.

---

## Features

- Check SSL certificate expiry date
- Run detailed SSL/TLS scans with `sslscan` and `testssl.sh`
- Detect `X-Frame-Options` header presence (clickjacking protection)
- Identify forms without CSRF tokens
- Detect web technologies and versions via `whatweb`
- Verify website loads identically via domain name and direct IP

---

## Requirements

- Python 3.x
- Python packages: `requests`, `beautifulsoup4`
- External tools:
  - [whatweb](https://github.com/urbanadventurer/WhatWeb)
  - [sslscan](https://github.com/rbsec/sslscan)
  - [testssl.sh](https://github.com/drwetter/testssl.sh)

---

## Installation

### On Debian/Ubuntu-based systems:

```bash
sudo apt update && sudo apt install -y whatweb sslscan git curl python3-pip
pip3 install --user requests beautifulsoup4
git clone https://github.com/drwetter/testssl.sh.git ~/testssl.sh
sudo ln -sf ~/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
