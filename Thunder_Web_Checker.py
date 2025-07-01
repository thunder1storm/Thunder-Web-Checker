def run_service_scan(host):
    print(Fore.CYAN + "\n[+] Service and Version Detection (nmap)")
    print(Fore.YELLOW + f"Running: nmap -sV --version-light {host}\n")
    try:
        result = subprocess.check_output(["nmap", "-sV", "--version-light", host], stderr=subprocess.DEVNULL).decode()
        if "open" in result:
            print(Fore.GREEN + "[✓] Services detected and responding.")
        else:
            print(Fore.RED + "[✗] No services responded on common ports.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to scan services: {e}")


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
            print(Fore.YELLOW + "[!] Direct IP access to website is possible: YES")
        else:
            print(Fore.GREEN + "[✓] Direct IP access blocked: NO")

    except requests.exceptions.SSLError:
        print(Fore.GREEN + "[✓] Direct IP access blocked due to SSL mismatch: NO")
    except Exception:
        print(Fore.GREEN + "[✓] Direct IP access blocked or unreachable: NO")


def detect_waf(target):
    print(Fore.CYAN + "\n[+] Checking for WAF Protection")
    try:
        response = requests.get(target, headers=DEFAULT_HEADERS, timeout=10)
        waf_headers = ['server', 'x-waf-detection', 'x-sucuri-id', 'x-firewall-protection']
        waf_detected = any(header in response.headers for header in waf_headers)

        if waf_detected or any("waf" in v.lower() for v in response.headers.values()):
            print(Fore.YELLOW + "[!] WAF detected: YES")
        else:
            print(Fore.GREEN + "[✓] WAF not detected: NO")

    except Exception as e:
        print(Fore.RED + f"[-] Failed to check for WAF: {e}")


def check_common_vulnerabilities(target):
    print(Fore.CYAN + "\n[+] Scanning for Common Vulnerabilities (CVE matching - Nmap NSE)")
    try:
        parsed = urlparse(target)
        host = parsed.hostname
        result = subprocess.check_output(["nmap", "--script", "vuln", host], stderr=subprocess.DEVNULL).decode()
        if "VULNERABLE" in result:
            print(Fore.RED + "[!] One or more potential vulnerabilities found.")
        else:
            print(Fore.GREEN + "[✓] No known vulnerabilities detected by scripts.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to run vulnerability scan: {e}")


def detect_directory_listing(target):
    print(Fore.CYAN + "\n[+] Checking for Directory Listing Enabled")
    try:
        test_path = target.rstrip('/') + "/.git/"
        res = requests.get(test_path, headers=DEFAULT_HEADERS, timeout=10, verify=False)
        if "Index of" in res.text and res.status_code == 200:
            print(Fore.YELLOW + "[!] Directory listing might be enabled: YES")
        else:
            print(Fore.GREEN + "[✓] Directory listing appears disabled: NO")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking directory listing: {e}")


def detect_exposed_env(target):
    print(Fore.CYAN + "\n[+] Checking for Exposed .env File")
    try:
        env_url = target.rstrip('/') + "/.env"
        res = requests.get(env_url, headers=DEFAULT_HEADERS, timeout=10, verify=False)
        if "APP_KEY" in res.text or "DB_PASSWORD" in res.text:
            print(Fore.RED + "[!] .env file exposed and contains sensitive keys!")
        else:
            print(Fore.GREEN + "[✓] No exposed .env file found.")
    except Exception as e:
        print(Fore.RED + f"[-] Error checking .env exposure: {e}")


def detect_outdated_js(target):
    print(Fore.CYAN + "\n[+] Checking for Outdated JavaScript Libraries")
    try:
        res = requests.get(target, headers=DEFAULT_HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(res.text, "html.parser")
        scripts = soup.find_all("script", src=True)
        known_libraries = {
            "fancybox": {"pattern": r"fancybox.*?([\d.]+)", "latest": "3.5.7", "name": "fancyBox"},
            # Add more libraries here as needed
        }

        found = False
        for script in scripts:
            src = script["src"]
            for lib, meta in known_libraries.items():
                if lib in src.lower():
                    version_match = re.search(meta["pattern"], src)
                    if version_match:
                        current_version = version_match.group(1)
                        if current_version != meta["latest"]:
                            print(Fore.YELLOW + f"[!] Outdated JavaScript Detected: {meta['name']} {current_version}")
                            print(Fore.YELLOW + f"    → {src}")
                            print(Fore.YELLOW + f"    → Latest: {meta['latest']}")
                            found = True
        if not found:
            print(Fore.GREEN + "[✓] No outdated JavaScript libraries detected.")

    except Exception as e:
        print(Fore.RED + f"[-] Error checking JavaScript libraries: {e}")
