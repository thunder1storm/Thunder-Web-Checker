def run_service_scan(host):
    print(Fore.CYAN + "\n[+] Service and Version Detection (nmap)")
    print(Fore.YELLOW + f"Running: nmap -sV --version-light {host}\n")
    try:
        result = subprocess.check_output(["nmap", "-sV", "--version-light", host], stderr=subprocess.DEVNULL).decode()
        print(Fore.GREEN + result)

        # Simplified output: Only check if any service is detected, skip printing all services
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
        waf_detected = False

        for header in waf_headers:
            if header in response.headers:
                waf_detected = True
                break

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
        print(Fore.GREEN + result)
        if "VULNERABLE" in result:
            print(Fore.RED + "[!] One or more potential vulnerabilities found.")
        else:
            print(Fore.GREEN + "[✓] No known vulnerabilities detected by scripts.")
    except Exception as e:
        print(Fore.RED + f"[-] Failed to run vulnerability scan: {e}")
