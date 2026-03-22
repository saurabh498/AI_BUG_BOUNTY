# main.py

from core.crawler import crawl
from modules.sqli_scanner import scan_sqli
from modules.xss_scanner import scan_xss
from modules.dir_scanner import scan_directories
from modules.header_scanner import scan_headers
from modules.sensitive_scanner import scan_sensitive_files
from modules.login_scanner import scan_login
from modules.fuzzer import fuzz_parameters
from recon.subdomain_enum import find_subdomains
from core.report import generate_report, update_scan_stats, save_scan_history
from core.thread_engine import run_multithreaded_scan
from core.storage import set_progress, set_status
from core.validator import validate_target
from modules.open_redirect import scan_open_redirect
from modules.js_scanner import scan_js_endpoints
import sys


def start_scan(target, user_id=None, config=None, threads=10):

    # ✅ Default config — all modules on
    if config is None:
        config = {
            "headers":   True,
            "sensitive": True,
            "sqli":      True,
            "xss":       True,
            "redirect":  True,
            "fuzzer":    True,
            "login":     True,
            "dirs":      True
        }

    print("\n🚀 AI Bug Bounty Scanner Starting\n")

    # ── 1️⃣ VALIDATE ──
    set_progress(2, "🔎 Validating target...")
    is_valid, cleaned_url, error = validate_target(target)
    if not is_valid:
        print(f"[✗] Invalid target: {error}")
        set_progress(100, f"❌ {error}")
        set_status("error")
        return

    target = cleaned_url
    print(f"[✔] Target validated: {target}")

    # ── 2️⃣ RECON ──
    set_progress(5, "🔍 Recon — finding subdomains")
    print("\n[1] Recon Phase")
    subdomains = find_subdomains(target)

    # ── 3️⃣ CRAWL ──
    set_progress(12, "🕷️ Crawling target")
    print("\n[2] Crawling Target")
    all_targets = [target] + [s for s in subdomains if s]
    urls = []
    for t in all_targets:
        urls.extend(crawl(t))
    urls = list(set(urls))

    if not urls:
        print("[!] No URLs found, using target directly")
        urls = [target]

    # ── 4️⃣ JS ENDPOINT DISCOVERY ──
    set_progress(20, "⚡ Discovering JS endpoints")
    print("\n[3] JS Endpoint Discovery")
    js_endpoints = []
    for url in urls[:10]:  # limit to first 10 to avoid slowdown
        found = scan_js_endpoints(url)
        js_endpoints.extend(found)

    js_endpoints = list(set(js_endpoints))
    urls = list(set(urls + js_endpoints))
    print(f"[JS] Added {len(js_endpoints)} JS-discovered endpoints")
    print(f"[INFO] Total URLs to scan: {len(urls)}")

    update_scan_stats(target=target, urls=len(urls))

    # ── 5️⃣ HEADERS ──
    if config.get("headers"):
        set_progress(28, "🔎 Checking security headers")
        print("\n[4] Security Headers Check")
        run_multithreaded_scan([target], scan_headers, threads=1)

    # ── 6️⃣ SENSITIVE FILES ──
    if config.get("sensitive"):
        set_progress(35, "🗂️ Sensitive file exposure check")
        print("\n[5] Sensitive File Scan")
        run_multithreaded_scan([target], scan_sensitive_files, threads=1)

    # ── 7️⃣ DIRECTORY SCAN ──
    if config.get("dirs"):
        set_progress(42, "📁 Directory bruteforce")
        print("\n[6] Directory Scan")
        run_multithreaded_scan([target], scan_directories, threads=threads // 2)

    # ── 8️⃣ SQLi ──
    if config.get("sqli"):
        set_progress(52, "💉 SQL Injection scan")
        print("\n[7] SQL Injection Scan")
        run_multithreaded_scan(urls, scan_sqli, threads=threads)

    # ── 9️⃣ XSS ──
    if config.get("xss"):
        set_progress(63, "⚡ XSS scan")
        print("\n[8] XSS Scan")
        run_multithreaded_scan(urls, scan_xss, threads=threads)

    # ── 🔟 OPEN REDIRECT ──
    if config.get("redirect"):
        set_progress(73, "↪️ Open redirect scan")
        print("\n[9] Open Redirect Scan")
        run_multithreaded_scan(urls, scan_open_redirect, threads=threads // 2)

    # ── 1️⃣1️⃣ FUZZER ──
    if config.get("fuzzer"):
        set_progress(82, "🎯 Fuzzing parameters")
        print("\n[10] Parameter Fuzzing")
        run_multithreaded_scan(urls, fuzz_parameters, threads=threads // 2)

    # ── 1️⃣2️⃣ LOGIN ──
    if config.get("login"):
        set_progress(91, "🔐 Login bypass testing")
        print("\n[11] Login Scan")
        run_multithreaded_scan(urls, scan_login, threads=threads // 2)

    # ── 1️⃣3️⃣ REPORT ──
    set_progress(97, "📄 Generating report")
    print("\n[12] Generating Report...")
    generate_report()

    set_progress(100, "✅ Scan completed")
    print("\n✅ Scan Completed!")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py http://target.com")
    else:
        start_scan(sys.argv[1])