import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.intelligence import handle_vulnerability
from core.validator import check_sqli
from core.ai_payloads import get_sqli_payloads
from modules.rate_limiter import rate_limiter  # ✅ NEW

SQLI_PAYLOADS = get_sqli_payloads()

def inject_payload(url, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        query = {"id": payload}
    else:
        for key in query:
            query[key] = payload
    return urlunparse(parsed._replace(query=urlencode(query)))

def scan_sqli(url):
    if "?" not in url:
        return
    print(f"[SQLi] {url}")
    try:
        baseline_res = requests.get(url, timeout=5)
        baseline_text = baseline_res.text
    except:
        return

    for payload in SQLI_PAYLOADS:
        rate_limiter.wait()  # ✅ rate limit
        test_url = inject_payload(url, payload)
        try:
            response = requests.get(test_url, timeout=5)
            if check_sqli(response, baseline_text):
                handle_vulnerability("SQL Injection", test_url, "auto", payload)
        except Exception as e:
            print("[SQLi ERROR]", e)