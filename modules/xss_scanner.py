import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.intelligence import handle_vulnerability
from core.validator import check_xss
from core.ai_payloads import get_xss_payloads
from modules.rate_limiter import rate_limiter  # ✅ NEW

payloads = get_xss_payloads()

def inject_payload(url, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        query = {"xss": payload}
    else:
        for key in query:
            query[key] = payload
    return urlunparse(parsed._replace(query=urlencode(query)))

def scan_xss(url):
    if "?" not in url:
        return
    print(f"[XSS] {url}")
    for payload in payloads:
        rate_limiter.wait()  # ✅ rate limit
        test_url = inject_payload(url, payload)
        try:
            response = requests.get(test_url, timeout=5)
            if check_xss(response, payload):
                handle_vulnerability("XSS", test_url, "auto", payload)
        except Exception as e:
            print("[XSS ERROR]", e)