import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.payloads import SQLI_PAYLOADS, XSS_PAYLOADS
from core.intelligence import handle_vulnerability
from core.validator import check_sqli
from modules.rate_limiter import rate_limiter  # ✅ NEW

def fuzz_parameters(url):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return

    print(f"[FUZZING] {url}")

    for param in params:
        payloads = SQLI_PAYLOADS + XSS_PAYLOADS
        for payload in payloads:
            rate_limiter.wait()  # ✅ rate limit
            test_params = params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            try:
                response = requests.get(new_url, timeout=5)
                text = response.text.lower()
                if any(err in text for err in ["sql", "mysql", "syntax"]):
                    handle_vulnerability("SQL Injection", new_url, param, payload)
                if ("<script" in payload or "onerror" in payload) and payload.lower() in text:
                    handle_vulnerability("XSS", new_url, param, payload)
            except Exception as e:
                print("[FUZZ ERROR]", e)