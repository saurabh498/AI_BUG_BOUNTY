# modules/open_redirect.py

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.intelligence import handle_vulnerability

# ✅ Common redirect parameters
REDIRECT_PARAMS = [
    "redirect", "redirect_to", "redirect_url", "redirectUrl",
    "return", "returnTo", "return_url", "returnUrl",
    "next", "url", "goto", "dest", "destination",
    "target", "rurl", "ref", "continue", "forward",
    "location", "link", "out", "view", "to", "from"
]

# ✅ Payloads to test
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2f..",
    "https://evil.com/%2f..",
    "/\\evil.com",
    "https:evil.com",
    "/%09/evil.com",
    "https://evil.com#",
    "https://evil.com?",
]

# ✅ Indicators that redirect happened
def is_redirected_to_evil(response):
    # Check final URL after redirects
    if "evil.com" in response.url:
        return True
    # Check Location header
    location = response.headers.get("Location", "")
    if "evil.com" in location:
        return True
    return False

def scan_open_redirect(url):
    print(f"[REDIRECT] Scanning: {url}")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    test_targets = []

    # ✅ Test existing parameters
    if params:
        for param in params:
            if any(p in param.lower() for p in REDIRECT_PARAMS):
                for payload in REDIRECT_PAYLOADS:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    new_query = urlencode(test_params, doseq=True)
                    new_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    test_targets.append((new_url, param, payload))

    # ✅ Also inject redirect params if none found
    if not test_targets:
        for param in ["redirect", "next", "url", "return"]:
            for payload in REDIRECT_PAYLOADS[:3]:  # limit to top 3
                injected = f"{url}{'&' if '?' in url else '?'}{param}={payload}"
                test_targets.append((injected, param, payload))

    for test_url, param, payload in test_targets:
        try:
            response = requests.get(
                test_url,
                timeout=5,
                allow_redirects=True
            )

            if is_redirected_to_evil(response):
                print(f"[!!!] Open Redirect Found: {test_url}")
                handle_vulnerability(
                    "Open Redirect",
                    test_url,
                    parameter=param,
                    payload=payload
                )

        except Exception as e:
            print(f"[REDIRECT ERROR] {test_url} -> {e}")