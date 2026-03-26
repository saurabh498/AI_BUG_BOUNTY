# core/validator.py

import re
import requests
from urllib.parse import urlparse

SQL_ERRORS = [
    "sql syntax",
    "mysql",
    "syntax error",
    "ora-",
    "postgresql",
    "warning: mysql",
    "unclosed quotation"
]

def check_xss(response, payload):
    if not response:
        return False
    content = response.text.lower()
    return payload.lower() in content

def check_sqli(response, baseline_text=None):
    if not response:
        return False
    content = response.text.lower()
    for err in SQL_ERRORS:
        if err in content:
            return True
    if baseline_text:
        if abs(len(content) - len(baseline_text)) > 100:
            return True
    return False


# ================================================================
# ✅ NEW — TARGET VALIDATION
# ================================================================

def validate_target(url):
    """
    Validates a target URL before scanning.
    Returns: (is_valid, cleaned_url, error_message)
    """

    if not url or not url.strip():
        return False, None, "Target URL cannot be empty"

    url = url.strip()

    # ── 1. Add scheme if missing ──
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    # ── 2. Basic URL format check ──
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, None, "Invalid URL format — no domain found"
    except Exception:
        return False, None, "Invalid URL format"

    # ── 3. Block ONLY loopback — allow private IPs for lab testing ──
    loopback_blocked = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1"
    ]
    domain = parsed.netloc.split(":")[0]
    for b in loopback_blocked:
        if domain == b:
            return False, None, f"Scanning loopback addresses is not allowed: {domain}"

    # ── 4. Domain/IP format check ──
    domain_regex = re.compile(
        r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    ip_regex = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'
    )
    if not domain_regex.match(domain) and not ip_regex.match(domain):
        return False, None, f"Invalid domain or IP format: {domain}"

    # ── 5. Check if target is reachable ──
    try:
        response = requests.get(url, timeout=8)
        if response.status_code >= 500:
            return False, url, f"Target returned server error: {response.status_code}"
    except requests.exceptions.ConnectionError:
        return False, None, f"Cannot connect to target: {url} — is it online?"
    except requests.exceptions.Timeout:
        return False, None, "Target timed out — is it online?"
    except requests.exceptions.InvalidURL:
        return False, None, "Invalid URL"
    except Exception as e:
        return False, None, f"Could not reach target: {e}"

    return True, url, None