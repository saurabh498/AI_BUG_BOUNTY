# modules/js_scanner.py

import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from core.intelligence import handle_vulnerability

# ✅ Patterns to find endpoints in JS files
JS_ENDPOINT_PATTERNS = [
    # fetch() calls
    r'fetch\(["\']([^"\']+)["\']',
    # axios calls
    r'axios\.(get|post|put|delete|patch)\(["\']([^"\']+)["\']',
    # jQuery ajax
    r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']',
    # XMLHttpRequest
    r'\.open\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']',
    # API strings
    r'["\`](/api/[^\s"\'`\)]+)["\`]',
    r'["\`](/v\d+/[^\s"\'`\)]+)["\`]',
    r'["\`](/internal/[^\s"\'`\)]+)["\`]',
    r'["\`](/admin/[^\s"\'`\)]+)["\`]',
    r'["\`](/user[s]?/[^\s"\'`\)]+)["\`]',
    r'["\`](/auth/[^\s"\'`\)]+)["\`]',
    # URL assignments
    r'url\s*[:=]\s*["\']([^"\']+)["\']',
    r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
    r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    r'BASE_URL\s*[:=]\s*["\']([^"\']+)["\']',
    # String paths
    r'["\`](/[a-zA-Z0-9_\-]+/[a-zA-Z0-9_\-]+)["\`]',
]

# ✅ Extensions to skip
SKIP_EXTENSIONS = [
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".pdf", ".zip"
]

# ✅ Known CDN/external domains to skip
SKIP_DOMAINS = [
    "cdn.", "googleapis.com", "cloudflare.com",
    "jquery.com", "bootstrapcdn.com", "unpkg.com",
    "jsdelivr.net", "analytics", "fonts.google"
]


def should_skip(url):
    for ext in SKIP_EXTENSIONS:
        if url.lower().endswith(ext):
            return True
    for domain in SKIP_DOMAINS:
        if domain in url.lower():
            return True
    return False


def extract_js_files(base_url, html):
    """Find all JS file URLs from HTML"""
    soup = BeautifulSoup(html, "html.parser")
    js_files = []

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            full_url = urljoin(base_url, src)
            if not should_skip(full_url):
                js_files.append(full_url)

    return list(set(js_files))


def extract_endpoints_from_js(js_content, base_url):
    """Extract API endpoints from JS file content"""
    endpoints = set()

    for pattern in JS_ENDPOINT_PATTERNS:
        matches = re.findall(pattern, js_content)
        for match in matches:
            # Some patterns return tuples (method, url)
            if isinstance(match, tuple):
                endpoint = match[-1]
            else:
                endpoint = match

            endpoint = endpoint.strip()

            # ✅ Filter out garbage
            if len(endpoint) < 2:
                continue
            if len(endpoint) > 200:
                continue
            if " " in endpoint:
                continue
            if endpoint.startswith("//"):
                continue
            if "{{" in endpoint or "{%" in endpoint:
                continue

            # ✅ Build full URL if relative
            if endpoint.startswith("/"):
                parsed = urlparse(base_url)
                full = f"{parsed.scheme}://{parsed.netloc}{endpoint}"
                endpoints.add(full)
            elif endpoint.startswith("http"):
                # Only keep same domain
                parsed_base = urlparse(base_url)
                parsed_ep = urlparse(endpoint)
                if parsed_ep.netloc == parsed_base.netloc:
                    endpoints.add(endpoint)

    return list(endpoints)


def probe_endpoint(url):
    """
    Check if endpoint is alive and interesting
    Returns (status_code, content_type, interesting)
    """
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        ct = response.headers.get("Content-Type", "")

        interesting = (
            response.status_code in [200, 201, 401, 403, 405, 500] and
            not should_skip(url)
        )

        return response.status_code, ct, interesting, response

    except:
        return None, None, False, None


def check_endpoint_vulns(url, response):
    """Check discovered endpoint for quick wins"""
    if not response:
        return

    text = response.text.lower()
    ct = response.headers.get("Content-Type", "").lower()

    # ✅ API returning sensitive data without auth
    sensitive_patterns = [
        "password", "passwd", "secret", "api_key",
        "apikey", "token", "auth", "credential",
        "private_key", "access_key"
    ]

    if response.status_code == 200:
        for pattern in sensitive_patterns:
            if pattern in text:
                handle_vulnerability(
                    "Information Disclosure",
                    url,
                    parameter="api_endpoint",
                    payload=f"Endpoint exposes sensitive data: '{pattern}' found in response"
                )
                break

    # ✅ JSON API without auth (401/403 = good, 200 = potential issue)
    if "application/json" in ct and response.status_code == 200:
        if len(response.text) > 100:
            handle_vulnerability(
                "Information Disclosure",
                url,
                parameter="api_endpoint",
                payload=f"Unauthenticated API endpoint returns JSON data ({len(response.text)} bytes)"
            )

    # ✅ Admin endpoints accessible
    admin_paths = ["/admin", "/administrator", "/manage", "/dashboard", "/internal"]
    for path in admin_paths:
        if path in url.lower() and response.status_code == 200:
            handle_vulnerability(
                "Sensitive File Exposure",
                url,
                parameter="admin_endpoint",
                payload=f"Admin endpoint accessible without authentication: {path}"
            )
            break


def scan_js_endpoints(url):
    """Main function — find JS files, extract endpoints, probe them"""
    print(f"[JS] Scanning: {url}")

    discovered_endpoints = []

    try:
        # ── Step 1: Get the page HTML ──
        response = requests.get(url, timeout=5)
        html = response.text

        # ── Step 2: Find all JS files ──
        js_files = extract_js_files(url, html)
        print(f"[JS] Found {len(js_files)} JS files at {url}")

        # ── Step 3: Also check inline scripts ──
        soup = BeautifulSoup(html, "html.parser")
        inline_scripts = []
        for tag in soup.find_all("script"):
            if not tag.get("src") and tag.string:
                inline_scripts.append(tag.string)

        # ── Step 4: Extract endpoints from inline scripts ──
        for script in inline_scripts:
            endpoints = extract_endpoints_from_js(script, url)
            discovered_endpoints.extend(endpoints)

        # ── Step 5: Fetch and parse each JS file ──
        for js_url in js_files:
            try:
                js_response = requests.get(js_url, timeout=5)
                endpoints = extract_endpoints_from_js(js_response.text, url)
                discovered_endpoints.extend(endpoints)
                print(f"[JS] {js_url} → {len(endpoints)} endpoints found")
            except Exception as e:
                print(f"[JS ERROR] {js_url} → {e}")

        # ── Step 6: Deduplicate ──
        discovered_endpoints = list(set(discovered_endpoints))
        print(f"[JS] Total unique endpoints discovered: {len(discovered_endpoints)}")

        # ── Step 7: Probe each endpoint ──
        for endpoint in discovered_endpoints:
            status, ct, interesting, ep_response = probe_endpoint(endpoint)

            if interesting:
                print(f"[JS] 🔍 Endpoint alive [{status}]: {endpoint}")

                # ── Step 8: Check for vulns ──
                check_endpoint_vulns(endpoint, ep_response)

    except Exception as e:
        print(f"[JS SCAN ERROR] {url} → {e}")

    return discovered_endpoints