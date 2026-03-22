# modules/header_scanner.py

import requests
from core.intelligence import handle_vulnerability

# ✅ Headers we check and their severity
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "score": 7.5,
        "description": "Missing CSP allows XSS attacks"
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "score": 5.0,
        "description": "Missing HSTS allows downgrade attacks"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "score": 4.5,
        "description": "Missing X-Frame-Options allows clickjacking"
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "score": 3.0,
        "description": "Missing X-Content-Type-Options allows MIME sniffing"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "score": 2.5,
        "description": "Missing Referrer-Policy leaks sensitive URLs"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "score": 2.0,
        "description": "Missing Permissions-Policy exposes browser features"
    }
}

def scan_headers(url):
    print(f"[HEADERS] Scanning: {url}")

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        for header, info in SECURITY_HEADERS.items():
            if header not in headers:
                print(f"[!!!] Missing Header: {header} on {url}")
                handle_vulnerability(
                    f"Missing Header: {header}",
                    url,
                    parameter=header,
                    payload=info["description"]
                )

        # ✅ BONUS: check for server version disclosure
        server = headers.get("Server", "")
        x_powered = headers.get("X-Powered-By", "")

        if server and any(char.isdigit() for char in server):
            handle_vulnerability(
                "Information Disclosure",
                url,
                parameter="Server",
                payload=f"Server header reveals version: {server}"
            )

        if x_powered:
            handle_vulnerability(
                "Information Disclosure",
                url,
                parameter="X-Powered-By",
                payload=f"X-Powered-By reveals tech: {x_powered}"
            )

    except Exception as e:
        print(f"[HEADERS ERROR] {url} -> {e}")