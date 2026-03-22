from core.report import report_vulnerability

def classify_vulnerability(vuln_type):
    severity_map = {
        "XSS": ("HIGH", 8.2),
        "SQL Injection": ("CRITICAL", 9.8),
        "Directory Exposure": ("MEDIUM", 5.3),
        "Information Disclosure": ("LOW", 3.1),
        "Login Bypass (SQLi)": ("CRITICAL", 9.5),
        "Open Redirect": ("MEDIUM", 5.0),          # ✅
        "Sensitive File Exposure": ("HIGH", 7.5),
        "Missing Header: Content-Security-Policy":  ("HIGH", 7.5),
        "Missing Header: Strict-Transport-Security":("MEDIUM", 5.0),
        "Missing Header: X-Frame-Options":          ("MEDIUM", 4.5),
        "Missing Header: X-Content-Type-Options":   ("LOW", 3.0),
        "Missing Header: Referrer-Policy":          ("LOW", 2.5),
        "Missing Header: Permissions-Policy":       ("LOW", 2.0),
    }
    return severity_map.get(vuln_type, ("MEDIUM", 5.0))


def handle_vulnerability(vuln_type, url, parameter=None, payload=None):
    severity, score = classify_vulnerability(vuln_type)

    print("\n==============================")
    print(" VULNERABILITY DETECTED")
    print("==============================")
    print("Type:", vuln_type)
    print("Severity:", severity)
    print("CVSS Score:", score)
    print("URL:", url)

    if parameter:
        print("Parameter:", parameter)

    if payload:
        print("Payload:", payload)

    print("==============================\n")

    report_vulnerability(
        vuln_type,
        url,
        parameter or "",
        payload or "",
        severity,
        score
    )