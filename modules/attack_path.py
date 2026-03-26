# modules/attack_path.py
# Builds attack path graph from scan findings

from core.storage import vulnerabilities


# ✅ Attack chain definitions
# Each chain shows how vulns connect to form attack paths
ATTACK_CHAINS = {
    "Full Database Compromise": {
        "required": ["SQL Injection"],
        "steps": [
            "SQL Injection found",
            "Extract database version: ' UNION SELECT @@version--",
            "Enumerate databases and tables",
            "Dump user credentials",
            "Crack password hashes offline",
            "Login with stolen credentials",
            "Full system compromise"
        ],
        "severity": "CRITICAL",
        "impact": "Complete database access, credential theft, potential RCE"
    },

    "Authentication Bypass Chain": {
        "required": ["Login Bypass (SQLi)"],
        "steps": [
            "Login bypass via SQLi found",
            "Access admin panel without credentials",
            "Enumerate admin functionality",
            "Look for file upload → RCE",
            "Extract all user data",
            "Privilege escalation"
        ],
        "severity": "CRITICAL",
        "impact": "Full admin access, account takeover, data breach"
    },

    "Session Hijacking Chain": {
        "required": ["XSS", "Missing Header: Content-Security-Policy"],
        "steps": [
            "XSS vulnerability found",
            "No CSP header to block script execution",
            "Inject cookie stealer payload",
            "Steal admin session cookie",
            "Hijack admin session",
            "Full account takeover"
        ],
        "severity": "HIGH",
        "impact": "Admin session theft, account takeover"
    },

    "Credential Exposure Chain": {
        "required": ["Sensitive File Exposure"],
        "steps": [
            "Sensitive file exposed (.env / config)",
            "Extract database credentials",
            "Extract API keys and secrets",
            "Access connected services",
            "Lateral movement to other systems"
        ],
        "severity": "CRITICAL",
        "impact": "Full credential exposure, lateral movement"
    },

    "Source Code Exposure Chain": {
        "required": ["Sensitive File Exposure"],
        "steps": [
            ".git repository exposed",
            "Download full source code: git-dumper",
            "Find hardcoded credentials in code",
            "Discover hidden endpoints",
            "Find encryption keys and secrets",
            "Full application compromise"
        ],
        "severity": "HIGH",
        "impact": "Source code theft, hardcoded secret exposure"
    },

    "Weak Credentials Chain": {
        "required": ["Weak Credentials"],
        "steps": [
            "Default credentials found (admin:admin)",
            "Login to application",
            "Access admin panel",
            "Enumerate privileged functionality",
            "Extract user database",
            "Full account takeover"
        ],
        "severity": "CRITICAL",
        "impact": "Full admin access, data breach"
    },

    "Information Gathering Chain": {
        "required": [
            "Missing Header: Content-Security-Policy",
            "Missing Header: X-Frame-Options",
            "Information Disclosure"
        ],
        "steps": [
            "Multiple security headers missing",
            "Server version disclosed",
            "Search CVE database for version exploits",
            "Clickjacking possible via missing X-Frame-Options",
            "XSS amplified by missing CSP",
            "Combined attack surface identified"
        ],
        "severity": "MEDIUM",
        "impact": "Technology fingerprinting, targeted attacks"
    },

    "Open Redirect Phishing Chain": {
        "required": ["Open Redirect"],
        "steps": [
            "Open redirect found",
            "Craft phishing URL using trusted domain",
            "Send to victims: trusted.com/redirect?url=evil.com",
            "Victim lands on cloned login page",
            "Steal credentials",
            "Account takeover"
        ],
        "severity": "HIGH",
        "impact": "Phishing attacks using trusted domain"
    }
}


def build_attack_paths():
    """
    Analyze current vulnerabilities and build
    relevant attack paths
    """
    if not vulnerabilities:
        return []

    # ✅ Get unique vuln types found
    found_types = set(v.get("type", "") for v in vulnerabilities)

    active_paths = []

    for chain_name, chain in ATTACK_CHAINS.items():
        required = chain["required"]

        # ✅ Check if ANY required vuln is present
        matched = []
        missing = []

        for req in required:
            # Check partial match too (e.g "Missing Header" matches any header finding)
            found = any(
                req.lower() in ft.lower() or ft.lower() in req.lower()
                for ft in found_types
            )
            if found:
                matched.append(req)
            else:
                missing.append(req)

        # ✅ Include chain if at least one required vuln found
        if matched:
            # Find actual vuln URLs for this chain
            relevant_vulns = []
            for req in matched:
                for v in vulnerabilities:
                    if req.lower() in v.get("type", "").lower() or \
                       v.get("type", "").lower() in req.lower():
                        relevant_vulns.append(v)
                        break

            completeness = len(matched) / len(required) * 100

            active_paths.append({
                "name": chain_name,
                "severity": chain["severity"],
                "steps": chain["steps"],
                "impact": chain["impact"],
                "matched_vulns": matched,
                "missing_vulns": missing,
                "completeness": round(completeness),
                "relevant_urls": [v.get("url", "") for v in relevant_vulns[:3]],
                "fully_exploitable": len(missing) == 0
            })

    # ✅ Sort by severity then completeness
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    active_paths.sort(
        key=lambda x: (
            severity_order.get(x["severity"], 4),
            -x["completeness"]
        )
    )

    return active_paths


def format_attack_paths_terminal(paths):
    """Format attack paths for terminal output"""
    if not paths:
        return "\n[ATTACK PATH] No attack chains identified\n"

    lines = []
    lines.append("\n" + "="*60)
    lines.append("🗺️  ATTACK PATH INTELLIGENCE")
    lines.append("="*60)

    for i, path in enumerate(paths, 1):
        status = "🔴 FULLY EXPLOITABLE" if path["fully_exploitable"] \
                 else f"🟡 {path['completeness']}% COMPLETE"

        lines.append(f"\n[{i}] {path['name']}")
        lines.append(f"    Severity: {path['severity']} | {status}")
        lines.append(f"    Impact: {path['impact']}")
        lines.append(f"    Attack Steps:")
        for j, step in enumerate(path["steps"], 1):
            lines.append(f"      {j}. {step}")
        if path["relevant_urls"]:
            lines.append(f"    Starting Points:")
            for url in path["relevant_urls"]:
                lines.append(f"      → {url}")

    lines.append("\n" + "="*60)
    return "\n".join(lines)