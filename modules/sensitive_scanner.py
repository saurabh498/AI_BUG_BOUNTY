# modules/sensitive_scanner.py

import requests
from core.intelligence import handle_vulnerability

# ✅ Sensitive files to check with their risk level
SENSITIVE_FILES = {
    # Environment & Config
    "/.env":                  ("CRITICAL", "Environment file exposes credentials/API keys"),
    "/.env.backup":           ("CRITICAL", "Backup environment file exposes credentials"),
    "/.env.local":            ("CRITICAL", "Local environment file exposes credentials"),
    "/config.php":            ("HIGH",     "PHP config file may expose DB credentials"),
    "/config.yml":            ("HIGH",     "YAML config file may expose credentials"),
    "/config.json":           ("HIGH",     "JSON config file may expose credentials"),
    "/configuration.php":     ("HIGH",     "Configuration file may expose credentials"),
    "/settings.py":           ("HIGH",     "Python settings file may expose credentials"),
    "/wp-config.php":         ("CRITICAL", "WordPress config exposes DB credentials"),

    # Git & Version Control
    "/.git/HEAD":             ("HIGH",     "Git repository exposed — source code leak"),
    "/.git/config":           ("HIGH",     "Git config exposes repository details"),
    "/.svn/entries":          ("HIGH",     "SVN repository exposed"),

    # Backup Files
    "/backup.zip":            ("HIGH",     "Backup archive may contain sensitive data"),
    "/backup.sql":            ("CRITICAL", "SQL backup exposes full database"),
    "/backup.tar.gz":         ("HIGH",     "Backup archive may contain sensitive data"),
    "/db.sql":                ("CRITICAL", "Database dump exposed"),
    "/database.sql":          ("CRITICAL", "Database dump exposed"),
    "/dump.sql":              ("CRITICAL", "Database dump exposed"),

    # Log Files
    "/error.log":             ("MEDIUM",   "Error log may expose internal paths/errors"),
    "/access.log":            ("MEDIUM",   "Access log exposes user activity"),
    "/debug.log":             ("MEDIUM",   "Debug log may expose sensitive info"),
    "/laravel.log":           ("MEDIUM",   "Laravel log exposes app internals"),

    # Admin & Sensitive Paths
    "/admin":                 ("MEDIUM",   "Admin panel exposed"),
    "/admin/":                ("MEDIUM",   "Admin panel exposed"),
    "/phpmyadmin":            ("HIGH",     "phpMyAdmin panel exposed"),
    "/phpmyadmin/":           ("HIGH",     "phpMyAdmin panel exposed"),
    "/.htaccess":             ("MEDIUM",   "Apache config file exposed"),
    "/.htpasswd":             ("HIGH",     "Password file exposed"),
    "/server-status":         ("MEDIUM",   "Apache server status exposed"),
    "/server-info":           ("MEDIUM",   "Apache server info exposed"),

    # Common Info Files
    "/robots.txt":            ("LOW",      "Robots.txt may reveal hidden paths"),
    "/sitemap.xml":           ("LOW",      "Sitemap reveals all site paths"),
    "/crossdomain.xml":       ("LOW",      "Crossdomain policy may be overly permissive"),
    "/.DS_Store":             ("MEDIUM",   "Mac DS_Store exposes directory structure"),
    "/Thumbs.db":             ("LOW",      "Windows Thumbs.db exposes file listing"),

    # API & Keys
    "/api/v1/users":          ("HIGH",     "User API endpoint exposed"),
    "/api/keys":              ("CRITICAL", "API keys endpoint exposed"),
    "/.aws/credentials":      ("CRITICAL", "AWS credentials exposed"),
    "/id_rsa":                ("CRITICAL", "Private SSH key exposed"),
    "/id_rsa.pub":            ("HIGH",     "Public SSH key exposed"),
}

# ✅ Content signatures that confirm a real finding
CONFIRMATION_SIGNATURES = {
    "/.env":              ["APP_KEY", "DB_PASSWORD", "SECRET", "API_KEY", "TOKEN"],
    "/.git/HEAD":         ["ref:", "refs/heads"],
    "/config.php":        ["<?php", "define(", "DB_"],
    "/wp-config.php":     ["DB_NAME", "DB_USER", "DB_PASSWORD"],
    "/backup.sql":        ["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
    "/database.sql":      ["INSERT INTO", "CREATE TABLE"],
    "/dump.sql":          ["INSERT INTO", "CREATE TABLE"],
    "/.htpasswd":         [":$apr1$", ":$2y$", ":{SHA}"],
    "/.aws/credentials":  ["aws_access_key_id", "aws_secret_access_key"],
    "/id_rsa":            ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"],
}

def confirm_finding(path, response_text):
    """Double-check findings using content signatures to reduce false positives"""
    if path not in CONFIRMATION_SIGNATURES:
        return True  # no signature needed, status code is enough
    signatures = CONFIRMATION_SIGNATURES[path]
    return any(sig.lower() in response_text.lower() for sig in signatures)

def scan_sensitive_files(base_url):
    print(f"[SENSITIVE] Scanning: {base_url}")

    base_url = base_url.rstrip("/")

    for path, (risk, description) in SENSITIVE_FILES.items():
        url = base_url + path

        try:
            response = requests.get(url, timeout=5, allow_redirects=False)

            # ✅ Only flag 200 responses (not redirects or errors)
            if response.status_code == 200:

                # ✅ Confirm using content signatures
                if confirm_finding(path, response.text):
                    print(f"[!!!] Sensitive File Found ({risk}): {url}")
                    handle_vulnerability(
                        "Sensitive File Exposure",
                        url,
                        parameter=path,
                        payload=description
                    )

            # ✅ Also flag 403 for admin paths (exists but forbidden)
            elif response.status_code == 403 and path in ["/admin", "/admin/", "/phpmyadmin", "/phpmyadmin/"]:
                print(f"[!!!] Restricted Path Found (403): {url}")
                handle_vulnerability(
                    "Directory Exposure",
                    url,
                    parameter=path,
                    payload=f"Path exists but access forbidden: {path}"
                )

        except Exception as e:
            print(f"[SENSITIVE ERROR] {url} -> {e}")