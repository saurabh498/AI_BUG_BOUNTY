# modules/auth_scanner.py
# ⚠️ For authorized security testing only

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from core.intelligence import handle_vulnerability

# ✅ Most common weak/default credentials
# Source: OWASP, default vendor credentials, common misconfigs
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", ""),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("test", "password"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("demo", "demo"),
    ("support", "support"),
]

# ✅ Success indicators in response
SUCCESS_INDICATORS = [
    "dashboard", "welcome", "logout", "sign out",
    "my account", "my profile", "logged in",
    "successfully", "hello,", "hi,", "profile"
]

# ✅ Failure indicators
FAILURE_INDICATORS = [
    "invalid", "incorrect", "wrong", "failed",
    "error", "denied", "unauthorized", "try again",
    "bad credentials", "login failed"
]


def find_login_form(url):
    """Find login form on page"""
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for form in soup.find_all("form"):
            inputs = form.find_all("input")
            has_user = False
            has_pass = False

            for inp in inputs:
                name = inp.get("name", "").lower()
                inp_type = inp.get("type", "").lower()
                if any(k in name for k in ["user", "email", "login", "name"]):
                    has_user = True
                if "pass" in name or inp_type == "password":
                    has_pass = True

            if has_user and has_pass:
                return form, response.text

    except Exception as e:
        print(f"[AUTH ERROR] {url} -> {e}")

    return None, None


def build_form_data(form, username, password):
    """Build POST data from form fields"""
    data = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        inp_type = inp.get("type", "").lower()
        name_lower = name.lower()

        if any(k in name_lower for k in ["user", "email", "login", "name"]):
            data[name] = username
        elif "pass" in name_lower or inp_type == "password":
            data[name] = password
        elif inp_type == "hidden":
            data[name] = inp.get("value", "")
        else:
            data[name] = inp.get("value", "test")

    return data


def check_login_success(response_text, original_text):
    """
    Determine if login was successful using multiple signals
    """
    text = response_text.lower()
    original = original_text.lower()

    # ✅ Check success indicators
    success = any(s in text for s in SUCCESS_INDICATORS)

    # ✅ Check failure indicators
    failure = any(f in text for f in FAILURE_INDICATORS)

    # ✅ Check response length change
    # Successful login often changes page significantly
    length_change = abs(len(response_text) - len(original_text))
    significant_change = length_change > 500

    if success and not failure:
        return True, "success_indicator"
    if significant_change and not failure:
        return True, "page_changed"

    return False, None


def scan_default_credentials(url):
    """
    Test login form for default/weak credentials
    """
    print(f"[AUTH] Testing default credentials: {url}")

    form, original_text = find_login_form(url)

    if not form:
        print(f"[AUTH] No login form found at {url}")
        return

    action = form.get("action")
    if not action:
        action = url
    else:
        action = urljoin(url, action)

    method = form.get("method", "post").lower()

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    print(f"[AUTH] Form found → testing {len(DEFAULT_CREDENTIALS)} credential pairs")

    for username, password in DEFAULT_CREDENTIALS:
        try:
            data = build_form_data(form, username, password)

            if method == "post":
                response = requests.post(
                    action, data=data,
                    headers=headers,
                    timeout=5,
                    allow_redirects=True
                )
            else:
                response = requests.get(
                    action, params=data,
                    headers=headers,
                    timeout=5,
                    allow_redirects=True
                )

            success, reason = check_login_success(response.text, original_text)

            if success:
                cred_display = f"{username}:{password if password else '(empty)'}"
                print(f"\n[!!!] Weak Credentials Found: {cred_display}")
                print(f"      URL: {action}")
                print(f"      Reason: {reason}")

                handle_vulnerability(
                    "Weak Credentials",
                    action,
                    parameter="login",
                    payload=cred_display
                )
                # ✅ Stop after first successful find per form
                return

        except Exception as e:
            print(f"[AUTH ERROR] {username}:{password} -> {e}")

    print(f"[AUTH] No weak credentials found at {url}")