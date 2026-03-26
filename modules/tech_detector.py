# modules/tech_detector.py
import requests
from bs4 import BeautifulSoup
from core.intelligence import handle_vulnerability

TECH_SIGNATURES = {
    "WordPress": ["wp-content", "wp-includes", "wordpress"],
    "Joomla": ["joomla", "/components/com_"],
    "Drupal": ["drupal", "sites/default"],
    "Laravel": ["laravel_session", "X-Powered-By: PHP"],
    "Django": ["csrfmiddlewaretoken", "django"],
    "React": ["react", "__REACT_DEVTOOLS"],
    "Angular": ["ng-version", "angular"],
    "jQuery": ["jquery"],
    "Bootstrap": ["bootstrap"],
    "PHP": ["X-Powered-By: PHP", ".php"],
    "ASP.NET": ["X-Powered-By: ASP.NET", "viewstate"],
    "Apache": ["Apache", "Server: Apache"],
    "Nginx": ["nginx", "Server: nginx"],
    "IIS": ["IIS", "Server: Microsoft-IIS"],
    "MySQL": ["mysql", "MySQL"],
    "PostgreSQL": ["postgresql", "PostgreSQL"],
}

def detect_tech_stack(url):
    """Detect technologies used by the target"""
    print(f"[TECH] Detecting stack: {url}")
    detected = []

    try:
        response = requests.get(url, timeout=5)
        html = response.text.lower()
        headers = str(response.headers).lower()
        combined = html + headers

        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined:
                    detected.append(tech)
                    break

        # Check specific headers
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")
        generator = ""

        # Check meta generator tag
        soup = BeautifulSoup(response.text, "html.parser")
        meta = soup.find("meta", attrs={"name": "generator"})
        if meta:
            generator = meta.get("content", "")
            if generator:
                detected.append(f"CMS: {generator}")

        result = {
            "technologies": list(set(detected)),
            "server": server,
            "powered_by": powered_by,
            "generator": generator
        }

        print(f"[TECH] Detected: {', '.join(result['technologies'])}")

        # Report if server version disclosed
        if server and any(char.isdigit() for char in server):
            handle_vulnerability(
                "Information Disclosure",
                url,
                parameter="Server",
                payload=f"Server: {server}"
            )

        return result

    except Exception as e:
        print(f"[TECH ERROR] {e}")
        return {"technologies": [], "server": "", "powered_by": "", "generator": ""}