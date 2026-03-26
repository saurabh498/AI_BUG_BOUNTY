import requests
from core.payloads import DIR_WORDLIST

def scan_directories(base_url):

    for word in DIR_WORDLIST:

        url = f"{base_url}/{word}"

        try:
            response = requests.get(url, timeout=5)

            if response.status_code in [200, 301, 302, 403]:
                print("[DIR FOUND]", url)

        except Exception as e:
            print("[DIR ERROR]", e)