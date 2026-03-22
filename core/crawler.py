# core/crawler.py

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

visited_urls = set()

def crawl(base_url):
    urls = []

    try:
        response = requests.get(base_url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for link in soup.find_all("a"):
            href = link.get("href")
            if not href:
                continue
            if href.startswith("javascript"):
                continue

            full_url = urljoin(base_url, href)

            if urlparse(full_url).netloc != urlparse(base_url).netloc:
                continue

            if full_url not in visited_urls:
                visited_urls.add(full_url)
                urls.append(full_url)

        # ✅ NEW — also grab URLs from form actions
        for form in soup.find_all("form"):
            action = form.get("action")
            if action:
                full_url = urljoin(base_url, action)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    if full_url not in visited_urls:
                        visited_urls.add(full_url)
                        urls.append(full_url)

        # ✅ NEW — grab src attributes (iframes, embeds)
        for tag in soup.find_all(["iframe", "embed", "frame"]):
            src = tag.get("src")
            if src:
                full_url = urljoin(base_url, src)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    if full_url not in visited_urls:
                        visited_urls.add(full_url)
                        urls.append(full_url)

    except:
        pass

    return urls