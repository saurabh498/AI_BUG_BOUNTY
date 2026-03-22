from urllib.parse import urlparse, parse_qs

def extract_parameters(urls):

    params = {}

    for url in urls:

        parsed = urlparse(url)

        query = parse_qs(parsed.query)

        if query:
            params[url] = query

    return params