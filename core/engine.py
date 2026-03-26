from concurrent.futures import ThreadPoolExecutor
from modules.sqli_scanner import scan_sqli
from modules.xss_scanner import scan_xss
from modules.fuzzer import fuzz_parameters


def scan_url(url):
    try:
        scan_sqli(url)
        scan_xss(url)
        fuzz_parameters(url)
    except:
        pass


def start_threaded_scan(urls, threads=10):

    print("\n[Multithreaded Scan Engine Started]")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(scan_url, urls)

    print("\n[Multithreaded Scan Completed]")