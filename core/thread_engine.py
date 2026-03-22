from concurrent.futures import ThreadPoolExecutor, as_completed
import time

def run_multithreaded_scan(urls, scan_function, threads=10):

    print(f"\n[THREAD ENGINE] Running {scan_function.__name__} with {threads} threads")

    results = []
    success = 0
    failed = 0

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(scan_function, url): url for url in urls}

        for future in as_completed(future_to_url):
            url = future_to_url[future]

            try:
                result = future.result()
                results.append(result)
                success += 1

            except Exception as e:
                print(f"[ERROR] {url} -> {e}")
                failed += 1

    end_time = time.time()

    print("\n[THREAD REPORT]")
    print(f"✔ Success: {success}")
    print(f"❌ Failed: {failed}")
    print(f"⏱ Time Taken: {round(end_time - start_time, 2)} sec")

    return results