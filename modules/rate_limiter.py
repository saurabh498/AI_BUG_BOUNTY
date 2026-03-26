# modules/rate_limiter.py

import time
import threading

class RateLimiter:
    """
    Controls request rate to avoid overwhelming targets
    and getting blocked by WAFs/IDS
    """

    def __init__(self, delay=0.2):
        self.delay = delay
        self.lock = threading.Lock()
        self.last_request = 0

    def wait(self):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_request
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
            self.last_request = time.time()


# ✅ Global rate limiter instance — shared across all scanners
rate_limiter = RateLimiter(delay=0.15)