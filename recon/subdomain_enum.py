# recon/subdomain_enum.py

import subprocess
import os

def find_subdomains(domain):
    print("[*] Running Sublist3r...")

    if not os.path.exists("Sublist3r/sublist3r.py"):
        print("[!] Sublist3r not found. Skipping subdomain enum.")
        return []

    try:
        result = subprocess.run(
            ["python3", "Sublist3r/sublist3r.py", "-d", domain],
            capture_output=True,
            text=True,
            timeout=60
        )

        print(result.stdout)

        # Filter out banner lines, keep only actual subdomains
        subdomains = [
            s.strip() for s in result.stdout.split("\n")
            if s.strip() and "." in s and not s.startswith("[")
        ]

        print(f"[*] Found {len(subdomains)} subdomains")
        return subdomains

    except subprocess.TimeoutExpired:
        print("[!] Sublist3r timed out after 60 seconds")
        return []

    except Exception as e:
        print(f"[!] Subdomain scan failed: {e}")
        return []