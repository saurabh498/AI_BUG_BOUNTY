# core/storage.py

import threading

vulnerabilities = []
lock = threading.Lock()
scan_status = "idle"
scan_progress = 0
scan_phase = "idle"

def add_vuln(v):
    with lock:
        if v not in vulnerabilities:
            vulnerabilities.append(v)

def clear_vulns():
    with lock:
        vulnerabilities.clear()

def set_status(status):
    with lock:
        global scan_status
        scan_status = status

def get_status():
    with lock:
        return scan_status

def set_progress(p, phase=None):
    with lock:
        global scan_progress, scan_phase
        scan_progress = p
        if phase:
            scan_phase = phase

def get_progress():
    with lock:
        return scan_progress, scan_phase

def get_risk_score():
    with lock:
        score = 0
        for v in vulnerabilities:
            if v["severity"] in ["HIGH", "CRITICAL"]:
                score += 10
            elif v["severity"] == "MEDIUM":
                score += 5
            elif v["severity"] == "LOW":
                score += 2
        # Cap at 100
        score = min(score, 100)

        if score >= 70:
            label = "CRITICAL RISK"
            color = "#7f1d1d"
        elif score >= 40:
            label = "HIGH RISK"
            color = "#ef4444"
        elif score >= 20:
            label = "MEDIUM RISK"
            color = "#facc15"
        else:
            label = "LOW RISK"
            color = "#22c55e"

        return score, label, color        