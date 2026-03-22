# core/report.py

import os
from datetime import datetime
import json
from core.storage import add_vuln, vulnerabilities

scan_stats = {
    "target": "",
    "urls": 0,
    "parameters": 0
}

def update_scan_stats(target=None, urls=None, parameters=None):
    if target:
        scan_stats["target"] = target
    if urls is not None:
        scan_stats["urls"] = urls
    if parameters is not None:
        scan_stats["parameters"] = parameters

def report_vulnerability(vtype, url, parameter="", payload="",
                         severity="MEDIUM", score=5.0, poc=None):
    from modules.exploit_suggester import get_suggestions

    vuln = {
        "type": vtype,
        "url": url,
        "parameter": parameter,
        "payload": payload,
        "severity": severity,
        "score": score,
        "suggestions": get_suggestions(vtype),
        "poc": poc  # ✅ Store PoC
    }

    # dedup check without poc and suggestions
    vuln_check = {k: v for k, v in vuln.items()
                  if k not in ["suggestions", "poc"]}
    for v in vulnerabilities:
        v_check = {k: val for k, val in v.items()
                   if k not in ["suggestions", "poc"]}
        if v_check == vuln_check:
            return

    add_vuln(vuln)

def generate_report():
    os.makedirs("templates", exist_ok=True)
    total_vulns = len(vulnerabilities)

    risk = "LOW"
    if total_vulns > 5:
        risk = "HIGH"
    elif total_vulns > 2:
        risk = "MEDIUM"

    with open("templates/scan_report.html", "w") as f:
        f.write("<html><body style='background:#0f172a;color:white;font-family:Arial'>")
        f.write(f"<h1>Scan Report</h1><p>{datetime.now()}</p>")
        f.write(f"<p>Target: {scan_stats['target']}</p>")
        f.write(f"<p>Total: {total_vulns} | Risk: {risk}</p>")
        f.write("<table border='1' style='width:100%;border-collapse:collapse'>")
        f.write("<tr><th>Type</th><th>Severity</th><th>URL</th><th>Payload</th></tr>")
        for v in vulnerabilities:
            f.write(f"<tr><td>{v['type']}</td><td>{v['severity']}</td>"
                    f"<td>{v['url']}</td><td>{v['payload']}</td></tr>")
        f.write("</table>")
        f.write("</body></html>")

    print("[✔] Report generated")

def save_scan_history(user_id=None):
    from auth.database import save_scan_for_user
    from core.storage import get_risk_score
    from datetime import datetime

    score, label, color = get_risk_score()

    save_scan_for_user(
        user_id=user_id,
        target=scan_stats["target"],
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(vulnerabilities),
        risk_score=score,
        risk_label=label,
        risk_color=color,
        vulnerabilities=list(vulnerabilities)
    )
    print("[✔] Scan saved for user:", user_id)