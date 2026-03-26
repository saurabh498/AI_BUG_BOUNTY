# modules/report_writer.py

import json
import requests
import os
from dotenv import load_dotenv

# ✅ Load .env here too — don't rely on dashboard.py
load_dotenv()


def call_ai(prompt, max_tokens=4000):
    """Call Groq API — completely free"""

    # ✅ Read key fresh every call — not at module load time
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")

    if not GROQ_API_KEY:
        return "❌ Error: GROQ_API_KEY not set in .env file"

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a professional penetration tester and bug bounty hunter writing detailed security reports."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "max_tokens": max_tokens,
                "temperature": 0.3
            },
            timeout=60
        )

        data = response.json()

        if "choices" in data and len(data["choices"]) > 0:
            return data["choices"][0]["message"]["content"]
        elif "error" in data:
            return f"❌ API Error: {data['error']['message']}"
        else:
            return "❌ No response from API"

    except requests.exceptions.Timeout:
        return "❌ Request timed out — try again"
    except Exception as e:
        return f"❌ Error: {e}"


def generate_ai_report(vulnerabilities, target, risk_score, risk_label):
    """Generate full security report"""

    if not vulnerabilities:
        return "No vulnerabilities found to report."

    vuln_summary = []
    for v in vulnerabilities:
        vuln_summary.append({
            "type": v.get("type", ""),
            "severity": v.get("severity", ""),
            "url": v.get("url", ""),
            "payload": v.get("payload", ""),
            "score": v.get("score", 0)
        })

    prompt = f"""You are a professional bug bounty hunter writing a vulnerability report.

Target: {target}
Overall Risk Score: {risk_score}/100 ({risk_label})
Total Vulnerabilities Found: {len(vulnerabilities)}

Vulnerabilities discovered:
{json.dumps(vuln_summary, indent=2)}

Write a professional bug bounty report with these exact sections:

1. EXECUTIVE SUMMARY
   - Brief overview of findings (2-3 sentences)
   - Overall risk assessment

2. VULNERABILITY DETAILS
   For each CRITICAL and HIGH vulnerability write:
   - Title
   - Severity + CVSS Score
   - Affected URL
   - Description (what it is and why it matters)
   - Steps to Reproduce (numbered steps)
   - Impact (what attacker can do)
   - Proof of Concept (the payload used)
   - Recommended Fix

3. ADDITIONAL FINDINGS
   - List MEDIUM and LOW findings briefly

4. REMEDIATION PRIORITY
   - Prioritized fix list

5. CONCLUSION
   - Final recommendation

Write in professional bug bounty style.
Be specific, technical, and clear.
Use the actual URLs and payloads provided."""

    return call_ai(prompt, max_tokens=4000)


def generate_hackerone_report(vuln, target):
    """Generate single HackerOne format report"""

    prompt = f"""Write a HackerOne bug bounty report for this vulnerability:

Type: {vuln.get('type', '')}
Severity: {vuln.get('severity', '')}
CVSS: {vuln.get('score', 0)}
Target: {target}
URL: {vuln.get('url', '')}
Payload: {vuln.get('payload', '')}

Write in EXACT HackerOne submission format:

**Vulnerability Title:**
[One clear descriptive title]

**Severity:** {vuln.get('severity', '')} (CVSS {vuln.get('score', 0)})

**Summary:**
[2-3 sentence description]

**Description:**
[Detailed technical description]

**Steps To Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Proof of Concept:**
[The actual payload/curl command]

**Impact:**
[What an attacker can do]

**Affected Assets:**
[The URL/endpoint affected]

**Recommended Fix:**
[Specific technical remediation]

**References:**
[OWASP or CVE references]

Be technical, specific, and use the actual URL and payload provided."""

    return call_ai(prompt, max_tokens=2000)