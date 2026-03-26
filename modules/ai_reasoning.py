# modules/ai_reasoning.py
import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

def explain_vulnerability(vuln_type, url, payload, parameter=None):
    """
    AI explains WHY a vulnerability exists and HOW to exploit it
    """
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    if not GROQ_API_KEY:
        return None

    prompt = f"""You are an expert penetration tester. Analyze this vulnerability and explain it clearly.

Vulnerability Type: {vuln_type}
URL: {url}
Payload Used: {payload}
Parameter: {parameter or 'auto-detected'}

Provide a JSON response with exactly these fields:
{{
    "why_it_exists": "explanation of root cause in 2-3 sentences",
    "entry_point": "where the vulnerability was found",
    "technical_explanation": "technical details in 3-4 sentences",
    "db_guess": "if SQLi, guess the database type and structure",
    "data_at_risk": "what sensitive data could be extracted",
    "fix_code": "code snippet showing the fix",
    "fix_explanation": "explanation of the fix in 1-2 sentences",
    "severity_reasoning": "why this severity level was assigned"
}}

Respond ONLY with valid JSON. No markdown, no extra text."""

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1000,
                "temperature": 0.2
            },
            timeout=30
        )

        data = response.json()
        if "choices" in data:
            text = data["choices"][0]["message"]["content"]
            # Clean JSON
            text = text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
    except Exception as e:
        print(f"[AI REASONING ERROR] {e}")
    return None