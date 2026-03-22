# core/ai_payloads.py

from core.payloads import SQLI_PAYLOADS, XSS_PAYLOADS
from ai.payload_generator import generate_payloads


def get_sqli_payloads():
    return generate_payloads(SQLI_PAYLOADS)


def get_xss_payloads():
    return generate_payloads(XSS_PAYLOADS)