"""Sensitive-data exfiltration checks: plain-text markers and base64-encoded secrets."""

import base64
import re

SENSITIVE_MARKERS = ["token", "password", "secret code", "account_number", "api_key"]
KNOWN_ID_PREFIXES = ("case-", "cu-", "acc-", "ben-", "pay-", "cd-", "fp-", "ne-", "ct-")
SINK_TOOLS = {"email_send", "case_note_create"}


def contains_encoded_secret(text: str) -> bool:
    """Detect base64-looking substrings that decode to something suspicious."""
    candidates = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text)
    for cand in candidates:
        try:
            decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore")
            if any(m in decoded.lower() for m in ["token", "password", "secret"]):
                return True
        except Exception:
            continue
    return False


def has_secret_like_value(arg_text: str) -> bool:
    candidate_tokens = re.findall(r"[a-z0-9_-]{10,}", arg_text)
    return any(
        re.search(r"[0-9]", tok) and re.search(r"[a-z]", tok) and not tok.startswith(KNOWN_ID_PREFIXES)
        for tok in candidate_tokens
    )


def has_sensitive_marker(arg_text: str) -> bool:
    return any(m in arg_text for m in SENSITIVE_MARKERS)
