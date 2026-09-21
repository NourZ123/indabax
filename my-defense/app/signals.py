"""Shared, deterministic text primitives used by injection and information-flow checks.

Kept intentionally small: normalization, a bounded set of encodings (plain / base64 / hex /
reversed / spaced-out), and a short verb -> tool-category map for natural-language injection
detection. No ML, no arbitrary recursive decoding.
"""

from __future__ import annotations

import base64
import re

MAX_HAYSTACK_CHARS = 8_000
MAX_TOKEN_CHARS = 512
MIN_VALUE_CHARS = 6

_MARKER_WORDS = ("token", "password", "secret", "api_key", "apikey", "credential")


def normalize(text: str) -> str:
    return " ".join(text.lower().split())


def _bounded(text: str) -> str:
    return text[:MAX_HAYSTACK_CHARS]


def _despaced(text: str) -> str:
    return re.sub(r"\s+", "", text)


def find_value(value: str, haystack: str) -> str | None:
    """Look for `value` in `haystack` as plain text or one bounded encoding.

    Returns the encoding name matched ("plain", "base64", "hex", "reversed", "spaced") or
    None. `value` must be reasonably distinctive (short IDs are not worth this check).
    """
    if not value or len(value) < MIN_VALUE_CHARS or len(value) > MAX_TOKEN_CHARS:
        return None
    hay = _bounded(haystack)
    hay_lower = hay.lower()
    needle = value.lower()

    if needle in hay_lower:
        return "plain"
    if needle[::-1] in hay_lower:
        return "reversed"
    try:
        if base64.b64encode(value.encode("utf-8")).decode("ascii").lower() in hay_lower:
            return "base64"
    except Exception:
        pass
    try:
        if value.encode("utf-8").hex() in hay_lower:
            return "hex"
    except Exception:
        pass
    if needle in _despaced(hay_lower):
        return "spaced"
    return None


def contains_encoded_secret_marker(text: str) -> bool:
    """Generic (no known value) detection: candidate tokens that decode to something
    mentioning a secret-ish marker word, via base64 or hex. Bounded to plausible token sizes.
    """
    hay = _bounded(text)
    for cand in re.findall(r"[A-Za-z0-9+/]{16,256}={0,2}", hay):
        try:
            decoded = base64.b64decode(cand, validate=True).decode("utf-8", errors="ignore").lower()
            if any(m in decoded for m in _MARKER_WORDS):
                return True
        except Exception:
            pass
    for cand in re.findall(r"[0-9a-fA-F]{32,256}", hay):
        if len(cand) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(cand).decode("utf-8", errors="ignore").lower()
            if any(m in decoded for m in _MARKER_WORDS):
                return True
        except Exception:
            pass
    reversed_hay = hay[::-1].lower()
    if any(m in reversed_hay for m in _MARKER_WORDS):
        return True
    return False


# Natural-language verb/phrase -> generic tool category. Deliberately small and transparent;
# a match here is only ever combined with other evidence (argument origin, provenance, impact).
CONTROL_VERBS = frozenset(
    {
        "send", "forward", "email", "transfer", "execute", "close", "disable",
        "retrieve", "fetch", "call", "open", "remember", "store", "ignore",
        "override", "approved", "authorization", "authorize", "policy update",
        "confirm", "grant", "share",
    }
)

VERB_TO_CATEGORY: dict[str, str] = {
    "send": "email_out",
    "forward": "email_out",
    "email": "email_out",
    "share": "email_out",
    "transfer": "payment",
    "confirm": "payment",
    "execute": "payment_or_remediation",
    "approve": "payment",
    "approved": "payment",
    "authorize": "payment",
    "authorization": "payment",
    "close": "state_change",
    "resolve": "state_change",
    "disable": "remediation",
    "isolate": "remediation",
    "reset": "remediation",
    "block": "remediation",
    "remember": "memory",
    "store": "memory",
    "retrieve": "read",
    "fetch": "read",
    "call": "generic_tool",
    "open": "incident",
    "ignore": "override",
    "override": "override",
}


def control_language_hits(text: str) -> set[str]:
    hay = normalize(text)
    return {verb for verb in CONTROL_VERBS if verb in hay}


def categories_for_hits(hits: set[str]) -> set[str]:
    return {VERB_TO_CATEGORY[h] for h in hits if h in VERB_TO_CATEGORY}
