"""Browser-safe view of simulator artifacts.

Artifacts may contain synthetic canaries, restricted data, or attacker-authored text.
This service deliberately does not return arbitrary free-form content. It provides
only allowlisted structured fields, and masks email local parts. Raw artifacts
remain on disk for authorized local investigation.
"""
from __future__ import annotations

import re
from typing import Any

REDACTED = '[REDACTED: free-form content]'
_PRIVATE_KEY = re.compile(r'(password|token|secret|credential|api.?key|authorization|private|access.?key|canary)', re.I)
_ID_PREFIX = {
    'ticket_id': ('TCK-',), 'case_id': ('CASE-',), 'payment_id': ('PAY-',),
    'remediation_id': ('REM-',), 'incident_id': ('INC-',), 'email_id': ('EM-',),
    'document_id': ('DOC-',), 'doc_id': ('DOC-',), 'alert_id': ('AL-',),
    'asset_id': ('WS-', 'SRV-', 'FW-'), 'customer_id': ('CU-',),
}
_SAFE_ENUM_KEYS = {'status', 'type', 'priority', 'category', 'final'}
_SAFE_ID = re.compile(r'^[A-Z]{1,5}-[A-Z0-9-]{1,24}$')
_SAFE_ENUM = re.compile(r'^[a-z_]{1,24}$')
_EMAIL = re.compile(r'^[^@\s]{1,128}@([a-z0-9.-]{1,200})$', re.I)
_SAFE_DOMAIN = re.compile(r'^(?:[a-z0-9-]+\.)+[a-z]{2,24}$', re.I)
_SAFE_CODE = re.compile(r'^[A-Z][A-Z0-9_]{1,63}$')


def safe_arguments(args: Any) -> dict[str, Any]:
    if not isinstance(args, dict):
        return {}
    output: dict[str, Any] = {}
    for key, value in args.items():
        if not isinstance(key, str):
            continue
        if _PRIVATE_KEY.search(key):
            output[key] = '[REDACTED]'
        elif key == 'to' or key in {'from', 'cc', 'bcc'}:
            match = _EMAIL.fullmatch(value.strip()) if isinstance(value, str) else None
            output[key] = f'***@{match.group(1).lower()}' if match and _SAFE_DOMAIN.fullmatch(match.group(1)) else '[REDACTED: recipient]'
        elif key in _ID_PREFIX:
            output[key] = value if isinstance(value, str) and _SAFE_ID.fullmatch(value) and value.startswith(_ID_PREFIX[key]) else '[REDACTED: identifier]'
        elif key == 'final' and isinstance(value, bool):
            output[key] = value
        elif key in _SAFE_ENUM_KEYS:
            output[key] = value if isinstance(value, str) and _SAFE_ENUM.fullmatch(value) else '[REDACTED]'
        else:
            # No arbitrary strings or nested dicts are released to the browser.
            output[key] = REDACTED
    return output


def safe_action(action: Any) -> dict[str, Any] | None:
    if not isinstance(action, dict):
        return None
    output = {'type': str(action.get('type', 'unknown'))[:40]}
    if isinstance(action.get('tool'), str):
        output['tool'] = action['tool'][:64]
    if isinstance(action.get('arguments'), dict):
        output['arguments'] = safe_arguments(action['arguments'])
    if action.get('content') is not None:
        output['content'] = REDACTED
    # A confirmation can refer to a whole nested action, which is recursively sanitized.
    if isinstance(action.get('confirmation_for'), dict):
        output['confirmation_for'] = safe_action(action['confirmation_for'])
    return output


def safe_reason_codes(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [c for c in value if isinstance(c, str) and _SAFE_CODE.fullmatch(c)][:25]


def safe_rule_description(text: Any) -> str:
    """Only called on trusted, developer-supplied repository policy definitions."""
    return str(text)[:1000] if text is not None else ''
