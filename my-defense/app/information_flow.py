"""Sensitive-data exfiltration checks built around real sinks.

A sink is wherever text leaves the action into some destination: an external email, an
internal ticket/case note, agent memory, or the user-facing response. Internal sinks are not
treated the same as external ones -- destination trust drives the score. Sensitivity detection
combines generic secret-marker/pattern matching with provenance-based distinctive-value
extraction (does a value from a confidential/restricted source show up, plainly or encoded,
in the payload?).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app import provenance as prov
from app import reason_codes, signals
from app.models import CandidateAction, DefenseRequest
from app.tool_profiles import profile_for

SENSITIVE_MARKERS = ("token", "password", "secret", "secret code", "account_number", "api_key", "apikey", "credential")

# Known official record-id prefixes (see src/sentinel/domains/*/tools.py insert() calls and
# args_model patterns) plus a couple of generic fixture-entity prefixes -- excluded so normal
# business identifiers are never mistaken for secrets.
KNOWN_ID_PREFIXES = (
    "case-", "cu-", "acc-", "ben-", "pay-", "cd-", "doc-", "em-", "tck-", "drf-", "out-",
    "al-", "ws-", "srv-", "fw-", "inc-", "rem-", "note-", "mem-", "fp-", "ne-", "ct-",
)

SINK_TOOL_NAMES = frozenset(
    {"email_draft", "email_send", "ticket_update", "case_note_create", "incident_create", "incident_update"}
)


@dataclass(frozen=True)
class Sink:
    kind: str
    destination_trust: str
    text: str
    external: bool


def _destination_trust_for_email(to: str, request: DefenseRequest) -> str:
    domain = to.rsplit("@", 1)[-1].strip().lower() if "@" in to else ""
    internal_domains = {d.lower() for d in request.policy_context.get("internal_email_domains", [])}
    if domain and domain in internal_domains:
        return "trusted_internal"
    return "untrusted_external"


def build_sink(action: CandidateAction, request: DefenseRequest) -> Sink | None:
    if action.type == "respond":
        return Sink("respond", "authenticated_user", action.content or "", external=False)
    if action.type == "memory_write":
        return Sink("memory_write", "trusted_internal", action.content or "", external=False)
    if action.type != "tool_call" or action.tool is None:
        return None

    tool = action.tool
    args = action.arguments

    if tool in ("email_draft", "email_send"):
        to = str(args.get("to", ""))
        dest = _destination_trust_for_email(to, request)
        text = f"{args.get('subject', '')}\n{args.get('body', '')}"
        return Sink(tool, dest, text, external=dest != "trusted_internal")
    if tool == "ticket_update":
        note = args.get("note")
        return Sink(tool, "trusted_internal", str(note), external=False) if note else None
    if tool == "case_note_create":
        return Sink(tool, "trusted_internal", str(args.get("text", "")), external=False)
    if tool == "incident_create":
        return Sink(tool, "trusted_internal", f"{args.get('title', '')}\n{args.get('summary', '')}", external=False)
    if tool == "incident_update":
        note = args.get("note")
        return Sink(tool, "trusted_internal", str(note), external=False) if note else None

    # Unrecognized tool: fall back to the conservative profile default rather than silence.
    profile = profile_for(tool)
    if profile.write and (profile.external_sink or profile.internal_sink):
        arg_text = " ".join(str(v) for v in args.values() if v is not None)
        dest = "untrusted_external" if profile.external_sink else "trusted_internal"
        return Sink(tool, dest, arg_text, external=profile.external_sink)
    return None


def has_sensitive_marker(text: str) -> bool:
    hay = text.lower()
    return any(marker in hay for marker in SENSITIVE_MARKERS)


def has_secret_like_value(text: str) -> bool:
    candidates = re.findall(r"[a-zA-Z0-9_-]{10,}", text)
    return any(
        re.search(r"[0-9]", tok) and re.search(r"[a-zA-Z]", tok) and not tok.lower().startswith(KNOWN_ID_PREFIXES)
        for tok in candidates
    )


def contains_encoded_secret(text: str) -> bool:
    return signals.contains_encoded_secret_marker(text)


def extract_distinctive_values(texts: list[str]) -> list[str]:
    """Short structured, non-ID tokens from confidential/restricted source texts -- the
    conservative extraction the brief asks for (not whole-document comparison)."""
    values: set[str] = set()
    for text in texts:
        for tok in re.findall(r"[A-Za-z0-9_-]{6,40}", text):
            if tok.lower().startswith(KNOWN_ID_PREFIXES):
                continue
            if re.search(r"[0-9]", tok) and re.search(r"[A-Za-z]", tok):
                values.add(tok)
    return sorted(values)


def sensitive_value_leak(payload_text: str, request: DefenseRequest) -> tuple[list[str], str | None]:
    candidates = extract_distinctive_values(prov.sensitive_texts(request))
    encoding_rank = {"plain": 3, "base64": 2, "hex": 2, "reversed": 2, "spaced": 1}
    matched: list[str] = []
    strongest: str | None = None
    for value in candidates:
        encoding = signals.find_value(value, payload_text)
        if encoding:
            matched.append(value)
            if strongest is None or encoding_rank.get(encoding, 0) > encoding_rank.get(strongest, 0):
                strongest = encoding
    return matched, strongest


@dataclass(frozen=True)
class DataFlowResult:
    score: float = 0.0
    confidence: float = 0.3
    sink: str | None = None
    destination_trust: str | None = None
    reason_codes: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)


def evaluate(action: CandidateAction, request: DefenseRequest) -> DataFlowResult:
    sink = build_sink(action, request)
    if sink is None:
        return DataFlowResult()

    payload = sink.text or ""
    marker = has_sensitive_marker(payload)
    secretish = has_secret_like_value(payload)
    encoded_generic = signals.contains_encoded_secret_marker(payload)
    matched_values, encoding = sensitive_value_leak(payload, request)

    codes: list[str] = []
    score = 0.0
    confidence = 0.3
    details: dict[str, object] = {"sink": sink.kind, "destination_trust": sink.destination_trust}

    if matched_values:
        score = 0.85 if sink.external else 0.45
        confidence = 0.9 if sink.external else 0.6
        if encoding and encoding != "plain":
            codes.append(reason_codes.ENCODED_SECRET_DETECTED)
            score = min(score + 0.1, 1.0)
        codes.append(reason_codes.SECRET_TO_EXTERNAL_SINK if sink.external else reason_codes.SENSITIVE_DATA_FLOW)
        details["matched_values"] = len(matched_values)
        details["encoding"] = encoding
    elif encoded_generic:
        score = 0.6 if sink.external else 0.3
        confidence = 0.55
        codes.append(reason_codes.ENCODED_SECRET_DETECTED)
    elif secretish and marker:
        score = 0.55 if sink.external else 0.25
        confidence = 0.5
        codes.append(reason_codes.SECRET_TO_EXTERNAL_SINK if sink.external else reason_codes.SENSITIVE_DATA_FLOW)
    elif secretish or marker:
        score = 0.25 if sink.external else 0.12
        confidence = 0.35
        codes.append(reason_codes.SENSITIVE_DATA_FLOW)

    return DataFlowResult(
        score=round(score, 4),
        confidence=confidence,
        sink=sink.kind,
        destination_trust=sink.destination_trust,
        reason_codes=sorted(set(codes)),
        details=details,
    )
