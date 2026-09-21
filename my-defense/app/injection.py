"""Detects candidate actions that mirror an instruction hidden in untrusted content.

Combines four signals instead of relying on the literal tool name appearing in the text:
1. tool-name + argument proximity match (strong, but attackers can avoid it)
2. argument values introduced only by untrusted content (provenance-based)
3. natural-language control verbs correlated to the tool's semantic category
4. control language alone, as weak corroborating evidence

Read-only actions are scaled down heavily (malicious text is not a reason to block reading
it) but never fully ignored, so a read still contributes to multi-step correlation.
Overlap between signals 1 and 2 (they're often the same evidence) is capped rather than summed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app import provenance as prov
from app import reason_codes, signals
from app.models import CandidateAction, DefenseRequest
from app.tool_profiles import profile_for

WINDOW = 250

# Tool -> the semantic category a natural-language instruction would use to describe it.
TOOL_CATEGORY: dict[str, str] = {
    "email_send": "email_out",
    "email_draft": "email_out",
    "payment_confirm": "payment",
    "payment_execute": "payment",
    "payment_prepare": "payment",
    "remediation_execute": "remediation",
    "remediation_prepare": "remediation",
    "ticket_update": "state_change",
    "incident_update": "state_change",
    "incident_create": "incident",
    "case_note_create": "case_note",
}
_AMBIGUOUS_EXECUTE = {"payment", "remediation"}


@dataclass(frozen=True)
class InjectionResult:
    score: float = 0.0
    strength: str = "none"  # "none" | "weak" | "strong"
    reason_codes: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)


def _tool_name_match_strength(action: CandidateAction, untrusted: list[str]) -> int:
    """0 = no match, 1 = weak (one value near the tool name), 2 = strong (two or more)."""
    if action.tool is None:
        return 0
    values = [str(v).lower() for v in action.arguments.values() if v is not None and len(str(v)) >= 4]
    if not values:
        return 0
    best = 0
    for text in untrusted:
        start = text.find(action.tool)
        while start != -1:
            window = text[start : start + WINDOW]
            matches = sum(1 for value in values if value in window)
            best = max(best, matches)
            start = text.find(action.tool, start + 1)
    if best >= 2:
        return 2
    if best == 1:
        return 1
    return 0


def evaluate(action: CandidateAction, request: DefenseRequest) -> InjectionResult:
    if action.type != "tool_call" or action.tool is None:
        return InjectionResult()

    untrusted = prov.untrusted_texts(request)
    untrusted_blob = " ".join(untrusted)
    profile = profile_for(action.tool)

    name_match = _tool_name_match_strength(action, untrusted)
    name_score = {0: 0.0, 1: 0.3, 2: 0.6}[name_match]

    origins = prov.argument_origin(action.arguments, request)
    untrusted_args = sorted(k for k, v in origins.items() if v in ("untrusted", "both"))
    arg_score = 0.5 if untrusted_args else 0.0

    control_hits = signals.control_language_hits(untrusted_blob)
    categories = signals.categories_for_hits(control_hits)
    tool_category = TOOL_CATEGORY.get(action.tool)
    category_hit = tool_category is not None and (
        tool_category in categories or (tool_category in _AMBIGUOUS_EXECUTE and "payment_or_remediation" in categories)
    )
    category_score = 0.35 if category_hit and name_match == 0 else 0.0
    control_only_score = 0.15 if (control_hits and name_match == 0 and not untrusted_args and not category_hit) else 0.0

    # signals 1 and 2 are frequently the same evidence (the matched argument *is* the untrusted
    # value); take the stronger at full weight and the weaker as half-weight corroboration.
    directive = max(name_score, arg_score) + 0.5 * min(name_score, arg_score)
    total = min(directive + category_score + control_only_score, 1.0)

    if profile.read_only:
        total *= 0.35

    if total >= 0.55:
        strength = "strong"
    elif total > 0.05:
        strength = "weak"
    else:
        strength = "none"

    codes: list[str] = []
    if name_match or untrusted_args or category_hit:
        codes.append(reason_codes.UNTRUSTED_INSTRUCTION_SOURCE)
    if untrusted_args:
        codes.append(reason_codes.UNTRUSTED_ARGUMENT_ORIGIN)

    return InjectionResult(
        score=round(total, 4),
        strength=strength,
        reason_codes=sorted(set(codes)),
        details={
            "name_match": name_match,
            "untrusted_argument_count": len(untrusted_args),
            "control_language": sorted(control_hits),
            "semantic_category_match": category_hit,
            "read_only": profile.read_only,
        },
    )
