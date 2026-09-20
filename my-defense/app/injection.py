"""Detects candidate actions that mirror an instruction hidden in untrusted text."""

from app.models import CandidateAction

WINDOW = 250
READ_ONLY_TOOLS = {"document_read", "email_read", "case_document_read", "policy_search", "document_search"}


def instruction_in_untrusted(action: CandidateAction, untrusted: list[str]) -> bool:
    """True only when the tool name and at least two of its values appear close together."""
    if action.tool is None:
        return False
    values = [str(v).lower() for v in action.arguments.values() if v is not None and len(str(v)) >= 4]
    if len(values) < 2:
        return False
    for text in untrusted:
        start = text.find(action.tool)
        while start != -1:
            window = text[start: start + WINDOW]
            matches = sum(1 for value in values if value in window)
            if matches >= 2:
                return True
            start = text.find(action.tool, start + 1)
    return False


def match_strength(action: CandidateAction, untrusted: list[str]) -> int:
    """0 = no match, 1 = weak (one value), 2 = strong (two or more values)."""
    if action.tool is None:
        return 0
    values = [str(v).lower() for v in action.arguments.values() if v is not None and len(str(v)) >= 4]
    if not values:
        return 0
    best = 0
    for text in untrusted:
        start = text.find(action.tool)
        while start != -1:
            window = text[start: start + WINDOW]
            matches = sum(1 for value in values if value in window)
            best = max(best, matches)
            start = text.find(action.tool, start + 1)
    if best >= 2:
        return 2
    if best == 1:
        return 1
    return 0
