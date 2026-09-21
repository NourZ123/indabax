"""Trust/origin analysis: who said what, and whether it carries authority.

Core principle: untrusted content may be useful data, but it does not have authority.
An email claiming an approval is not a human confirmation; a hostile log line claiming
a new policy does not change the policy. This module only ever reads what's actually on
`DefenseRequest` -- it never assumes fields the official API does not expose.
"""

from __future__ import annotations

import re

from app import config
from app.models import ConversationItem, DefenseRequest, Provenance

TRUST_ORDER = [
    "system_policy",
    "authenticated_user",
    "trusted_internal",
    "untrusted_internal",
    "untrusted_external",
    "adversary_controlled",
]
TRUST_RANK = {level: i for i, level in enumerate(TRUST_ORDER)}
UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}

SENSITIVITY_ORDER = ["public", "internal", "confidential", "restricted"]
SENSITIVITY_RANK = {level: i for i, level in enumerate(SENSITIVITY_ORDER)}
SENSITIVE = {"confidential", "restricted"}


def provenance_map(request: DefenseRequest) -> dict[str, Provenance]:
    return {record.id: record.provenance for record in request.provenance}


def least_trusted_level(levels: list[str]) -> str:
    """Empty list == authenticated user input, matching sentinel.core.provenance.least_trusted."""
    if not levels:
        return "authenticated_user"
    return max(levels, key=lambda level: TRUST_RANK.get(level, len(TRUST_ORDER)))


def most_sensitive_level(levels: list[str]) -> str:
    if not levels:
        return "public"
    return max(levels, key=lambda level: SENSITIVITY_RANK.get(level, 0))


def _levels(item_provenance_ids: list[str], pmap: dict[str, Provenance]) -> list[str]:
    return [pmap[pid].trust_level for pid in item_provenance_ids if pid in pmap]


def item_trust(item: ConversationItem, pmap: dict[str, Provenance]) -> str:
    return least_trusted_level(_levels(item.provenance_ids, pmap))


def item_is_untrusted(item: ConversationItem, pmap: dict[str, Provenance]) -> bool:
    return item_trust(item, pmap) in UNTRUSTED


def item_sensitivity(item: ConversationItem, pmap: dict[str, Provenance]) -> str:
    sens = [pmap[pid].sensitivity for pid in item.provenance_ids if pid in pmap]
    return most_sensitive_level(sens)


def untrusted_texts(request: DefenseRequest) -> list[str]:
    """Lowercased content of every conversation item (and the observation) whose least
    trusted attached provenance is untrusted_internal / untrusted_external / adversary_controlled.
    """
    if not config.ENABLE_PROVENANCE:
        return []
    pmap = provenance_map(request)
    texts = [item.content.lower() for item in request.conversation if item_is_untrusted(item, pmap)]
    obs = request.observation
    if obs is not None and least_trusted_level(_levels(obs.provenance_ids, pmap)) in UNTRUSTED:
        texts.append(obs.content.lower())
    return texts


def trusted_texts(request: DefenseRequest) -> list[str]:
    """user_goal plus every conversation item whose provenance is trusted (or has none, which
    the official model treats as authenticated_user)."""
    if not config.ENABLE_PROVENANCE:
        texts = [request.user_goal.lower()] + [item.content.lower() for item in request.conversation]
        if request.observation is not None:
            texts.append(request.observation.content.lower())
        return texts
    pmap = provenance_map(request)
    texts = [request.user_goal.lower()]
    for item in request.conversation:
        if not item_is_untrusted(item, pmap):
            texts.append(item.content.lower())
    obs = request.observation
    if obs is not None and least_trusted_level(_levels(obs.provenance_ids, pmap)) not in UNTRUSTED:
        texts.append(obs.content.lower())
    return texts


def sensitive_texts(request: DefenseRequest) -> list[str]:
    """Content of conversation items whose most sensitive attached provenance is
    confidential or restricted -- source material for leak checks."""
    if not config.ENABLE_PROVENANCE:
        return []
    pmap = provenance_map(request)
    return [item.content for item in request.conversation if item_sensitivity(item, pmap) in SENSITIVE]


def argument_origin(arguments: dict[str, object], request: DefenseRequest) -> dict[str, str]:
    """For each candidate-action argument, classify where its value textually appears:
    'trusted', 'untrusted', 'both', or 'unknown' (introduced by neither, e.g. a literal the
    agent invented, or too short to judge)."""
    trusted_blob = " ".join(trusted_texts(request))
    untrusted_blob = " ".join(untrusted_texts(request))
    origins: dict[str, str] = {}
    for key, value in arguments.items():
        if value is None:
            continue
        val = str(value).lower().strip()
        if len(val) < 3:
            origins[key] = "unknown"
            continue
        in_trusted = val in trusted_blob
        in_untrusted = val in untrusted_blob
        if in_trusted and in_untrusted:
            origins[key] = "both"
        elif in_untrusted:
            origins[key] = "untrusted"
        elif in_trusted:
            origins[key] = "trusted"
        else:
            origins[key] = "unknown"
    return origins


# ---- authority-claim detection ----------------------------------------------------------
# Untrusted content asserting approval, new policy, or permission does not grant authority.
# These patterns only ever produce evidence; decision.py combines them with actual trust
# level and action impact rather than acting on the claim alone.

_AUTHORITY_PATTERNS: dict[str, tuple[str, ...]] = {
    "approval_claim": (
        "already approved", "was approved", "approval was granted", "approved by",
        "pre-approved", "authorization ref", "authorized by", "approval for this",
    ),
    "policy_claim": (
        "new policy", "policy update", "policy allows", "policy now allows",
        "updated policy", "new company policy", "new legal policy",
    ),
    "permission_claim": (
        "permission granted", "you are allowed", "you're allowed", "cleared to",
        "no longer requires confirmation", "does not require confirmation",
        "does not need confirmation", "approved to send",
    ),
    "override_claim": (
        "ignore previous", "ignore prior", "ignore the policy", "override policy",
        "disregard the policy", "ignore all previous instructions",
    ),
}

_TOOL_DIRECTIVE_RE = re.compile(r"\bcall\s+[a-z][a-z0-9_]{2,63}\b")
_REMEMBER_DIRECTIVE_RE = re.compile(r"remember to (call|send|execute|transfer|close|disable|forward|store)")


def authority_claims(text: str) -> set[str]:
    """Which categories of authority-claim language appear in `text`. A non-empty result is
    evidence of AUTHORITY_MISMATCH when the text's source is untrusted."""
    hay = " ".join(text.lower().split())
    hits: set[str] = set()
    for tag, phrases in _AUTHORITY_PATTERNS.items():
        if any(p in hay for p in phrases):
            hits.add(tag)
    if _TOOL_DIRECTIVE_RE.search(hay) or _REMEMBER_DIRECTIVE_RE.search(hay):
        hits.add("tool_directive")
    return hits
