"""Builds a safer alternative action (rewrite) when a consequential action lacks confirmation,
and revalidates it -- a rewrite is only accepted if it is both policy-allowed and does not
itself trigger a high information-flow score. Bounded to one pass: no recursive rewriting.
"""

from __future__ import annotations

from app import information_flow
from app.models import CandidateAction, DefenseRequest

REWRITE_TARGETS: dict[str, str] = {"email_send": "email_draft"}


def draft_rewrite(action: CandidateAction, allowed_tools: list[str]) -> CandidateAction | None:
    target = REWRITE_TARGETS.get(action.tool or "")
    if target is None or target not in allowed_tools:
        return None
    return CandidateAction(type="tool_call", tool=target, arguments=dict(action.arguments))


def validate_rewrite(rewritten: CandidateAction, request: DefenseRequest) -> bool:
    """A rewrite is only safe if it is allowed by policy and does not itself leak sensitive
    data to an untrusted destination (e.g. email_send -> email_draft still addressed
    externally with a secret in the body must not be accepted)."""
    if rewritten.tool not in request.policy_context.get("allowed_tools", []):
        return False
    flow = information_flow.evaluate(rewritten, request)
    return flow.score < 0.5
