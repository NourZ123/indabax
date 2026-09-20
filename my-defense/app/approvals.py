"""Builds a safer alternative action (rewrite) when a consequential action lacks confirmation."""

from app.models import CandidateAction


def draft_rewrite(action: CandidateAction, allowed_tools: list[str]) -> CandidateAction | None:
    if action.tool == "email_send" and "email_draft" in allowed_tools:
        return CandidateAction(type="tool_call", tool="email_draft", arguments=dict(action.arguments))
    return None
