"""Allowed-tools policy check."""

from app.models import CandidateAction, DefenseRequest


def is_tool_allowed(action: CandidateAction, request: DefenseRequest) -> bool:
    return action.tool in request.policy_context.get("allowed_tools", [])
