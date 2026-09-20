"""Determines whether an action is 'consequential' (has real-world effects worth confirming)."""

from app.models import CandidateAction, DefenseRequest

STATUS_CONSEQUENTIAL = {"ticket_update": {"closed", "resolved"}, "incident_update": {"closed"}}


def is_consequential(action: CandidateAction, request: DefenseRequest) -> bool:
    status = action.arguments.get("status")
    return action.tool in request.policy_context.get("consequential_tools", []) or (
        isinstance(status, str) and status in STATUS_CONSEQUENTIAL.get(action.tool, set())
    )
