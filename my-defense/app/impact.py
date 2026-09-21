"""Consequence classification for tool_call actions.

`is_consequential` is the "does this need a human confirmation" predicate (matches the
official policy semantics: policy_context consequential_tools, plus dynamic status args for
ticket_update/incident_update). `classify_impact` buckets an action into LOW/MEDIUM/HIGH for
risk scaling elsewhere (goal alignment, injection, information flow all require stronger
evidence as impact rises).
"""

from __future__ import annotations

from typing import Literal

from app.models import CandidateAction, DefenseRequest
from app.tool_profiles import profile_for

Impact = Literal["low", "medium", "high"]


def is_consequential(action: CandidateAction, request: DefenseRequest) -> bool:
    if action.type != "tool_call" or action.tool is None:
        return False
    if action.tool in request.policy_context.get("consequential_tools", []):
        return True
    profile = profile_for(action.tool)
    if profile.consequential:
        return True
    if profile.dynamic_consequential_field:
        value = action.arguments.get(profile.dynamic_consequential_field)
        if isinstance(value, str) and value in profile.dynamic_consequential_values:
            return True
    return False


def classify_impact(action: CandidateAction, request: DefenseRequest) -> Impact:
    if action.type != "tool_call" or action.tool is None:
        return "low"
    profile = profile_for(action.tool)
    if profile.read_only:
        return "low"
    if is_consequential(action, request):
        return "high"
    return "medium"
