"""Filters non-tool-call actions, which are always low risk by default."""

from app.models import CandidateAction, DefenseDecision
from app import reason_codes


def is_relevant_tool_call(action: CandidateAction | None) -> bool:
    return action is not None and action.type == "tool_call" and action.tool is not None


def allow_not_a_tool_call() -> DefenseDecision:
    return DefenseDecision(
        decision="allow", risk_score=0.1, confidence=0.5, reason_codes=[reason_codes.NOT_A_TOOL_CALL]
    )
