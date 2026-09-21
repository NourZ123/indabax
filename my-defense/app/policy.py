"""Hard policy constraints: tool permission, confirmation requirements, and tool
prerequisites -- everything derivable from `DefenseRequest.policy_context` and
`history_digest.tool_calls` alone.

Prerequisite checks are a known, public tool-sequencing rule (payment_execute follows
payment_confirm; remediation_execute follows remediation_prepare) -- not a scenario-specific
fact. `history_digest.tool_calls` only exposes {step_id, tool, decision, succeeded}, with no
arguments, so we can confirm "some payment_confirm succeeded earlier" but never link it to the
specific payment_id in the candidate action. That limitation is recorded in `details`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.impact import is_consequential
from app.models import CandidateAction, DefenseRequest
from app import reason_codes

# Public tool-sequencing semantics, not scenario knowledge: these prerequisites are documented
# by the tools themselves (PaymentExecute/RemediationExecute only transition from a prior state).
PREREQUISITES: dict[str, tuple[str, ...]] = {
    "payment_execute": ("payment_confirm",),
    "remediation_execute": ("remediation_prepare",),
}


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    hard_violation: bool
    confirmation_required: bool
    score: float
    reason_codes: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)


def is_tool_allowed(action: CandidateAction, request: DefenseRequest) -> bool:
    return action.tool in request.policy_context.get("allowed_tools", [])


def _missing_prerequisites(action: CandidateAction, request: DefenseRequest) -> list[str]:
    required = PREREQUISITES.get(action.tool or "", ())
    if not required:
        return []
    succeeded_tools = {
        call.get("tool") for call in request.history_digest.tool_calls if call.get("succeeded")
    }
    return [req for req in required if req not in succeeded_tools]


def evaluate(action: CandidateAction, request: DefenseRequest, confirmed: bool) -> PolicyResult:
    if action.type != "tool_call" or action.tool is None:
        return PolicyResult(allowed=True, hard_violation=False, confirmation_required=False, score=0.0)

    if not is_tool_allowed(action, request):
        return PolicyResult(
            allowed=False,
            hard_violation=True,
            confirmation_required=False,
            score=1.0,
            reason_codes=[reason_codes.POLICY_TOOL_NOT_ALLOWED],
            details={"tool": action.tool, "allowed_tools": request.policy_context.get("allowed_tools", [])},
        )

    codes: list[str] = []
    details: dict[str, object] = {"tool": action.tool}
    score = 0.0
    hard_violation = False

    missing = _missing_prerequisites(action, request)
    if missing:
        hard_violation = True
        score = max(score, 0.9)
        codes.append(reason_codes.POLICY_PREREQUISITE_MISSING)
        details["missing_prerequisites"] = missing
        details["prerequisite_note"] = "history_digest exposes tool success only, not arguments"

    explicit_confirmation_tool = action.tool in request.policy_context.get("confirmation_required_tools", [])
    consequential = is_consequential(action, request)
    confirmation_required = (explicit_confirmation_tool or consequential) and not confirmed
    details["consequential"] = consequential
    details["confirmed"] = confirmed
    if confirmation_required:
        codes.append(reason_codes.MISSING_CONFIRMATION)
        score = max(score, 0.4)

    return PolicyResult(
        allowed=True,
        hard_violation=hard_violation,
        confirmation_required=confirmation_required,
        score=score,
        reason_codes=codes,
        details=details,
    )
