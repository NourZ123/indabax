"""Your defense logic lives here. Orchestrates policy, injection, information-flow,
impact and approval checks into a single cumulative-risk decision.
"""

from __future__ import annotations

from app.models import DefenseDecision, DefenseRequest
from app import reason_codes, risk as risk_mod
from app.provenance import untrusted_texts
from app.policy import is_tool_allowed
from app.injection import match_strength, READ_ONLY_TOOLS
from app.information_flow import (
    contains_encoded_secret,
    has_secret_like_value,
    has_sensitive_marker,
    SINK_TOOLS,
)
from app.history import is_confirmed
from app.impact import is_consequential
from app.approvals import draft_rewrite
from app.goal_alignment import is_relevant_tool_call, allow_not_a_tool_call


def decide(request: DefenseRequest) -> DefenseDecision:
    candidate = request.candidate_action
    action = candidate.confirmation_for if candidate.type == "request_confirmation" else candidate

    if not is_relevant_tool_call(action):
        return allow_not_a_tool_call()

    if not is_tool_allowed(action, request):
        return DefenseDecision(
            decision="block", risk_score=0.95, confidence=0.9,
            reason_codes=[reason_codes.TOOL_NOT_REQUIRED_FOR_GOAL],
        )

    risk = risk_mod.BASE_RISK
    codes: list[str] = []
    untrusted = untrusted_texts(request)

    # Signal 1 : instruction cachée dans un texte non fiable.
    if action.tool not in READ_ONLY_TOOLS:
        strength = match_strength(action, untrusted)
        if strength == 2:
            risk += risk_mod.INJECTION_STRONG
            codes.append(reason_codes.UNTRUSTED_INSTRUCTION_SOURCE_STRONG)
        elif strength == 1:
            risk += risk_mod.INJECTION_WEAK
            codes.append(reason_codes.UNTRUSTED_INSTRUCTION_SOURCE_WEAK)

    # Signal 2 : fuite de données sensibles vers l'extérieur.
    arg_text = " ".join(str(v).lower() for v in action.arguments.values() if v is not None)
    secret_value = has_secret_like_value(arg_text)
    sensitive_marker = has_sensitive_marker(arg_text)
    encoded_secret = contains_encoded_secret(arg_text)
    if action.tool in SINK_TOOLS:
        if encoded_secret:
            risk += risk_mod.SENSITIVE_STRONG
            codes.append(reason_codes.ENCODED_SECRET_DETECTED)
        elif secret_value and sensitive_marker:
            risk += risk_mod.SENSITIVE_STRONG
            codes.append(reason_codes.SENSITIVE_TO_UNTRUSTED_SINK)
        elif secret_value or sensitive_marker:
            risk += risk_mod.SENSITIVE_WEAK
            codes.append(reason_codes.SENSITIVE_MARKER_WEAK)

    # Signal 3 : action à conséquence, pas encore confirmée.
    consequential = is_consequential(action, request)
    confirmed = is_confirmed(action, request)
    needs_confirmation = consequential and not confirmed and candidate.type != "request_confirmation"
    if needs_confirmation:
        risk += risk_mod.MISSING_CONFIRMATION_WEIGHT
        codes.append(reason_codes.MISSING_CONFIRMATION)

    risk = risk_mod.clamp(risk)

    # Décision finale à partir du risque cumulé.
    if risk >= risk_mod.BLOCK_THRESHOLD:
        return DefenseDecision(
            decision="block", risk_score=risk, confidence=0.7, reason_codes=codes or [reason_codes.HIGH_RISK]
        )

    if needs_confirmation:
        rewritten = draft_rewrite(action, request.policy_context.get("allowed_tools", []))
        if rewritten is not None:
            return DefenseDecision(
                decision="rewrite", risk_score=risk, confidence=0.6, reason_codes=codes, rewritten_action=rewritten
            )
        return DefenseDecision(decision="escalate", risk_score=risk, confidence=0.6, reason_codes=codes)

    if risk >= risk_mod.ESCALATE_THRESHOLD:
        return DefenseDecision(
            decision="escalate", risk_score=risk, confidence=0.6, reason_codes=codes or [reason_codes.MODERATE_RISK]
        )

    return DefenseDecision(decision="allow", risk_score=risk, confidence=0.6, reason_codes=[
        reason_codes.USER_GOAL_ALIGNED])
