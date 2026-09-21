"""Real goal alignment: is the candidate action reasonably justified by the authenticated
user's goal, using `request.user_goal` plus trusted vs. untrusted context?

Principle: policy-allowed does not mean goal-aligned, and goal-aligned does not override
policy. Reads are treated more permissively than writes -- malicious text present in a read's
context is not itself a reason to block reading it. Write/consequential actions need stronger
justification: an argument introduced only by untrusted content is real evidence of mismatch,
especially at higher impact.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app import provenance as prov
from app import reason_codes
from app.impact import classify_impact
from app.models import CandidateAction, DefenseRequest


@dataclass(frozen=True)
class GoalAlignmentResult:
    alignment_score: float
    mismatch_score: float
    confidence: float
    reason_codes: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)


# Mismatch contributed when an action's arguments are introduced *only* by untrusted content,
# scaled by impact: reads get a moderate signal (evidence, not a block); writes get a strong one.
_UNTRUSTED_ONLY_MISMATCH = {"low": 0.35, "medium": 0.6, "high": 0.85}
# Mismatch when a write/consequential action's arguments trace to neither trusted nor untrusted
# context at all (agent invented values with no grounding). Reads are left alone here.
_UNGROUNDED_MISMATCH = {"medium": 0.35, "high": 0.55}


def evaluate(action: CandidateAction, request: DefenseRequest) -> GoalAlignmentResult:
    if action.type != "tool_call" or action.tool is None:
        return GoalAlignmentResult(alignment_score=0.5, mismatch_score=0.0, confidence=0.2, details={"skipped": True})

    impact = classify_impact(action, request)
    origins = prov.argument_origin(action.arguments, request)
    untrusted_only = sorted(k for k, v in origins.items() if v == "untrusted")
    trusted_hit = sorted(k for k, v in origins.items() if v in ("trusted", "both"))
    ungrounded = sorted(k for k, v in origins.items() if v == "unknown")

    mismatch = 0.0
    codes: list[str] = []
    details: dict[str, object] = {"impact": impact, "argument_origins": origins}

    if untrusted_only:
        mismatch = _UNTRUSTED_ONLY_MISMATCH[impact]
        codes.append(reason_codes.GOAL_MISMATCH)
        details["reason"] = "argument(s) introduced only by untrusted content"
        details["untrusted_arguments"] = untrusted_only
    elif impact != "low" and ungrounded and not trusted_hit and origins:
        mismatch = _UNGROUNDED_MISMATCH[impact]
        codes.append(reason_codes.GOAL_MISMATCH)
        details["reason"] = "argument(s) not traceable to the user goal or observed context"
        details["ungrounded_arguments"] = ungrounded

    alignment = round(1.0 - mismatch, 4)
    if mismatch >= 0.5:
        confidence = 0.55
    elif mismatch > 0:
        confidence = 0.45
    elif origins:
        confidence = 0.6
    else:
        confidence = 0.35

    if mismatch < 0.2:
        codes.append(reason_codes.USER_GOAL_ALIGNED)

    return GoalAlignmentResult(
        alignment_score=alignment,
        mismatch_score=round(mismatch, 4),
        confidence=confidence,
        reason_codes=codes,
        details=details,
    )
