"""Orchestrates policy, provenance, goal-alignment, injection, information-flow, impact and
history checks into a single cumulative-risk decision. Every `CandidateAction.type` is handled
explicitly -- `memory_write` and `respond` are analyzed, not auto-allowed.

Design principles enforced here (see also each module's docstring):
  * malicious text != malicious action; reading untrusted content stays possible
  * untrusted content is evidence, never authority
  * policy-allowed != goal-aligned, and goal-aligned never overrides policy
  * a rewrite is only accepted if it is itself revalidated as safe
"""

from __future__ import annotations

from dataclasses import dataclass

from app import config, goal_alignment, history, impact, information_flow, injection, policy
from app import provenance as prov
from app import reason_codes
from app import risk as risk_mod
from app.approvals import draft_rewrite, validate_rewrite
from app.goal_alignment import GoalAlignmentResult
from app.history import MultistepResult
from app.information_flow import DataFlowResult
from app.injection import InjectionResult
from app.models import CandidateAction, DefenseDecision, DefenseRequest


@dataclass(frozen=True)
class SignalBundle:
    goal: GoalAlignmentResult
    injection: InjectionResult
    flow: DataFlowResult
    history: MultistepResult


def _dedupe(codes: list[str]) -> list[str]:
    seen: list[str] = []
    for code in codes:
        if code not in seen:
            seen.append(code)
    return seen[:16]


def _strongest_confidence(scored: list[tuple[float, float]], default: float = 0.5) -> float:
    """Confidence of the highest-scoring category; evidence quality drives confidence, not
    a copy of the risk score."""
    fired = [(score, confidence) for score, confidence in scored if score > 0]
    if not fired:
        return default
    return max(fired, key=lambda pair: pair[0])[1]


def decide(request: DefenseRequest) -> DefenseDecision:
    candidate = request.candidate_action
    if candidate.type == "tool_call":
        return _decide_tool_call(candidate, request)
    if candidate.type == "memory_write":
        return _decide_memory_write(candidate, request)
    if candidate.type == "respond":
        return _decide_respond(candidate, request)
    if candidate.type == "request_confirmation":
        return _decide_request_confirmation(candidate, request)
    return DefenseDecision(decision="block", risk_score=0.9, confidence=0.5, reason_codes=[reason_codes.NOT_A_TOOL_CALL])


# ---- tool_call ----------------------------------------------------------------------------


def _evaluate_tool_call_signals(action: CandidateAction, request: DefenseRequest) -> SignalBundle:
    goal = goal_alignment.evaluate(action, request) if config.ENABLE_GOAL_ALIGNMENT else GoalAlignmentResult(
        alignment_score=1.0, mismatch_score=0.0, confidence=0.0
    )
    inj = injection.evaluate(action, request) if config.ENABLE_INJECTION else InjectionResult()
    flow = information_flow.evaluate(action, request) if config.ENABLE_INFORMATION_FLOW else DataFlowResult()
    hist = history.multistep_signal(action, request) if config.ENABLE_HISTORY else MultistepResult()
    return SignalBundle(goal=goal, injection=inj, flow=flow, history=hist)


def _decide_tool_call(action: CandidateAction, request: DefenseRequest) -> DefenseDecision:
    confirmed = history.is_confirmed(action, request)
    policy_result = policy.evaluate(action, request, confirmed)

    if not policy_result.allowed:
        return DefenseDecision(
            decision="block",
            risk_score=policy_result.score,
            confidence=0.9,
            reason_codes=_dedupe(policy_result.reason_codes),
            metadata={"policy": {"allowed": False, "hard_violation": True}},
        )

    if policy_result.hard_violation:
        return DefenseDecision(
            decision="block",
            risk_score=policy_result.score,
            confidence=0.85,
            reason_codes=_dedupe(policy_result.reason_codes),
            metadata={"policy": {"allowed": True, "hard_violation": True, "details": policy_result.details}},
        )

    signals = _evaluate_tool_call_signals(action, request)
    goal = signals.goal
    inj = signals.injection
    flow = signals.flow
    hist = signals.history
    impact_level = impact.classify_impact(action, request)

    category_scores = {
        "policy": policy_result.score,
        "goal_mismatch": goal.mismatch_score,
        "injection": inj.score,
        "data_flow": flow.score,
        "history": hist.score,
    }
    risk = risk_mod.aggregate(risk_mod.BASE_RISK, category_scores)
    confidence = _strongest_confidence(
        [
            (policy_result.score, 0.85),
            (goal.mismatch_score, goal.confidence),
            (inj.score, 0.8 if inj.strength == "strong" else 0.5),
            (flow.score, flow.confidence),
            (hist.score, 0.5),
        ]
    )

    codes = policy_result.reason_codes + goal.reason_codes + inj.reason_codes + flow.reason_codes + hist.reason_codes
    if impact_level == "high":
        codes.append(reason_codes.HIGH_IMPACT_ACTION)

    metadata = {
        "policy": {
            "allowed": policy_result.allowed,
            "hard_violation": policy_result.hard_violation,
            "confirmation_required": policy_result.confirmation_required,
        },
        "goal_alignment": {"alignment": goal.alignment_score, "mismatch": goal.mismatch_score},
        "injection": {"score": inj.score, "strength": inj.strength},
        "data_flow": {"score": flow.score, "sink": flow.sink, "destination_trust": flow.destination_trust},
        "history": {"score": hist.score},
        "impact": impact_level,
        "confirmed": confirmed,
    }

    # Hard rule: a clear, high-confidence sensitive-data flow to an untrusted external sink
    # blocks outright regardless of the aggregated score.
    if flow.score >= 0.8 and flow.destination_trust == "untrusted_external":
        return DefenseDecision(
            decision="block",
            risk_score=risk_mod.clamp(max(risk, flow.score)),
            confidence=flow.confidence,
            reason_codes=_dedupe(codes),
            metadata=metadata,
        )

    if risk >= risk_mod.BLOCK_THRESHOLD:
        return DefenseDecision(
            decision="block", risk_score=risk, confidence=confidence, reason_codes=_dedupe(codes) or [reason_codes.HIGH_RISK], metadata=metadata
        )

    if policy_result.confirmation_required:
        rewritten = draft_rewrite(action, request.policy_context.get("allowed_tools", []))
        if rewritten is not None and validate_rewrite(rewritten, request):
            codes.append(reason_codes.SAFE_REWRITE_AVAILABLE)
            return DefenseDecision(
                decision="rewrite",
                risk_score=risk,
                confidence=confidence,
                reason_codes=_dedupe(codes),
                rewritten_action=rewritten,
                metadata=metadata,
            )
        if rewritten is not None:
            codes.append(reason_codes.REWRITE_UNSAFE)
        return DefenseDecision(
            decision="escalate",
            risk_score=risk_mod.clamp(max(risk, risk_mod.ESCALATE_THRESHOLD)),
            confidence=confidence,
            reason_codes=_dedupe(codes),
            metadata=metadata,
        )

    if risk >= risk_mod.ESCALATE_THRESHOLD:
        return DefenseDecision(
            decision="escalate", risk_score=risk, confidence=confidence, reason_codes=_dedupe(codes) or [reason_codes.MODERATE_RISK], metadata=metadata
        )

    if impact_level == "low" and risk < 0.2:
        codes.append(reason_codes.LOW_RISK_READ)

    return DefenseDecision(decision="allow", risk_score=risk, confidence=confidence,
                           reason_codes=_dedupe(codes), metadata=metadata)


# ---- memory_write ---------------------------------------------------------------------------


def _memory_source_trust(request: DefenseRequest) -> str:
    pmap = prov.provenance_map(request)
    obs = request.observation
    if obs is not None and obs.provenance_ids:
        return prov.least_trusted_level([pmap[pid].trust_level for pid in obs.provenance_ids if pid in pmap])
    for item in reversed(request.conversation):
        if item.provenance_ids:
            return prov.item_trust(item, pmap)
    if request.history_digest.least_trusted_seen:
        return request.history_digest.least_trusted_seen
    return "authenticated_user"


def _decide_memory_write(action: CandidateAction, request: DefenseRequest) -> DefenseDecision:
    content = action.content or ""
    source_trust = _memory_source_trust(request) if config.ENABLE_PROVENANCE else "authenticated_user"
    untrusted_source = source_trust in prov.UNTRUSTED
    claims = prov.authority_claims(content) if untrusted_source else set()

    codes: list[str] = []
    memory_score = 0.0
    if untrusted_source and claims:
        memory_score = 0.9
        codes += [reason_codes.AUTHORITY_MISMATCH,
                  reason_codes.UNTRUSTED_MEMORY_SOURCE, reason_codes.MEMORY_POISONING_RISK]
    elif untrusted_source:
        memory_score = 0.15
        codes.append(reason_codes.UNTRUSTED_MEMORY_SOURCE)

    flow = information_flow.evaluate(
        action, request) if config.ENABLE_INFORMATION_FLOW else information_flow.DataFlowResult()
    codes += flow.reason_codes

    risk = risk_mod.aggregate(risk_mod.BASE_RISK, {"memory": memory_score, "data_flow": flow.score})
    confidence = 0.75 if (untrusted_source and claims) else (0.4 if untrusted_source else 0.5)

    metadata = {
        "memory": {"source_trust": source_trust, "authority_claims": sorted(claims)},
        "data_flow": {"score": flow.score, "sink": flow.sink},
    }

    if risk >= risk_mod.BLOCK_THRESHOLD:
        decision = "block"
    elif risk >= risk_mod.ESCALATE_THRESHOLD:
        decision = "escalate"
    else:
        decision = "allow"

    return DefenseDecision(
        decision=decision, risk_score=risk, confidence=confidence, reason_codes=_dedupe(codes), metadata=metadata
    )


# ---- respond ----------------------------------------------------------------------------------


def _decide_respond(action: CandidateAction, request: DefenseRequest) -> DefenseDecision:
    flow = information_flow.evaluate(
        action, request) if config.ENABLE_INFORMATION_FLOW else information_flow.DataFlowResult()
    risk = risk_mod.aggregate(risk_mod.BASE_RISK, {"data_flow": flow.score})
    confidence = flow.confidence if flow.score > 0 else 0.5
    metadata = {"data_flow": {"score": flow.score, "sink": flow.sink, "destination_trust": flow.destination_trust}}

    if risk >= risk_mod.BLOCK_THRESHOLD:
        decision = "block"
    elif risk >= risk_mod.ESCALATE_THRESHOLD:
        decision = "escalate"
    else:
        decision = "allow"

    return DefenseDecision(
        decision=decision, risk_score=risk, confidence=confidence, reason_codes=_dedupe(flow.reason_codes), metadata=metadata
    )


# ---- request_confirmation ----------------------------------------------------------------------


def _decide_request_confirmation(action: CandidateAction, request: DefenseRequest) -> DefenseDecision:
    target = action.confirmation_for
    assert target is not None  # guaranteed by the official CandidateAction validator

    # Requesting confirmation *is* the safe path for a consequential action, so evaluate the
    # target as already-confirmed to avoid penalizing the agent for doing the right thing.
    policy_result = policy.evaluate(target, request, confirmed=True)
    if not policy_result.allowed or policy_result.hard_violation:
        return DefenseDecision(
            decision="block",
            risk_score=max(policy_result.score, 0.8),
            confidence=0.85,
            reason_codes=_dedupe(policy_result.reason_codes),
            metadata={"policy": {"allowed": policy_result.allowed, "hard_violation": policy_result.hard_violation}},
        )

    signals = _evaluate_tool_call_signals(target, request)
    goal, inj, flow, hist = signals.goal, signals.injection, signals.flow, signals.history
    category_scores = {
        "goal_mismatch": goal.mismatch_score,
        "injection": inj.score,
        "data_flow": flow.score,
        "history": hist.score,
    }
    risk = risk_mod.aggregate(risk_mod.BASE_RISK, category_scores)
    codes = goal.reason_codes + inj.reason_codes + flow.reason_codes + hist.reason_codes
    confidence = _strongest_confidence(
        [(goal.mismatch_score, goal.confidence), (inj.score, 0.7), (flow.score, flow.confidence), (hist.score, 0.5)]
    )
    metadata = {
        "target_tool": target.tool,
        "goal_alignment": {"mismatch": goal.mismatch_score},
        "injection": {"score": inj.score, "strength": inj.strength},
        "data_flow": {"score": flow.score, "sink": flow.sink},
    }

    # A request for human review is not itself the effect; only block if the underlying
    # target is clearly malicious, otherwise let the human confirmation gate do its job.
    if risk >= risk_mod.BLOCK_THRESHOLD:
        return DefenseDecision(decision="block", risk_score=risk, confidence=confidence, reason_codes=_dedupe(codes), metadata=metadata)

    return DefenseDecision(decision="allow", risk_score=risk, confidence=confidence,
                           reason_codes=_dedupe(codes), metadata=metadata)
