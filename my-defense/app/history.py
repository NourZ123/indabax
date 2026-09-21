"""Action-confirmation digests (must match the evaluator exactly) plus lightweight
multi-step correlation over the conversation and `history_digest.tool_calls` already on
the request -- no invented state, no fabricated argument history.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from app import provenance as prov
from app.impact import is_consequential
from app.models import CandidateAction, DefenseRequest
from app.tool_profiles import profile_for
from app import reason_codes


def action_digest(action: CandidateAction) -> str:
    """Same digest the evaluator uses for confirmations (see sentinel.core.actions.CandidateAction.digest)."""

    def canonical(value: object) -> object:
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, float) and value.is_integer():
            return int(value)
        return value

    payload: dict[str, object] = {
        "type": action.type,
        "tool": action.tool,
        "arguments": {k: canonical(v) for k, v in sorted(action.arguments.items())},
        "content": action.content if action.type != "tool_call" else None,
    }
    if action.confirmation_for is not None:
        payload["confirmation_for"] = action_digest(action.confirmation_for)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def is_confirmed(action: CandidateAction, request: DefenseRequest) -> bool:
    return action_digest(action) in request.history_digest.confirmations_granted


@dataclass(frozen=True)
class MultistepResult:
    score: float = 0.0
    reason_codes: list[str] = field(default_factory=list)
    details: dict[str, object] = field(default_factory=dict)


def multistep_signal(action: CandidateAction, request: DefenseRequest) -> MultistepResult:
    """Detects cross-step patterns visible from the current request's own conversation +
    provenance + history_digest. Only fires on real correlation, never on the mere presence
    of untrusted text."""
    if action.type != "tool_call" or action.tool is None:
        return MultistepResult()

    profile = profile_for(action.tool)
    codes: list[str] = []
    details: dict[str, object] = {}
    score = 0.0

    # Pattern: an argument of *this* write/sink action was introduced only by untrusted
    # content, and sensitive material has been observed in the run -- i.e. untrusted content
    # steered where data goes, and sensitive data is in play.
    if not profile.read_only and (profile.external_sink or profile.internal_sink):
        origins = prov.argument_origin(action.arguments, request)
        tainted_args = [k for k, v in origins.items() if v in ("untrusted", "both")]
        sensitive_seen = bool(prov.sensitive_texts(request)) or request.history_digest.most_sensitive_seen in (
            "confidential",
            "restricted",
        )
        if tainted_args and sensitive_seen:
            score = max(score, 0.3)
            codes.append(reason_codes.MULTISTEP_RISK)
            details["pattern"] = "untrusted_destination_then_sensitive_write"
            details["tainted_arguments"] = tainted_args

    # Pattern: untrusted content in this request claims approval/permission/override, and the
    # candidate action is consequential -- a claim is not a confirmation. An untrusted merchant
    # email claiming "approval was granted" or a hostile log line saying "close incident" does
    # not carry authority, regardless of how confident the claim sounds.
    untrusted_blob = " ".join(prov.untrusted_texts(request))
    claims = prov.authority_claims(untrusted_blob) & {"approval_claim", "permission_claim", "override_claim"}
    if claims and is_consequential(action, request):
        score = max(score, 0.4)
        codes.append(reason_codes.MULTISTEP_RISK)
        codes.append(reason_codes.AUTHORITY_MISMATCH)
        details.setdefault("pattern", "untrusted_authority_claim_then_consequential_action")
        details["authority_claims"] = sorted(claims)

    return MultistepResult(score=score, reason_codes=sorted(set(codes)), details=details)
