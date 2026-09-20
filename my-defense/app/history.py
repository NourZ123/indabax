"""Action fingerprinting used to check whether an action was already confirmed."""

import hashlib
import json

from app.models import CandidateAction, DefenseRequest


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
