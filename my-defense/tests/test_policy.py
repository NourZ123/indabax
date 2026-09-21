"""Policy: tool permission, confirmation requirements, prerequisites, and exact-action
confirmation digests."""

from __future__ import annotations

from app.history import action_digest
from helpers import decide, make_request, tool_call


def test_tool_not_in_allowed_tools_blocks() -> None:
    body = make_request(
        user_goal="Execute the payment.",
        action=tool_call("payment_execute", payment_id="PAY-0001"),
        allowed_tools=["payment_prepare"],
    )
    result = decide(body)
    assert result["decision"] == "block"
    assert "POLICY_TOOL_NOT_ALLOWED" in result["reason_codes"]


def test_consequential_action_missing_confirmation_escalates_without_rewrite_target() -> None:
    body = make_request(
        user_goal="Confirm the prepared payment.",
        action=tool_call("payment_confirm", payment_id="PAY-0001"),
        allowed_tools=["payment_confirm"],
        consequential_tools=["payment_confirm"],
    )
    result = decide(body)
    assert result["decision"] == "escalate"
    assert "MISSING_CONFIRMATION" in result["reason_codes"]


def test_consequential_email_send_without_confirmation_rewrites_to_draft() -> None:
    body = make_request(
        user_goal="Send the reply to the customer.",
        action=tool_call("email_send", to="partner@atlas.example", subject="hi", body="hello there"),
        allowed_tools=["email_send", "email_draft"],
        consequential_tools=["email_send"],
    )
    result = decide(body)
    assert result["decision"] == "rewrite"
    assert result["rewritten_action"]["tool"] == "email_draft"


def test_confirmed_exact_action_is_allowed() -> None:
    action = tool_call("ticket_update", ticket_id="TCK-501", status="closed")
    digest = action_digest_from_dict(action)
    body = make_request(
        user_goal="Close the resolved ticket.",
        action=action,
        allowed_tools=["ticket_update"],
        history_digest={"confirmations_granted": [digest]},
    )
    result = decide(body)
    assert result["decision"] == "allow"


def test_modified_action_after_confirmation_is_not_confirmed() -> None:
    confirmed_action = tool_call("ticket_update", ticket_id="TCK-501", status="closed")
    digest = action_digest_from_dict(confirmed_action)
    modified_action = tool_call("ticket_update", ticket_id="TCK-502", status="closed")
    body = make_request(
        user_goal="Close the resolved ticket.",
        action=modified_action,
        allowed_tools=["ticket_update"],
        history_digest={"confirmations_granted": [digest]},
    )
    result = decide(body)
    assert result["decision"] != "allow"
    assert "MISSING_CONFIRMATION" in result["reason_codes"]


def test_payment_execute_without_prior_confirm_is_flagged() -> None:
    body = make_request(
        user_goal="Execute the payment.",
        action=tool_call("payment_execute", payment_id="PAY-0001"),
        allowed_tools=["payment_execute", "payment_confirm"],
        history_digest={"tool_calls": []},
    )
    result = decide(body)
    assert result["decision"] == "block"
    assert "POLICY_PREREQUISITE_MISSING" in result["reason_codes"]


def test_remediation_execute_without_prior_prepare_is_flagged() -> None:
    body = make_request(
        user_goal="Execute the remediation.",
        action=tool_call("remediation_execute", remediation_id="REM-0001"),
        allowed_tools=["remediation_execute", "remediation_prepare"],
        history_digest={"tool_calls": [{"step_id": 1, "tool": "alert_read", "decision": "allow", "succeeded": True}]},
    )
    result = decide(body)
    assert result["decision"] == "block"
    assert "POLICY_PREREQUISITE_MISSING" in result["reason_codes"]


def test_remediation_execute_after_prepare_succeeds_is_not_blocked_by_prerequisite() -> None:
    body = make_request(
        user_goal="Execute the remediation.",
        action=tool_call("remediation_execute", remediation_id="REM-0001"),
        allowed_tools=["remediation_execute", "remediation_prepare"],
        consequential_tools=["remediation_execute"],
        history_digest={
            "tool_calls": [{"step_id": 1, "tool": "remediation_prepare", "decision": "allow", "succeeded": True}]
        },
    )
    result = decide(body)
    assert "POLICY_PREREQUISITE_MISSING" not in result["reason_codes"]


# Helper: local re-import to avoid coupling the test file's import order to app internals.
def action_digest_from_dict(action: dict[str, object]) -> str:
    from app.models import CandidateAction

    return action_digest(CandidateAction.model_validate(action))
