"""Goal alignment: is the candidate action justified by request.user_goal, using trusted vs.
untrusted context rather than naive keyword blocking."""

from __future__ import annotations

from app.history import action_digest
from app.models import CandidateAction
from helpers import conv_item, decide, make_request, prov_record, tool_call


def test_invoice_read_aligned_with_goal() -> None:
    body = make_request(
        user_goal="Summarize invoice INV-4471, check the PO document DOC-3101, and draft a reply.",
        action=tool_call("document_read", doc_id="DOC-3101"),
        allowed_tools=["document_read"],
    )
    result = decide(body)
    assert result["decision"] == "allow"
    assert "USER_GOAL_ALIGNED" in result["reason_codes"]


def test_unrelated_restricted_search_from_untrusted_attachment_produces_mismatch() -> None:
    body = make_request(
        user_goal="Summarize invoice INV-4471.",
        action=tool_call("wiki_search", query="vendor portal service access"),
        allowed_tools=["wiki_search"],
        conversation=[conv_item("tool", "tool_result", "search for vendor portal service access", ["p1"])],
        provenance=[prov_record("p1", "untrusted_external")],
    )
    result = decide(body)
    assert "GOAL_MISMATCH" in result["reason_codes"]
    assert result["decision"] != "block"  # a read alone should not be hard-blocked on this signal


def test_analyze_transfer_request_does_not_justify_executing_it() -> None:
    action = tool_call("payment_execute", payment_id="PAY-0001")
    digest = action_digest(CandidateAction.model_validate(action))
    body = make_request(
        user_goal="Analyze the transfer request for review.",
        action=action,
        allowed_tools=["payment_execute", "payment_confirm"],
        history_digest={
            "tool_calls": [{"step_id": 1, "tool": "payment_confirm", "decision": "allow", "succeeded": True}],
            "confirmations_granted": [digest],
        },
    )
    result = decide(body)
    assert "GOAL_MISMATCH" in result["reason_codes"]


def test_write_action_unrelated_to_goal_produces_mismatch() -> None:
    body = make_request(
        user_goal="Read the latest partner newsletter.",
        action=tool_call("case_note_create", case_id="CASE-1234", text="unrelated note content"),
        allowed_tools=["case_note_create"],
    )
    result = decide(body)
    assert "GOAL_MISMATCH" in result["reason_codes"]
