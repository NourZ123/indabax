"""Shared request-building helpers for the test suite. All tests exercise the defense through
its actual HTTP contract (POST /v1/decision), the same way the evaluator does.
"""

from __future__ import annotations

from typing import Any

from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def prov_record(
    id: str,
    trust_level: str,
    sensitivity: str = "internal",
    source_type: str = "document",
    origin_actor: str = "actor",
    retrieved_via: str = "tool",
    timestamp: str = "2026-09-01T08:00:00Z",
) -> dict[str, Any]:
    return {
        "id": id,
        "provenance": {
            "source_type": source_type,
            "source_id": id.upper(),
            "trust_level": trust_level,
            "origin_actor": origin_actor,
            "retrieved_via": retrieved_via,
            "sensitivity": sensitivity,
            "timestamp": timestamp,
        },
    }


def conv_item(role: str, kind: str, content: str, provenance_ids: list[str] | None = None) -> dict[str, Any]:
    return {"role": role, "kind": kind, "content": content, "provenance_ids": provenance_ids or []}


def tool_call(tool: str, **arguments: Any) -> dict[str, Any]:
    return {"type": "tool_call", "tool": tool, "arguments": arguments}


def respond_action(content: str, final: bool = False) -> dict[str, Any]:
    return {"type": "respond", "content": content, "final": final}


def memory_write_action(content: str) -> dict[str, Any]:
    return {"type": "memory_write", "content": content}


def request_confirmation_action(target: dict[str, Any]) -> dict[str, Any]:
    return {"type": "request_confirmation", "confirmation_for": target, "content": "please confirm"}


def make_request(
    *,
    user_goal: str,
    action: dict[str, Any],
    allowed_tools: list[str],
    consequential_tools: list[str] | None = None,
    confirmation_required_tools: list[str] | None = None,
    internal_email_domains: list[str] | None = None,
    conversation: list[dict[str, Any]] | None = None,
    provenance: list[dict[str, Any]] | None = None,
    observation: dict[str, Any] | None = None,
    history_digest: dict[str, Any] | None = None,
    run_id: str = "r1",
    step_id: int = 1,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "step_id": step_id,
        "user_goal": user_goal,
        "conversation": conversation or [],
        "observation": observation,
        "candidate_action": action,
        "policy_context": {
            "allowed_tools": allowed_tools,
            "consequential_tools": consequential_tools or [],
            "confirmation_required_tools": confirmation_required_tools or [],
            "internal_email_domains": internal_email_domains if internal_email_domains is not None else ["atlas.example"],
        },
        "provenance": provenance or [],
        "history_digest": history_digest or {},
    }


def decide(body: dict[str, Any]) -> dict[str, Any]:
    response = client.post("/v1/decision", json=body)
    assert response.status_code == 200, response.text
    return response.json()
