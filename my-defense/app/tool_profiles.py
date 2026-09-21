"""Central table of generic tool semantics for the enterprise/finance/soc domains.

Built from the official tool definitions (src/sentinel/domains/*/tools.py) and the
consequential/confirmation rules in policies/*.yaml. This is the single source of truth
for "is this tool read-only / a sink / consequential" -- no other module should hardcode
a tool list.

Unknown tools are never treated as safe: `profile_for` returns a conservative default
(not read-only, writes, both sinks, consequential) so an unrecognized tool is scrutinized
rather than waved through.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolProfile:
    category: str
    read_only: bool
    write: bool
    external_sink: bool  # can this tool's payload reach a destination outside the org
    internal_sink: bool  # can this tool's payload be written to an internal store
    consequential: bool  # statically consequential regardless of arguments
    reversible: bool
    dynamic_consequential_field: str | None = None  # arg name whose value can make it consequential
    dynamic_consequential_values: frozenset[str] = frozenset()


READ_ONLY_TOOLS: frozenset[str] = frozenset(
    {
        # enterprise
        "email_search",
        "email_read",
        "document_search",
        "document_read",
        "wiki_search",
        "ticket_read",
        # finance
        "customer_lookup",
        "account_summary",
        "case_document_read",
        "policy_search",
        # soc
        "alert_search",
        "alert_read",
        "asset_lookup",
        "intel_search",
    }
)

_PROFILES: dict[str, ToolProfile] = {
    # ---- enterprise: reads --------------------------------------------------------------
    "email_search": ToolProfile("enterprise", True, False, False, False, False, True),
    "email_read": ToolProfile("enterprise", True, False, False, False, False, True),
    "document_search": ToolProfile("enterprise", True, False, False, False, False, True),
    "document_read": ToolProfile("enterprise", True, False, False, False, False, True),
    "wiki_search": ToolProfile("enterprise", True, False, False, False, False, True),
    "ticket_read": ToolProfile("enterprise", True, False, False, False, False, True),
    # ---- enterprise: writes ---------------------------------------------------------------
    "email_draft": ToolProfile("enterprise", False, True, True, True, False, True),
    "email_send": ToolProfile("enterprise", False, True, True, True, True, False),
    "ticket_update": ToolProfile(
        "enterprise", False, True, False, True, False, True, "status", frozenset({"closed", "resolved"})
    ),
    # ---- finance: reads ---------------------------------------------------------------
    "customer_lookup": ToolProfile("finance", True, False, False, False, False, True),
    "account_summary": ToolProfile("finance", True, False, False, False, False, True),
    "case_document_read": ToolProfile("finance", True, False, False, False, False, True),
    "policy_search": ToolProfile("finance", True, False, False, False, False, True),
    # ---- finance: writes ----------------------------------------------------------------
    "case_note_create": ToolProfile("finance", False, True, False, True, False, True),
    "payment_prepare": ToolProfile("finance", False, True, False, True, False, True),
    "payment_confirm": ToolProfile("finance", False, True, False, True, True, False),
    "payment_execute": ToolProfile("finance", False, True, False, True, True, False),
    # ---- soc: reads ---------------------------------------------------------------------
    "alert_search": ToolProfile("soc", True, False, False, False, False, True),
    "alert_read": ToolProfile("soc", True, False, False, False, False, True),
    "asset_lookup": ToolProfile("soc", True, False, False, False, False, True),
    "intel_search": ToolProfile("soc", True, False, False, False, False, True),
    # ---- soc: writes ----------------------------------------------------------------------
    "incident_create": ToolProfile("soc", False, True, False, True, False, True),
    "incident_update": ToolProfile(
        "soc", False, True, False, True, False, True, "status", frozenset({"closed"})
    ),
    "remediation_prepare": ToolProfile("soc", False, True, False, True, False, True),
    "remediation_execute": ToolProfile("soc", False, True, False, True, True, False),
}

_UNKNOWN_PROFILE = ToolProfile(
    category="unknown",
    read_only=False,
    write=True,
    external_sink=True,
    internal_sink=True,
    consequential=True,
    reversible=False,
)


def profile_for(tool: str | None) -> ToolProfile:
    if tool is None:
        return _UNKNOWN_PROFILE
    return _PROFILES.get(tool, _UNKNOWN_PROFILE)


def is_read_only(tool: str | None) -> bool:
    return tool in READ_ONLY_TOOLS


def is_known_tool(tool: str | None) -> bool:
    return tool in _PROFILES
