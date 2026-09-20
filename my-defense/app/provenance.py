"""Provenance and trust-level helpers."""

from app.models import DefenseRequest

UNTRUSTED = {"untrusted_internal", "untrusted_external", "adversary_controlled"}


def untrusted_texts(request: DefenseRequest) -> list[str]:
    trust = {record.id: record.provenance.trust_level for record in request.provenance}
    return [
        item.content.lower()
        for item in request.conversation
        if any(trust.get(pid) in UNTRUSTED for pid in item.provenance_ids)
    ]
