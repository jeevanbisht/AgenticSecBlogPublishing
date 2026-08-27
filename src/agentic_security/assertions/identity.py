"""Stable ontology-key identity."""

from agentic_security.models import AssertionSlots


def assertion_key(slots: AssertionSlots) -> str:
    """Build identity from controlled ontology slots, never prose."""
    agent = slots.agent or "_system"
    return ":".join((slots.system, agent, slots.subject, slots.action, slots.object))


def candidate_matches(existing_key: str, slots: AssertionSlots) -> bool:
    """Return whether an extracted candidate belongs to an existing assertion."""
    return existing_key == assertion_key(slots)
