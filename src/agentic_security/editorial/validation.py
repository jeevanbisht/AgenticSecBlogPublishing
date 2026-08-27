"""Claim verification and editorial-risk policy."""

import re
from collections.abc import Iterable

from agentic_security.models import ClaimCheck, EditorialRisk, Evidence

_HIGH = re.compile(
    r"\b(zero[- ]day|exploitability|breach|named victim|attribution|security failure|"
    r"unpublished vulnerability|accusation)\b",
    re.I,
)
_MEDIUM = re.compile(r"\b(compare|benchmark|architecture|trend|better than|leader)\b", re.I)


def classify_editorial_risk(text: str) -> EditorialRisk:
    if _HIGH.search(text):
        return EditorialRisk.HIGH
    if _MEDIUM.search(text):
        return EditorialRisk.MEDIUM
    return EditorialRisk.LOW


def verify_claims(
    claims: Iterable[str],
    evidence_ids_by_claim: dict[str, tuple[str, ...]],
    evidence_by_id: dict[str, Evidence],
) -> tuple[ClaimCheck, ...]:
    checks = []
    for claim in claims:
        ids = evidence_ids_by_claim.get(claim, ())
        available = tuple(item for item in ids if item in evidence_by_id)
        checks.append(
            ClaimCheck(
                claim=claim,
                evidence_ids=available,
                supported=bool(available),
                rationale=(
                    "Claim has traceable evidence."
                    if available
                    else "Unsupported factual claim: no traceable evidence."
                ),
            )
        )
    return tuple(checks)


def require_human_review(text: str, *, human_approved: bool) -> None:
    if classify_editorial_risk(text) is EditorialRisk.HIGH and not human_approved:
        raise ValueError("HIGH-risk editorial content requires explicit human review")
