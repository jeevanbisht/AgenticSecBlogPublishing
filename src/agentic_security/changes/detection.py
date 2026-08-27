"""Deterministic snapshot comparison and structured change classification."""

from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher

from agentic_security.models import (
    ChangeClassification,
    DecisionImpact,
    EvidenceStatusChangeSubtype,
    Snapshot,
    StructuredDiff,
)

_SYNONYMS = {
    "performs": "perform",
    "performed": "perform",
    "triages": "triage",
    "triaged": "triage",
    "investigates": "investigate",
    "automatically": "autonomous",
    "generally available": "ga",
    "general availability": "ga",
    "human approval": "approval",
    "requires approval": "approval",
}
_COSMETIC = re.compile(
    r"^(last updated|updated|copyright|cookie|skip to|table of contents)\b", re.I
)
_TRACKING = re.compile(r"\b(utm_[a-z]+|ref|tracking-id)=[^\s&]+", re.I)
_INDEPENDENT_VALIDATION = re.compile(
    r"\b(?:independent validation|independently validated|independently designed|"
    r"source class i1|i1/e3)\b",
    re.I,
)
_NEGATED_INDEPENDENT_VALIDATION = re.compile(
    r"\b(?:"
    r"no|not|without|lacks?|missing|neither|never|none(?:[\s_]+found)?|"
    r"has\s+not|have\s+not|had\s+not|is\s+not|was\s+not|were\s+not"
    r")\b.{0,80}\b(?:independent validation|independently validated|"
    r"independently designed|source class i1|i1/e3)\b"
    r"|\b(?:independent validation|independently validated|independently designed|"
    r"source class i1|i1/e3)\b.{0,80}\b(?:"
    r"removed|withdrawn|retracted|revoked|unpublished|unavailable|"
    r"has\s+not|have\s+not|had\s+not|is\s+not|was\s+not|were\s+not|"
    r"does\s+not|did\s+not|not published|no longer|none[\s_]*found"
    r")\b",
    re.I,
)


def _semantic(text: str) -> str:
    value = text.lower()
    for phrase, replacement in _SYNONYMS.items():
        value = value.replace(phrase, replacement)
    value = _TRACKING.sub("", value)
    value = re.sub(r"\b(the|a|an|is|are|by|for|to|of|and)\b", " ", value)
    return " ".join(sorted(re.findall(r"[a-z0-9]+", value)))


def _meaningful_lines(text: str) -> tuple[str, ...]:
    return tuple(
        line.strip() for line in text.splitlines() if line.strip() and not _COSMETIC.match(line)
    )


def detect_change(
    old: Snapshot,
    new: Snapshot,
    *,
    diff_id: str,
    derivative_only: bool = False,
) -> StructuredDiff:
    """Compare stored normalized snapshots without executing historical normalizers."""
    if old.source_id != new.source_id:
        raise ValueError("snapshots must belong to the same source")
    old_lines = _meaningful_lines(old.normalized_text)
    new_lines = _meaningful_lines(new.normalized_text)
    old_set, new_set = set(old_lines), set(new_lines)
    added = tuple(sorted(new_set - old_set))
    removed = tuple(sorted(old_set - new_set))
    cosmetic_only = old.normalized_text == new.normalized_text or not (added or removed)
    old_semantic = _semantic("\n".join(old_lines))
    new_semantic = _semantic("\n".join(new_lines))
    similarity = SequenceMatcher(None, old_semantic, new_semantic).ratio()
    paraphrase_only = not cosmetic_only and (old_semantic == new_semantic or similarity >= 0.9)
    material = bool(added or removed) and not (cosmetic_only or paraphrase_only or derivative_only)
    evidence_status_subtype = _evidence_status_subtype(added, removed) if material else None
    digest = hashlib.sha256(
        "\n".join((old.sha256, new.sha256, *removed, "--", *added)).encode()
    ).hexdigest()
    return StructuredDiff(
        id=diff_id,
        source_id=old.source_id,
        old_snapshot_id=old.id,
        new_snapshot_id=new.id,
        added=added,
        removed=removed,
        cosmetic_only=cosmetic_only,
        paraphrase_only=paraphrase_only,
        derivative_only=derivative_only,
        material_candidate=material,
        evidence_status_subtype=evidence_status_subtype,
        fingerprint=digest,
    )


def _evidence_status_subtype(
    added: tuple[str, ...], removed: tuple[str, ...]
) -> EvidenceStatusChangeSubtype | None:
    added_text = " ".join(added).lower()
    all_text = f"{added_text} {' '.join(removed).lower()}"
    if any(
        term in added_text
        for term in ("contradicting evidence", "contradiction added", "evidence conflict")
    ):
        return EvidenceStatusChangeSubtype.EVIDENCE_CONTRADICTION_ADDED
    if _INDEPENDENT_VALIDATION.search(added_text) and not _NEGATED_INDEPENDENT_VALIDATION.search(
        added_text
    ):
        return EvidenceStatusChangeSubtype.INDEPENDENT_VALIDATION_ADDED
    if any(
        term in all_text
        for term in (
            "evidence maturity",
            "maturity changed",
            "reproducibly evaluated",
            " e2 ",
            " e3 ",
            " e4 ",
            " e5 ",
        )
    ):
        return EvidenceStatusChangeSubtype.EVIDENCE_MATURITY_CHANGED
    return None


def classify_diff(
    diff: StructuredDiff,
) -> tuple[ChangeClassification, frozenset[DecisionImpact], str]:
    """Produce a deterministic proposal; a human must confirm it and its impacts."""
    if not diff.material_candidate:
        return (
            ChangeClassification.NOT_MATERIAL,
            frozenset(),
            "Filtered deterministic non-material change.",
        )
    if diff.evidence_status_subtype is not None:
        return (
            ChangeClassification.EVIDENCE_STATUS_CHANGE,
            frozenset({DecisionImpact.EVALUATION, DecisionImpact.PROCUREMENT}),
            f"Evidence establishment changed: {diff.evidence_status_subtype.value}.",
        )
    text = " ".join((*diff.added, *diff.removed)).lower()
    removed_text = " ".join(diff.removed).lower()
    added_text = " ".join(diff.added).lower()
    if "agent" in removed_text and "agent" not in added_text:
        return (
            ChangeClassification.AGENT_REMOVAL,
            frozenset({DecisionImpact.ARCHITECTURE, DecisionImpact.RISK}),
            "Agent terminology was removed without a replacement.",
        )
    if any(word in removed_text for word in ("capability", "supports", "can ")) and not any(
        word in added_text for word in ("capability", "supports", "can ")
    ):
        return (
            ChangeClassification.CAPABILITY_REMOVAL,
            frozenset({DecisionImpact.OPERATIONS, DecisionImpact.RISK}),
            "Capability language was removed without a replacement.",
        )
    rules: tuple[tuple[tuple[str, ...], ChangeClassification, frozenset[DecisionImpact]], ...] = (
        (
            ("generally available", " ga ", "public preview", "private preview"),
            ChangeClassification.AVAILABILITY_LIFECYCLE_CHANGE,
            frozenset({DecisionImpact.DEPLOYMENT, DecisionImpact.PROCUREMENT}),
        ),
        (
            ("new agent", "agent added", "verification agent", "specialized agent"),
            ChangeClassification.AGENT_ADDITION,
            frozenset({DecisionImpact.ARCHITECTURE, DecisionImpact.RISK}),
        ),
        (
            ("approval", "human gate", "pre-action", "post-action"),
            ChangeClassification.APPROVAL_CHANGE,
            frozenset({DecisionImpact.AUTHORIZATION, DecisionImpact.OPERATIONS}),
        ),
        (
            ("permission", "read-only", "write access", "authorization"),
            ChangeClassification.PERMISSION_CHANGE,
            frozenset({DecisionImpact.AUTHORIZATION, DecisionImpact.RISK}),
        ),
        (
            ("trigger", "event-driven", "scheduled", "continuous"),
            ChangeClassification.TRIGGER_CHANGE,
            frozenset({DecisionImpact.OPERATIONS, DecisionImpact.RISK}),
        ),
        (
            ("benchmark", "score", "success rate"),
            ChangeClassification.BENCHMARK_RESULT_CHANGE,
            frozenset({DecisionImpact.EVALUATION, DecisionImpact.PROCUREMENT}),
        ),
        (
            ("architecture", "supervisor", "multi-agent", "orchestration"),
            ChangeClassification.ARCHITECTURE_CHANGE,
            frozenset({DecisionImpact.ARCHITECTURE, DecisionImpact.RISK}),
        ),
        (
            ("model", "llm", "foundation model"),
            ChangeClassification.MODEL_CHANGE,
            frozenset({DecisionImpact.ARCHITECTURE, DecisionImpact.EVALUATION}),
        ),
        (
            ("deprecated", "retired", "end of support"),
            ChangeClassification.DOCUMENTATION_DEPRECATION,
            frozenset({DecisionImpact.DEPLOYMENT, DecisionImpact.PROCUREMENT}),
        ),
        (
            ("autonomy", "persistent", "session-bound"),
            ChangeClassification.AUTONOMY_FACET_CHANGE,
            frozenset({DecisionImpact.AUTHORIZATION, DecisionImpact.OPERATIONS}),
        ),
        (
            ("capability", "can now", "supports", "triage", "investigate", "remediate"),
            ChangeClassification.CAPABILITY_ADDITION,
            frozenset({DecisionImpact.OPERATIONS, DecisionImpact.EVALUATION}),
        ),
    )
    padded = f" {text} "
    for keywords, classification, impacts in rules:
        if any(keyword in padded for keyword in keywords):
            rationale = f"Matched deterministic keywords: {', '.join(keywords)}."
            return classification, impacts, rationale
    return (
        ChangeClassification.CONTROL_CHANGE,
        frozenset({DecisionImpact.ARCHITECTURE}),
        "Surviving structured change requires analyst classification.",
    )
