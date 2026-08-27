"""Deterministic golden fixtures for the Gate B review packet."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from agentic_security.changes.detection import detect_change
from agentic_security.changes.review import confirm_review, create_review
from agentic_security.collection.base import build_snapshot
from agentic_security.contradictions.rules import flag_contradictions
from agentic_security.derivations import derive_capability_evidence_panel
from agentic_security.fixtures import gate_a_packet
from agentic_security.models import (
    ChangeClassification,
    ChangeReviewItem,
    ClaimPurpose,
    DecisionImpact,
    Evidence,
    EvidenceAnchor,
    EvidenceMaturity,
    Snapshot,
    SourceClass,
    StructuredDiff,
)

NOW = datetime(2026, 8, 26, tzinfo=UTC)

GOLDEN_PAIRS: dict[str, tuple[str, str, bool]] = {
    "unchanged": ("Blue agents triage alerts.", "Blue agents triage alerts.", False),
    "cosmetic-only": (
        "<h1>Blue agents</h1><p>Blue agents triage alerts.</p>",
        "<nav>Skip to content</nav><h1>Blue agents</h1><p>Blue agents triage alerts.</p>",
        False,
    ),
    "paraphrase-only": (
        "Blue agents triage supported security alerts.",
        "Supported security alerts are triaged by blue agents.",
        False,
    ),
    "capability-change": (
        "Blue agents triage supported security alerts.",
        "Blue agents triage supported security alerts and can now remediate incidents.",
        False,
    ),
    "preview-ga": (
        "Project Perception is in public preview.",
        "Project Perception is generally available.",
        False,
    ),
    "agent-addition": (
        "Project Perception has red and blue agents.",
        "Project Perception has red and blue agents. A new agent, "
        "the green verification agent, was added.",
        False,
    ),
    "derivative-press": (
        "Vendor reports benchmark score 82%.",
        "Press repeats that the vendor reports benchmark score 82%.",
        True,
    ),
    "independence": (
        "Independent validation: NONE_FOUND.",
        "Independent validation added: source class I1, maturity E3, "
        "reproducibly evaluated under an unrestricted grant.",
        False,
    ),
}


def gate_b_fixture() -> dict[str, Any]:
    packet = gate_a_packet()
    diffs: list[StructuredDiff] = []
    reviews: list[ChangeReviewItem] = []
    snapshots: list[Snapshot] = []
    for index, (name, (old_text, new_text, derivative)) in enumerate(GOLDEN_PAIRS.items(), 1):
        old = build_snapshot(
            snapshot_id=f"SNAP-GOLDEN-{index}-OLD",
            source_id="SRC-MS-DOCS",
            canonical_uri=f"fixture://golden/{name}/old",
            content_type="text/html",
            raw_text=old_text,
            retrieved_at=NOW,
        )
        new = build_snapshot(
            snapshot_id=f"SNAP-GOLDEN-{index}-NEW",
            source_id="SRC-MS-DOCS",
            canonical_uri=f"fixture://golden/{name}/new",
            content_type="text/html",
            raw_text=new_text,
            retrieved_at=NOW,
        )
        diff = detect_change(
            old,
            new,
            diff_id=f"DIFF-GOLDEN-{index}",
            derivative_only=derivative,
        )
        snapshots.extend((old, new))
        diffs.append(diff)
        reviews.append(create_review(diff, f"REVIEW-GOLDEN-{index}"))
    evidence = {item.id: item for item in packet.evidence}
    conflicts = flag_contradictions(packet.assertions, evidence)
    baseline_panel = derive_capability_evidence_panel("alert-triage", (evidence["EV-TRIAGE"],))
    independent_template = evidence["EV-INDEPENDENT-GRANT"]
    validation_snapshot = build_snapshot(
        snapshot_id="SNAP-TRIAGE-INDEPENDENT",
        source_id=independent_template.source_id,
        canonical_uri="fixture://golden/independent-triage",
        content_type="text/markdown",
        raw_text=(
            "The university independently reproduced alert-triage results "
            "in a public evaluation environment."
        ),
        retrieved_at=NOW,
    )
    quote = validation_snapshot.normalized_text
    independent_validation = Evidence(
        id="EV-TRIAGE-INDEPENDENT",
        source_id=independent_template.source_id,
        source_class=SourceClass.I1,
        maturity=EvidenceMaturity.E3,
        claim_purpose=ClaimPurpose.INDEPENDENT_VALIDATION,
        anchor=EvidenceAnchor(
            snapshot_id=validation_snapshot.id,
            snapshot_sha256=validation_snapshot.sha256,
            normalizer_version=validation_snapshot.normalizer_version,
            document_path="/fixture/independent-triage",
            document_heading="Independent alert-triage evaluation",
            quote=quote,
            start_offset=0,
            end_offset=len(quote),
        ),
        published_at=NOW,
        first_seen_at=NOW,
        retrieved_at=NOW,
        last_seen_at=NOW,
        last_verified_at=NOW,
        independence_facets=independent_template.independence_facets,
    )
    updated_panel = derive_capability_evidence_panel(
        "alert-triage", (evidence["EV-TRIAGE"], independent_validation)
    )
    evidence_diff = diffs[list(GOLDEN_PAIRS).index("independence")]
    evidence_machine_review = reviews[list(GOLDEN_PAIRS).index("independence")]
    evidence_human_review = confirm_review(
        evidence_machine_review,
        review_id="REVIEW-GOLDEN-EVIDENCE-H1",
        reviewer="gate-b-fixture-analyst",
        reviewed_at=NOW,
        classification=ChangeClassification.EVIDENCE_STATUS_CHANGE,
        decision_impacts=frozenset({DecisionImpact.EVALUATION, DecisionImpact.PROCUREMENT}),
        rationale="Confirmed that independent I1/E3 evidence changes the evidence panel.",
    )
    return {
        "snapshots": (*snapshots, validation_snapshot),
        "diffs": tuple(diffs),
        "reviews": tuple(reviews),
        "conflicts": conflicts,
        "evidence_status_flow": {
            "candidate": evidence_diff,
            "machine_review": evidence_machine_review,
            "human_review": evidence_human_review,
            "evidence": independent_validation,
            "before_panel": baseline_panel,
            "after_panel": updated_panel,
        },
    }
