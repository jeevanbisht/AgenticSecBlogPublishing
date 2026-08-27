"""Human-gated materiality and decision-impact review."""

from datetime import datetime

from agentic_security.changes.detection import classify_diff
from agentic_security.models import (
    ChangeClassification,
    ChangeReviewItem,
    DecisionImpact,
    ReviewStatus,
    StructuredDiff,
)


def create_review(diff: StructuredDiff, review_id: str) -> ChangeReviewItem:
    classification, impacts, rationale = classify_diff(diff)
    return ChangeReviewItem(
        id=review_id,
        candidate_id=diff.id,
        machine_classification=classification,
        machine_decision_impacts=impacts,
        machine_rationale=rationale,
        evidence_status_subtype=diff.evidence_status_subtype,
        methodology_version="ASI-1.0",
    )


def confirm_review(
    item: ChangeReviewItem,
    *,
    review_id: str | None = None,
    reviewer: str,
    reviewed_at: datetime,
    classification: ChangeClassification,
    decision_impacts: frozenset[DecisionImpact],
    rationale: str = "Human reviewer confirmed the classification and decision impact.",
) -> ChangeReviewItem:
    if item.status is not ReviewStatus.PENDING:
        raise ValueError(
            "a completed review cannot be overwritten; append from the machine proposal"
        )
    return ChangeReviewItem(
        id=review_id or f"{item.id}-H1",
        candidate_id=item.candidate_id,
        machine_classification=item.machine_classification,
        machine_rationale=item.machine_rationale,
        machine_decision_impacts=item.machine_decision_impacts,
        evidence_status_subtype=item.evidence_status_subtype,
        status=ReviewStatus.CONFIRMED,
        reviewer=reviewer,
        reviewed_at=reviewed_at,
        human_classification=classification,
        confirmed_decision_impacts=decision_impacts,
        human_rationale=rationale,
        methodology_version=item.methodology_version,
        prior_review_id=item.id,
    )
