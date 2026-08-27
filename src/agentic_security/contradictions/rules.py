"""Rule-only potential conflict detection; no model adjudication."""

from collections.abc import Iterable
from datetime import datetime

from agentic_security.models import (
    Assertion,
    AssertionScope,
    AssertionState,
    ContradictionFlag,
    ContradictionResolution,
    Evidence,
    SourceClass,
    SubjectType,
)


def flag_contradictions(
    assertions: Iterable[Assertion],
    evidence_by_id: dict[str, Evidence],
) -> tuple[ContradictionFlag, ...]:
    items = tuple(assertions)
    flags: list[ContradictionFlag] = []
    for index, left in enumerate(items):
        for right in items[index + 1 :]:
            same_subject = (
                left.system_id,
                left.agent_id,
                left.slots.subject_type,
                left.slots.subject,
            ) == (
                right.system_id,
                right.agent_id,
                right.slots.subject_type,
                right.slots.subject,
            )
            if same_subject and {
                left.state,
                right.state,
            } == {AssertionState.AFFIRMED, AssertionState.EXPLICITLY_UNSUPPORTED}:
                flags.append(
                    ContradictionFlag(
                        id=f"CONFLICT-STATE-{len(flags) + 1}",
                        assertion_ids=(left.id, right.id),
                        detected_by="rule:same-subject-conflicting-state",
                        rationale="Same subject has affirmed and explicitly unsupported states.",
                    )
                )
            if same_subject and left.statement != right.statement:
                if left.slots.subject_type is SubjectType.AVAILABILITY:
                    flags.append(
                        ContradictionFlag(
                            id=f"CONFLICT-AVAILABILITY-{len(flags) + 1}",
                            assertion_ids=(left.id, right.id),
                            detected_by="rule:availability-source-conflict",
                            rationale=("Sources establish incompatible availability descriptions."),
                        )
                    )
                if left.slots.subject_type is SubjectType.BENCHMARK_RESULT:
                    classes = {
                        evidence_by_id[evidence_id].source_class
                        for assertion in (left, right)
                        for evidence_id in assertion.evidence_ids
                        if evidence_id in evidence_by_id
                    }
                    if SourceClass.P2 in classes and classes & {SourceClass.R2, SourceClass.I1}:
                        flags.append(
                            ContradictionFlag(
                                id=f"CONFLICT-BENCHMARK-{len(flags) + 1}",
                                assertion_ids=(left.id, right.id),
                                detected_by="rule:benchmark-claim-vs-operator-record",
                                rationale=(
                                    "Vendor benchmark claim differs from an operator or "
                                    "independent record."
                                ),
                            )
                        )
    for assertion in items:
        support = [
            evidence_by_id[item] for item in assertion.evidence_ids if item in evidence_by_id
        ]
        contrary = [
            evidence_by_id[item]
            for item in assertion.contradicting_evidence_ids
            if item in evidence_by_id
        ]
        if (
            assertion.slots.subject in {"remediation", "autonomous-investigation"}
            and any(item.source_class is SourceClass.P2 for item in support)
            and any(item.source_class is SourceClass.P1 for item in contrary)
        ):
            flags.append(
                ContradictionFlag(
                    id=f"CONFLICT-AUTONOMY-{len(flags) + 1}",
                    assertion_ids=(assertion.id,),
                    detected_by="rule:autonomy-claim-vs-gate-doc",
                    rationale=(
                        "Official marketing autonomy claim conflicts with primary "
                        "gate documentation."
                    ),
                )
            )
    return tuple(flags)


def resolve_conflict(
    conflict: ContradictionFlag,
    *,
    resolution_id: str,
    resolution: str,
    resulting_state: AssertionState,
    resulting_scope: AssertionScope,
    reviewer: str,
    reviewed_at: datetime,
) -> ContradictionResolution:
    """Create the human resolution record; rules never adjudicate automatically."""
    return ContradictionResolution(
        id=resolution_id,
        conflict_id=conflict.id,
        resolution=resolution,
        resulting_state=resulting_state,
        resulting_scope=resulting_scope,
        reviewer=reviewer,
        reviewed_at=reviewed_at,
    )
