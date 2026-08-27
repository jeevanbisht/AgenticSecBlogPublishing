"""Versioned Gate A methodology derivations."""

from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from agentic_security.models import (
    AssertionScope,
    AutonomyAssessment,
    CapabilityEvidenceLevel,
    CapabilityEvidencePanel,
    ClaimPurpose,
    CommercialRelationship,
    Evidence,
    EvidenceMaturity,
    Freshness,
    FundingRelationship,
    HumanGate,
    IndependenceDesignation,
    IndependenceFacets,
    MethodologyId,
    Observation,
    PermissionScope,
    SourceClass,
    SupportConfidence,
    Trigger,
)

METHODOLOGY_VERSION = "ASI-1.0"
FRESHNESS_RULE_VERSION = "freshness-1.0"


def derive_freshness(
    last_verified_at: datetime,
    *,
    as_of: datetime | None = None,
) -> Freshness:
    """Derive freshness; freshness is never persisted on Assertion."""
    now = as_of or datetime.now(UTC)
    age = now - last_verified_at
    if age <= timedelta(days=30):
        return Freshness.FRESH
    if age <= timedelta(days=90):
        return Freshness.AGING
    if age <= timedelta(days=180):
        return Freshness.STALE
    return Freshness.REVALIDATION_REQUIRED


def derive_current_scope(assertion_id: str, observations: Iterable[Observation]) -> AssertionScope:
    """Return scope from the latest accepted observation only."""
    accepted = [
        item for item in observations if item.assertion_id == assertion_id and item.accepted
    ]
    if not accepted:
        return AssertionScope()
    return max(accepted, key=lambda item: (item.observed_at, item.id)).scope


def derive_independence(facets: IndependenceFacets) -> IndependenceDesignation:
    """Derive evaluator independence conservatively under ASI-1.0."""
    if (
        facets.funding_relationship is FundingRelationship.UNDISCLOSED
        or facets.commercial_relationship is CommercialRelationship.UNDISCLOSED
    ):
        return IndependenceDesignation.UNDETERMINED
    if facets.commercial_relationship is CommercialRelationship.VENDOR_SELF:
        return IndependenceDesignation.VENDOR_SELF
    if facets.funding_relationship in {
        FundingRelationship.COMMISSIONED,
        FundingRelationship.EMPLOYMENT,
    }:
        return IndependenceDesignation.VENDOR_SELF
    if (
        facets.vendor_selected_methodology
        or facets.vendor_operated_test
        or facets.vendor_reviewed_before_publication
    ):
        return IndependenceDesignation.VENDOR_INFLUENCED
    if facets.reproducible_method:
        return IndependenceDesignation.INDEPENDENT
    return IndependenceDesignation.UNDETERMINED


def derive_support_confidence(
    evidence: Iterable[Evidence],
    freshness: Freshness,
    *,
    has_unresolved_contradiction: bool = False,
) -> SupportConfidence:
    """Apply the ASI-1.0 assertion support rubric."""
    items = tuple(evidence)
    if (
        has_unresolved_contradiction
        or freshness in {Freshness.STALE, Freshness.REVALIDATION_REQUIRED}
        or not items
    ):
        return SupportConfidence.LOW
    non_derivative = tuple(item for item in items if item.derivative_of_evidence_id is None)
    if freshness is Freshness.FRESH and any(
        item.source_class is SourceClass.P1 and item.maturity is not EvidenceMaturity.E0
        for item in non_derivative
    ):
        return SupportConfidence.HIGH
    if freshness is Freshness.AGING or any(
        item.source_class
        in {SourceClass.P2, SourceClass.R1, SourceClass.R2, SourceClass.O1, SourceClass.I1}
        for item in non_derivative
    ):
        return SupportConfidence.MEDIUM
    return SupportConfidence.LOW


def provenance_independent_count(
    evidence: Iterable[Evidence], root_by_evidence: dict[str, str]
) -> int:
    """Count unique provenance roots, excluding derivative inflation."""
    return len(
        {
            root_by_evidence.get(item.id, item.id)
            for item in evidence
            if item.derivative_of_evidence_id is None
        }
    )


def derive_autonomy_label(assessment: AutonomyAssessment) -> str:
    """Derive the A0-A4 display label from stored facets under ASI-1.0."""
    trigger = Trigger(assessment.trigger.value)
    permission = PermissionScope(assessment.permission_scope.value)
    gate = HumanGate(assessment.human_gate.value)
    action_gates = {HumanGate(value.value) for value in assessment.action_human_gates.values()}
    all_gates = action_gates | {gate}
    if (
        trigger is Trigger.CONTINUOUS
        and permission is not PermissionScope.READ_ONLY
        and all_gates <= {HumanGate.NONE, HumanGate.NOTIFY_ONLY}
    ):
        return "A4"
    if trigger in {Trigger.EVENT_DRIVEN, Trigger.SCHEDULED, Trigger.CONTINUOUS}:
        return "A3"
    if trigger is Trigger.HUMAN_INITIATED and permission in {
        PermissionScope.SCOPED_WRITE,
        PermissionScope.BROAD_WRITE,
    }:
        return "A2"
    if trigger is Trigger.HUMAN_INITIATED and permission is PermissionScope.READ_ONLY:
        return "A0" if gate is HumanGate.PRE_ACTION else "A1"
    return "A1"


def derive_capability_evidence_panel(
    capability_id: str,
    evidence: Iterable[Evidence],
    methodology_version: MethodologyId = METHODOLOGY_VERSION,
) -> CapabilityEvidencePanel:
    """Build the non-conflating capability panel from evidence kinds."""
    items = tuple(evidence)
    vendor = [
        e
        for e in items
        if e.claim_purpose is ClaimPurpose.DOCUMENTATION
        and e.maturity
        in {
            EvidenceMaturity.E1,
            EvidenceMaturity.E2,
            EvidenceMaturity.E3,
            EvidenceMaturity.E4,
            EvidenceMaturity.E5,
        }
        and e.source_class in {SourceClass.P1, SourceClass.P2}
    ]
    demos = [
        e
        for e in items
        if e.claim_purpose is ClaimPurpose.DEMONSTRATION
        and e.maturity
        in {
            EvidenceMaturity.E2,
            EvidenceMaturity.E3,
            EvidenceMaturity.E4,
            EvidenceMaturity.E5,
        }
    ]
    independent = [
        e
        for e in items
        if e.claim_purpose is ClaimPurpose.INDEPENDENT_VALIDATION
        and e.maturity in {EvidenceMaturity.E3, EvidenceMaturity.E4, EvidenceMaturity.E5}
        if e.independence_facets
        and derive_independence(e.independence_facets) is IndependenceDesignation.INDEPENDENT
    ]
    production = [
        e
        for e in items
        if e.claim_purpose is ClaimPurpose.EFFECTIVENESS
        and e.maturity in {EvidenceMaturity.E4, EvidenceMaturity.E5}
        and e.independence_facets
        and derive_independence(e.independence_facets) is IndependenceDesignation.INDEPENDENT
        and e.independence_facets.public_environment
    ]
    return CapabilityEvidencePanel(
        capability_id=capability_id,
        vendor_documentation=(
            CapabilityEvidenceLevel.HIGH if vendor else CapabilityEvidenceLevel.NONE_FOUND
        ),
        public_demonstration=(
            CapabilityEvidenceLevel.MEDIUM if demos else CapabilityEvidenceLevel.NONE_FOUND
        ),
        independent_validation=(
            CapabilityEvidenceLevel.HIGH if independent else CapabilityEvidenceLevel.NONE_FOUND
        ),
        production_effectiveness=(
            CapabilityEvidenceLevel.MEDIUM if production else CapabilityEvidenceLevel.UNKNOWN
        ),
        methodology_version=methodology_version,
        rationale=(
            "Rows represent evidence categories; assertion support confidence is intentionally "
            "not rendered beside the capability name."
        ),
    )
