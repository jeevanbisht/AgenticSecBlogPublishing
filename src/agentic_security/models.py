"""First-class domain models for the ASI evidence ledger."""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

MethodologyId = Annotated[str, Field(pattern=r"^ASI-\d+\.\d+$")]
TaxonomyId = Annotated[str, Field(pattern=r"^ASI-TAXONOMY-\d+\.\d+$")]
SourceId = Annotated[str, Field(pattern=r"^SRC-[A-Z0-9-]+$")]
SnapshotId = Annotated[str, Field(pattern=r"^SNAP-[A-Z0-9-]+$")]
EvidenceId = Annotated[str, Field(pattern=r"^EV-[A-Z0-9-]+$")]
AssertionId = Annotated[str, Field(pattern=r"^ASRT-[A-Z0-9-]+$")]
ObservationId = Annotated[str, Field(pattern=r"^OBS-[A-Z0-9-]+$")]
ChangeId = Annotated[str, Field(pattern=r"^CHANGE-[A-Z0-9-]+$")]


class FrozenModel(BaseModel):
    """Strict immutable ledger value."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=False)


class TrustClass(StrEnum):
    PRIMARY = "PRIMARY"
    OFFICIAL = "OFFICIAL"
    RESEARCH = "RESEARCH"
    INDEPENDENT = "INDEPENDENT"
    COMMUNITY = "COMMUNITY"
    SECONDARY = "SECONDARY"
    UNVERIFIED = "UNVERIFIED"
    SELF = "SELF"


class RegistryStatus(StrEnum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    DISABLED = "DISABLED"


class SourceKind(StrEnum):
    HTTP = "HTTP"
    GIT = "GIT"
    FIXTURE = "FIXTURE"


class SourceRole(StrEnum):
    INPUT = "INPUT"
    OUTPUT = "OUTPUT"


class SourceClass(StrEnum):
    P1 = "P1"
    P2 = "P2"
    R1 = "R1"
    R2 = "R2"
    O1 = "O1"
    I1 = "I1"
    C1 = "C1"
    S1 = "S1"
    U = "U"


class EvidenceMaturity(StrEnum):
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"
    E5 = "E5"


class AssertionState(StrEnum):
    AFFIRMED = "AFFIRMED"
    EXPLICITLY_UNSUPPORTED = "EXPLICITLY_UNSUPPORTED"
    UNKNOWN = "UNKNOWN"
    PARTIAL = "PARTIAL"
    CONDITIONAL = "CONDITIONAL"
    DISPUTED = "DISPUTED"


class ClaimPurpose(StrEnum):
    DOCUMENTATION = "DOCUMENTATION"
    DEMONSTRATION = "DEMONSTRATION"
    BENCHMARK_RESULT = "BENCHMARK_RESULT"
    INDEPENDENT_VALIDATION = "INDEPENDENT_VALIDATION"
    EFFECTIVENESS = "EFFECTIVENESS"


class SubjectType(StrEnum):
    CAPABILITY = "capability"
    CONTROL = "control"
    ARCHITECTURE_PATTERN = "architecture_pattern"
    AUTONOMY_FACET = "autonomy_facet"
    AVAILABILITY = "availability"
    BENCHMARK_RESULT = "benchmark_result"


class SupportConfidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Freshness(StrEnum):
    FRESH = "FRESH"
    AGING = "AGING"
    STALE = "STALE"
    REVALIDATION_REQUIRED = "REVALIDATION_REQUIRED"


class AvailabilityState(StrEnum):
    UNKNOWN = "UNKNOWN"
    PRIVATE_PREVIEW = "PRIVATE_PREVIEW"
    LIMITED_PUBLIC_PREVIEW = "LIMITED_PUBLIC_PREVIEW"
    PUBLIC_PREVIEW = "PUBLIC_PREVIEW"
    GA = "GA"
    DEPRECATED = "DEPRECATED"


class FundingRelationship(StrEnum):
    NONE = "NONE"
    UNRESTRICTED_GRANT = "UNRESTRICTED_GRANT"
    COMMISSIONED = "COMMISSIONED"
    EMPLOYMENT = "EMPLOYMENT"
    UNDISCLOSED = "UNDISCLOSED"


class CommercialRelationship(StrEnum):
    NONE = "NONE"
    CUSTOMER = "CUSTOMER"
    PARTNER = "PARTNER"
    VENDOR_SELF = "VENDOR_SELF"
    UNDISCLOSED = "UNDISCLOSED"


class IndependenceDesignation(StrEnum):
    INDEPENDENT = "INDEPENDENT"
    VENDOR_INFLUENCED = "VENDOR_INFLUENCED"
    VENDOR_SELF = "VENDOR_SELF"
    UNDETERMINED = "UNDETERMINED"


class Trigger(StrEnum):
    HUMAN_INITIATED = "HUMAN_INITIATED"
    EVENT_DRIVEN = "EVENT_DRIVEN"
    SCHEDULED = "SCHEDULED"
    CONTINUOUS = "CONTINUOUS"


class Persistence(StrEnum):
    SESSION_BOUND = "SESSION_BOUND"
    PERSISTENT = "PERSISTENT"


class PermissionScope(StrEnum):
    READ_ONLY = "READ_ONLY"
    SCOPED_WRITE = "SCOPED_WRITE"
    BROAD_WRITE = "BROAD_WRITE"
    UNKNOWN = "UNKNOWN"


class HumanGate(StrEnum):
    PRE_ACTION = "PRE_ACTION"
    POST_ACTION = "POST_ACTION"
    NOTIFY_ONLY = "NOTIFY_ONLY"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ControlMaturity(StrEnum):
    C0 = "C0"
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    C4 = "C4"


class DecisionImpact(StrEnum):
    DEPLOYMENT = "DEPLOYMENT"
    AUTHORIZATION = "AUTHORIZATION"
    ARCHITECTURE = "ARCHITECTURE"
    RISK = "RISK"
    PROCUREMENT = "PROCUREMENT"
    OPERATIONS = "OPERATIONS"
    EVALUATION = "EVALUATION"


class CapabilityEvidenceLevel(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE_FOUND = "NONE_FOUND"
    UNKNOWN = "UNKNOWN"


class ChangeClassification(StrEnum):
    CAPABILITY_ADDITION = "CAPABILITY_ADDITION"
    CAPABILITY_REMOVAL = "CAPABILITY_REMOVAL"
    CONTROL_CHANGE = "CONTROL_CHANGE"
    AUTONOMY_FACET_CHANGE = "AUTONOMY_FACET_CHANGE"
    AVAILABILITY_LIFECYCLE_CHANGE = "AVAILABILITY_LIFECYCLE_CHANGE"
    ARCHITECTURE_CHANGE = "ARCHITECTURE_CHANGE"
    MODEL_CHANGE = "MODEL_CHANGE"
    AGENT_ADDITION = "AGENT_ADDITION"
    AGENT_REMOVAL = "AGENT_REMOVAL"
    PERMISSION_CHANGE = "PERMISSION_CHANGE"
    TRIGGER_CHANGE = "TRIGGER_CHANGE"
    APPROVAL_CHANGE = "APPROVAL_CHANGE"
    BENCHMARK_RESULT_CHANGE = "BENCHMARK_RESULT_CHANGE"
    EVIDENCE_STATUS_CHANGE = "EVIDENCE_STATUS_CHANGE"
    DOCUMENTATION_DEPRECATION = "DOCUMENTATION_DEPRECATION"
    NOT_MATERIAL = "NOT_MATERIAL"


class EvidenceStatusChangeSubtype(StrEnum):
    INDEPENDENT_VALIDATION_ADDED = "INDEPENDENT_VALIDATION_ADDED"
    EVIDENCE_MATURITY_CHANGED = "EVIDENCE_MATURITY_CHANGED"
    EVIDENCE_CONTRADICTION_ADDED = "EVIDENCE_CONTRADICTION_ADDED"


class ReviewStatus(StrEnum):
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"


class EditorialRisk(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class DailyStatus(StrEnum):
    MATERIAL_CHANGES = "MATERIAL_CHANGES"
    NO_REVIEWED_CONTENT = "NO_REVIEWED_CONTENT"
    NO_MATERIAL_CHANGE = "NO_MATERIAL_CHANGE"
    NO_CONFIRMED_MATERIAL_CHANGE = "NO_CONFIRMED_MATERIAL_CHANGE"
    REVIEW_PENDING = "REVIEW_PENDING"


class TaxonomyTerm(FrozenModel):
    key: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    label: str
    description: str
    deprecated: bool = False


class TaxonomyMapping(FrozenModel):
    old_term: str
    new_terms: tuple[str, ...]
    rationale: str


class TaxonomyVersion(FrozenModel):
    id: TaxonomyId
    published_at: datetime
    vocabularies: dict[str, tuple[TaxonomyTerm, ...]]
    previous_version: TaxonomyId | None = None
    mappings: tuple[TaxonomyMapping, ...] = ()
    reserved_agent_ids: tuple[str, ...] = ()
    gate_category_reuse: str | None = None


class MethodologyVersion(FrozenModel):
    id: MethodologyId
    published_at: datetime
    description: str
    normalizer_version: str = Field(pattern=r"^norm-\d+\.\d+$")


class Vendor(FrozenModel):
    id: str
    name: str
    website: HttpUrl


class System(FrozenModel):
    id: str
    vendor_id: str
    name: str
    category: str
    description: str
    first_observed_at: datetime
    last_verified_at: datetime


class Agent(FrozenModel):
    id: str
    system_id: str
    name: str
    category: str
    description: str
    first_observed_at: datetime
    last_verified_at: datetime

    @model_validator(mode="after")
    def reserve_system_sentinel(self) -> Agent:
        if self.id == "_system" or self.name.strip().lower() == "_system":
            raise ValueError("_system is reserved for system-level ontology keys")
        return self


class Capability(FrozenModel):
    id: str
    name: str
    description: str
    taxonomy_version: TaxonomyId


class Control(FrozenModel):
    id: str
    name: str
    description: str
    taxonomy_version: TaxonomyId


class ArchitecturePattern(FrozenModel):
    id: str
    name: str
    description: str
    taxonomy_version: TaxonomyId


class ModelEntity(FrozenModel):
    id: str
    provider: str
    name: str
    version: str | None = None


class Harness(FrozenModel):
    id: str
    name: str
    version: str | None = None
    repository_url: HttpUrl | None = None


class Benchmark(FrozenModel):
    id: str
    name: str
    version: str
    task_definition: str
    success_criterion: str


class SourcePolicy(FrozenModel):
    allowed_claim_types: frozenset[SubjectType]
    prohibited_claim_types: frozenset[SubjectType] = frozenset()
    allowed_claim_purposes: frozenset[ClaimPurpose]
    prohibited_claim_purposes: frozenset[ClaimPurpose] = frozenset()
    crawl_frequency: str
    human_approval_required: bool = True
    usable_as_independent_evidence: bool = True


class Source(FrozenModel):
    id: SourceId
    publisher: str
    name: str
    kind: SourceKind
    role: SourceRole = SourceRole.INPUT
    domains: tuple[str, ...]
    base_url: HttpUrl | None = None
    repository: str | None = None
    trust_class: TrustClass
    status: RegistryStatus
    enabled: bool
    policy: SourcePolicy
    pinned_at: date
    fallback_note: str
    derivative_of_hints: tuple[SourceId, ...] = ()
    notes: str = ""

    @model_validator(mode="after")
    def approval_is_required(self) -> Source:
        if self.enabled and self.status is not RegistryStatus.APPROVED:
            raise ValueError("only APPROVED sources may be enabled")
        if self.trust_class is TrustClass.SELF and self.policy.usable_as_independent_evidence:
            raise ValueError("self sources cannot be independent evidence")
        if self.role is SourceRole.OUTPUT and (
            self.trust_class is not TrustClass.SELF
            or self.policy.usable_as_independent_evidence
            or self.policy.allowed_claim_types
            or self.policy.allowed_claim_purposes
        ):
            raise ValueError("output sources must be SELF and contribute no evidence")
        return self


class ProvenanceEdge(FrozenModel):
    source_id: SourceId
    derivative_of_source_id: SourceId
    rationale: str


class Snapshot(FrozenModel):
    id: SnapshotId
    source_id: SourceId
    canonical_uri: str
    retrieved_at: datetime
    normalizer_version: str = Field(pattern=r"^norm-\d+\.\d+$")
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    content_type: str
    raw_content: str
    normalized_text: str
    duplicate_of: SnapshotId | None = None
    repository: str | None = None
    commit_sha: str | None = Field(default=None, pattern=r"^[a-f0-9]{40}$")
    file_path: str | None = None

    @model_validator(mode="after")
    def git_fields_are_complete(self) -> Snapshot:
        values = (self.repository, self.commit_sha, self.file_path)
        if any(values) and not all(values):
            raise ValueError("repository, commit_sha, and file_path must be supplied together")
        return self


class EvidenceAnchor(FrozenModel):
    snapshot_id: SnapshotId
    snapshot_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    normalizer_version: str = Field(pattern=r"^norm-\d+\.\d+$")
    document_path: str
    document_heading: str
    quote: str = Field(min_length=1, max_length=2000)
    start_offset: int = Field(ge=0)
    end_offset: int = Field(gt=0)
    repository: str | None = None
    commit_sha: str | None = Field(default=None, pattern=r"^[a-f0-9]{40}$")
    file_path: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_shape(self) -> EvidenceAnchor:
        if self.end_offset <= self.start_offset:
            raise ValueError("end_offset must exceed start_offset")
        git_values = (
            self.repository,
            self.commit_sha,
            self.file_path,
            self.line_start,
            self.line_end,
        )
        if any(value is not None for value in git_values) and not all(
            value is not None for value in git_values
        ):
            raise ValueError("all git anchor fields must be supplied together")
        if self.line_start and self.line_end and self.line_end < self.line_start:
            raise ValueError("line_end must not precede line_start")
        return self


class IndependenceFacets(FrozenModel):
    funding_relationship: FundingRelationship
    commercial_relationship: CommercialRelationship
    vendor_selected_methodology: bool
    vendor_operated_test: bool
    vendor_reviewed_before_publication: bool
    reproducible_method: bool
    public_environment: bool


class Evidence(FrozenModel):
    id: EvidenceId
    source_id: SourceId
    source_class: SourceClass
    maturity: EvidenceMaturity
    claim_purpose: ClaimPurpose
    anchor: EvidenceAnchor
    published_at: datetime | None
    modified_at: datetime | None = None
    first_seen_at: datetime
    retrieved_at: datetime
    last_seen_at: datetime
    last_verified_at: datetime
    effective_at: datetime | None = None
    independence_facets: IndependenceFacets | None = None
    derivative_of_evidence_id: EvidenceId | None = None


class AssertionScope(FrozenModel):
    license_tier: str = "unknown"
    availability: AvailabilityState = AvailabilityState.UNKNOWN
    regions: tuple[str, ...] = ()
    conditions: tuple[str, ...] = ()


class AssertionSlots(FrozenModel):
    system: str
    agent: str | None = None
    subject_type: SubjectType
    subject: str
    action: str
    object: str
    scope_key: str = "default"


class Assertion(FrozenModel):
    id: AssertionId
    assertion_key: str
    taxonomy_version: TaxonomyId
    system_id: str
    agent_id: str | None = None
    slots: AssertionSlots
    statement: str
    canonical_rendering: str
    state: AssertionState
    support_confidence: SupportConfidence
    support_confidence_rationale: str
    published_at: datetime | None = None
    modified_at: datetime | None = None
    first_seen_at: datetime
    retrieved_at: datetime
    last_seen_at: datetime
    first_observed_at: datetime
    last_verified_at: datetime
    effective_at: datetime | None = None
    methodology_version: MethodologyId
    evidence_ids: tuple[EvidenceId, ...]
    contradicting_evidence_ids: tuple[EvidenceId, ...] = ()
    superseded_by: AssertionId | None = None

    @model_validator(mode="after")
    def enforce_semantics(self) -> Assertion:
        from agentic_security.assertions.identity import assertion_key

        if self.assertion_key != assertion_key(self.slots):
            raise ValueError("assertion_key does not match ontology slots")
        if self.state is AssertionState.EXPLICITLY_UNSUPPORTED and not (
            self.evidence_ids or self.contradicting_evidence_ids
        ):
            raise ValueError("negative assertions require explicit evidence")
        if self.state is AssertionState.DISPUTED and not self.contradicting_evidence_ids:
            raise ValueError("DISPUTED assertions require contradicting evidence")
        return self


class Observation(FrozenModel):
    id: ObservationId
    assertion_id: AssertionId
    evidence_id: EvidenceId
    observed_statement: str
    observed_at: datetime
    published_at: datetime | None = None
    modified_at: datetime | None = None
    first_seen_at: datetime
    retrieved_at: datetime
    last_seen_at: datetime
    last_verified_at: datetime
    effective_at: datetime | None = None
    is_paraphrase: bool = False
    accepted: bool = True
    scope: AssertionScope = AssertionScope()


class LifecycleModifiers(FrozenModel):
    regions: tuple[str, ...] = ()
    conditions: tuple[str, ...] = ()


class LifecycleEvent(FrozenModel):
    id: str = Field(pattern=r"^LIFE-[A-Z0-9-]+$")
    system_id: str | None = None
    agent_id: str | None = None
    state: AvailabilityState
    modifiers: LifecycleModifiers = LifecycleModifiers()
    effective_at: datetime | None
    evidence_id: EvidenceId
    source_class: SourceClass
    retrieved_at: datetime
    rationale: str

    @model_validator(mode="after")
    def exactly_one_entity(self) -> LifecycleEvent:
        if (self.system_id is None) == (self.agent_id is None):
            raise ValueError("exactly one of system_id or agent_id is required")
        return self

    @property
    def entity_type(self) -> Literal["system", "agent"]:
        return "system" if self.system_id is not None else "agent"

    @property
    def entity_id(self) -> str:
        return self.system_id or self.agent_id or ""


class AutonomyFacetEvidence(FrozenModel):
    value: str
    evidence_id: EvidenceId
    support_confidence: SupportConfidence
    methodology_version: MethodologyId
    last_verified_at: datetime


class AutonomyAssessment(FrozenModel):
    id: str
    system_id: str
    agent_id: str | None = None
    trigger: AutonomyFacetEvidence
    persistence: AutonomyFacetEvidence
    permission_scope: AutonomyFacetEvidence
    human_gate: AutonomyFacetEvidence
    action_human_gates: dict[str, AutonomyFacetEvidence] = Field(default_factory=dict)

    @model_validator(mode="after")
    def controlled_gate_categories(self) -> AutonomyAssessment:
        approved = {
            "alert-triage",
            "autonomous-investigation",
            "attack-simulation",
            "remediation",
            "detection-authoring",
            "vulnerability-validation",
        }
        unknown = set(self.action_human_gates) - approved
        if unknown:
            raise ValueError(f"unapproved autonomy gate categories: {sorted(unknown)}")
        return self


class CapabilityEvidencePanel(FrozenModel):
    capability_id: str
    vendor_documentation: CapabilityEvidenceLevel
    public_demonstration: CapabilityEvidenceLevel
    independent_validation: CapabilityEvidenceLevel
    production_effectiveness: CapabilityEvidenceLevel
    methodology_version: MethodologyId
    rationale: str


class BenchmarkResult(FrozenModel):
    id: str
    benchmark_id: str
    model_id: str
    harness_id: str
    tools: tuple[str, ...]
    score: str
    retries: int = Field(ge=0)
    time_budget: str
    sample_size: int = Field(gt=0)
    environment: str
    limitations: tuple[str, ...]
    result_date: date
    evidence_id: EvidenceId
    source_class: SourceClass
    maturity: EvidenceMaturity
    reporting_party: str
    independence_facets: IndependenceFacets


class MaterialChange(FrozenModel):
    id: ChangeId
    assertion_ids: tuple[AssertionId, ...]
    description: str
    dimensions: tuple[SubjectType, ...]
    decision_impacts: frozenset[DecisionImpact]
    human_confirmed: bool
    confirmed_by: str | None = None
    confirmed_at: datetime | None = None

    @model_validator(mode="after")
    def human_gate(self) -> MaterialChange:
        if self.human_confirmed and (
            not self.decision_impacts or not self.confirmed_by or not self.confirmed_at
        ):
            raise ValueError("confirmed changes require impacts, reviewer, and timestamp")
        return self


class StructuredDiff(FrozenModel):
    id: str = Field(pattern=r"^DIFF-[A-Z0-9-]+$")
    source_id: SourceId
    old_snapshot_id: SnapshotId
    new_snapshot_id: SnapshotId
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    cosmetic_only: bool = False
    paraphrase_only: bool = False
    derivative_only: bool = False
    material_candidate: bool = False
    evidence_status_subtype: EvidenceStatusChangeSubtype | None = None
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")


class ChangeReviewItem(FrozenModel):
    id: str = Field(pattern=r"^REVIEW-[A-Z0-9-]+$")
    candidate_id: str = Field(pattern=r"^DIFF-[A-Z0-9-]+$")
    machine_classification: ChangeClassification
    machine_rationale: str
    machine_decision_impacts: frozenset[DecisionImpact] = frozenset()
    evidence_status_subtype: EvidenceStatusChangeSubtype | None = None
    status: ReviewStatus = ReviewStatus.PENDING
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    human_classification: ChangeClassification | None = None
    confirmed_decision_impacts: frozenset[DecisionImpact] = frozenset()
    human_rationale: str | None = None
    methodology_version: MethodologyId
    prior_review_id: str | None = Field(default=None, pattern=r"^REVIEW-[A-Z0-9-]+$")

    @model_validator(mode="after")
    def enforce_human_decision(self) -> ChangeReviewItem:
        decision_fields = (
            self.reviewer,
            self.reviewed_at,
            self.human_classification,
            self.human_rationale,
        )
        if self.status is ReviewStatus.PENDING and (
            any(value is not None for value in decision_fields)
            or self.confirmed_decision_impacts
            or self.prior_review_id is not None
        ):
            raise ValueError("pending machine proposal cannot contain a human decision")
        if self.status is not ReviewStatus.PENDING and (
            any(value is None for value in decision_fields) or self.prior_review_id is None
        ):
            raise ValueError(
                "completed review requires reviewer, time, classification, rationale, "
                "and prior review reference"
            )
        if (
            self.status is ReviewStatus.CONFIRMED
            and self.human_classification is not ChangeClassification.NOT_MATERIAL
            and not self.confirmed_decision_impacts
        ):
            raise ValueError("confirmed material change requires human-confirmed decision impacts")
        if (self.machine_classification is ChangeClassification.EVIDENCE_STATUS_CHANGE) != (
            self.evidence_status_subtype is not None
        ):
            raise ValueError("evidence-status classifications require exactly one subtype")
        return self

    @property
    def diff_id(self) -> str:
        return self.candidate_id

    @property
    def proposed_classification(self) -> ChangeClassification:
        return self.machine_classification

    @property
    def rationale(self) -> str:
        return self.machine_rationale

    @property
    def proposed_decision_impacts(self) -> frozenset[DecisionImpact]:
        return self.machine_decision_impacts

    @property
    def confirmed_classification(self) -> ChangeClassification | None:
        return self.human_classification


class ContradictionFlag(FrozenModel):
    id: str = Field(pattern=r"^CONFLICT-[A-Z0-9-]+$")
    type: Literal["POTENTIAL_EVIDENCE_CONFLICT"] = "POTENTIAL_EVIDENCE_CONFLICT"
    assertion_ids: tuple[AssertionId, ...]
    detected_by: str
    rationale: str
    human_review_required: bool = True
    status: ReviewStatus = ReviewStatus.PENDING


class ContradictionResolution(FrozenModel):
    id: str = Field(pattern=r"^RESOLUTION-[A-Z0-9-]+$")
    conflict_id: str
    resolution: str
    resulting_state: AssertionState
    resulting_scope: AssertionScope
    reviewer: str
    reviewed_at: datetime


class ClaimCheck(FrozenModel):
    claim: str
    evidence_ids: tuple[EvidenceId, ...]
    supported: bool
    rationale: str


class DailyBrief(FrozenModel):
    date: date
    markdown: str
    confirmed_change_ids: tuple[ChangeId, ...]
    status: DailyStatus

    @property
    def no_material_change(self) -> bool:
        return self.status is DailyStatus.NO_MATERIAL_CHANGE


class WeeklyEvidencePack(FrozenModel):
    week_ending: date
    markdown: str
    confirmed_change_ids: tuple[ChangeId, ...]
    open_conflict_ids: tuple[str, ...]
    freshness_alert_assertion_ids: tuple[AssertionId, ...]


class Article(FrozenModel):
    id: str = Field(pattern=r"^ARTICLE-[A-Z0-9-]+$")
    title: str
    body: str


class Trend(FrozenModel):
    id: str = Field(pattern=r"^TREND-[A-Z0-9-]+$")
    title: str
    description: str
    supporting_assertion_ids: tuple[AssertionId, ...]
    supporting_evidence_ids: tuple[EvidenceId, ...]


class GateAPacket(FrozenModel):
    taxonomy_version: TaxonomyId
    methodology_version: MethodologyId
    vendors: tuple[Vendor, ...]
    systems: tuple[System, ...]
    agents: tuple[Agent, ...]
    capabilities: tuple[Capability, ...]
    controls: tuple[Control, ...]
    architecture_patterns: tuple[ArchitecturePattern, ...]
    models: tuple[ModelEntity, ...]
    harnesses: tuple[Harness, ...]
    benchmarks: tuple[Benchmark, ...]
    sources: tuple[Source, ...]
    provenance_edges: tuple[ProvenanceEdge, ...]
    snapshots: tuple[Snapshot, ...]
    evidence: tuple[Evidence, ...]
    assertions: tuple[Assertion, ...]
    observations: tuple[Observation, ...]
    lifecycle_events: tuple[LifecycleEvent, ...]
    autonomy_assessments: tuple[AutonomyAssessment, ...]
    benchmark_results: tuple[BenchmarkResult, ...]
    material_changes: tuple[MaterialChange, ...]
    metadata: dict[str, Any] = Field(default_factory=dict)
