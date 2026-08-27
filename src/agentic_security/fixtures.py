"""Deterministic Gate A fixture corpus; no live collection is performed."""

from __future__ import annotations

from datetime import UTC, date, datetime

from pydantic import HttpUrl

from agentic_security.assertions.identity import assertion_key
from agentic_security.collection.base import build_snapshot
from agentic_security.models import (
    Agent,
    ArchitecturePattern,
    Assertion,
    AssertionScope,
    AssertionSlots,
    AssertionState,
    AutonomyAssessment,
    AutonomyFacetEvidence,
    AvailabilityState,
    Benchmark,
    BenchmarkResult,
    Capability,
    ClaimPurpose,
    CommercialRelationship,
    Control,
    DecisionImpact,
    Evidence,
    EvidenceAnchor,
    EvidenceMaturity,
    FundingRelationship,
    GateAPacket,
    Harness,
    IndependenceFacets,
    LifecycleEvent,
    LifecycleModifiers,
    MaterialChange,
    ModelEntity,
    Observation,
    ProvenanceEdge,
    RegistryStatus,
    Snapshot,
    Source,
    SourceClass,
    SourceKind,
    SourcePolicy,
    SubjectType,
    SupportConfidence,
    System,
    TrustClass,
    Vendor,
)

NOW = datetime(2026, 8, 26, tzinfo=UTC)
TAXONOMY = "ASI-TAXONOMY-1.1"
METHODOLOGY = "ASI-1.0"
ALL_CLAIMS = frozenset(SubjectType)


def _source(
    source_id: str,
    publisher: str,
    domain: str,
    trust: TrustClass,
    *,
    independent: bool = False,
) -> Source:
    return Source(
        id=source_id,
        publisher=publisher,
        name=f"{publisher} fixture source",
        kind=SourceKind.FIXTURE,
        domains=(domain,),
        base_url=HttpUrl(f"https://{domain}/"),
        trust_class=trust,
        status=RegistryStatus.APPROVED,
        enabled=True,
        policy=SourcePolicy(
            allowed_claim_types=ALL_CLAIMS,
            allowed_claim_purposes=(
                frozenset(ClaimPurpose)
                if independent
                else frozenset(
                    {
                        ClaimPurpose.DOCUMENTATION,
                        ClaimPurpose.DEMONSTRATION,
                        ClaimPurpose.BENCHMARK_RESULT,
                    }
                )
            ),
            prohibited_claim_purposes=(
                frozenset()
                if independent
                else frozenset({ClaimPurpose.INDEPENDENT_VALIDATION, ClaimPurpose.EFFECTIVENESS})
            ),
            crawl_frequency="fixture-only",
            usable_as_independent_evidence=independent,
        ),
        pinned_at=date(2026, 8, 26),
        fallback_note="Deterministic fixture; no network fallback.",
    )


def _evidence(
    evidence_id: str,
    source: Source,
    source_class: SourceClass,
    maturity: EvidenceMaturity,
    text: str,
    quote: str,
    *,
    derivative_of: str | None = None,
    facets: IndependenceFacets | None = None,
    git: bool = False,
    purpose: ClaimPurpose = ClaimPurpose.DOCUMENTATION,
) -> tuple[Snapshot, Evidence]:
    snapshot_id = f"SNAP-{evidence_id.removeprefix('EV-')}"
    repository = "Example/docs" if git else None
    commit = "a" * 40 if git else None
    file_path = "docs/security.md" if git else None
    snapshot = build_snapshot(
        snapshot_id=snapshot_id,
        source_id=source.id,
        canonical_uri=f"fixture://{source.id}/{snapshot_id}",
        content_type="text/markdown",
        raw_text=text,
        retrieved_at=NOW,
        repository=repository,
        commit_sha=commit,
        file_path=file_path,
    )
    start = snapshot.normalized_text.index(quote)
    line_start = snapshot.normalized_text[:start].count("\n") + 1 if git else None
    line_end = line_start + quote.count("\n") if line_start else None
    evidence = Evidence(
        id=evidence_id,
        source_id=source.id,
        source_class=source_class,
        maturity=maturity,
        claim_purpose=purpose,
        anchor=EvidenceAnchor(
            snapshot_id=snapshot.id,
            snapshot_sha256=snapshot.sha256,
            normalizer_version=snapshot.normalizer_version,
            document_path=file_path or f"/fixture/{snapshot.id}",
            document_heading="Gate A fixture",
            quote=quote,
            start_offset=start,
            end_offset=start + len(quote),
            repository=repository,
            commit_sha=commit,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
        ),
        published_at=NOW,
        first_seen_at=NOW,
        retrieved_at=NOW,
        last_seen_at=NOW,
        last_verified_at=NOW,
        independence_facets=facets,
        derivative_of_evidence_id=derivative_of,
    )
    return snapshot, evidence


def _assertion(
    assertion_id: str,
    slots: AssertionSlots,
    statement: str,
    evidence_ids: tuple[str, ...],
    *,
    state: AssertionState = AssertionState.AFFIRMED,
    contradicting: tuple[str, ...] = (),
    confidence: SupportConfidence = SupportConfidence.HIGH,
) -> Assertion:
    return Assertion(
        id=assertion_id,
        assertion_key=assertion_key(slots),
        taxonomy_version=TAXONOMY,
        system_id=slots.system,
        agent_id=slots.agent,
        slots=slots,
        statement=statement,
        canonical_rendering=statement,
        state=state,
        support_confidence=confidence,
        support_confidence_rationale="Fixture evidence directly supports the scoped statement.",
        first_seen_at=NOW,
        retrieved_at=NOW,
        last_seen_at=NOW,
        first_observed_at=NOW,
        last_verified_at=NOW,
        methodology_version=METHODOLOGY,
        evidence_ids=evidence_ids,
        contradicting_evidence_ids=contradicting,
    )


def gate_a_packet() -> GateAPacket:
    sources = (
        _source("SRC-MS-DOCS", "Microsoft", "learn.example", TrustClass.PRIMARY),
        _source("SRC-MS-BLOG", "Microsoft", "blog.example", TrustClass.OFFICIAL),
        _source("SRC-CROWDSTRIKE-DOCS", "CrowdStrike", "crowdstrike.example", TrustClass.OFFICIAL),
        _source("SRC-SENTINELONE-DOCS", "SentinelOne", "sentinelone.example", TrustClass.OFFICIAL),
        _source("SRC-BENCHMARK", "Example Benchmark", "benchmark.example", TrustClass.RESEARCH),
        _source("SRC-PRESS", "Security Press", "press.example", TrustClass.SECONDARY),
        _source(
            "SRC-UNIVERSITY",
            "Example University",
            "university.example",
            TrustClass.INDEPENDENT,
            independent=True,
        ),
    )
    by_source = {source.id: source for source in sources}
    independent_facets = IndependenceFacets(
        funding_relationship=FundingRelationship.UNRESTRICTED_GRANT,
        commercial_relationship=CommercialRelationship.NONE,
        vendor_selected_methodology=False,
        vendor_operated_test=False,
        vendor_reviewed_before_publication=False,
        reproducible_method=True,
        public_environment=True,
    )
    vendor_facets = IndependenceFacets(
        funding_relationship=FundingRelationship.NONE,
        commercial_relationship=CommercialRelationship.VENDOR_SELF,
        vendor_selected_methodology=True,
        vendor_operated_test=True,
        vendor_reviewed_before_publication=True,
        reproducible_method=False,
        public_environment=False,
    )
    records = (
        _evidence(
            "EV-TRIAGE",
            by_source["SRC-MS-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "# Triage\nBlue agents triage supported security alerts.",
            "Blue agents triage supported security alerts.",
            git=True,
        ),
        _evidence(
            "EV-TRIAGE-PARAPHRASE",
            by_source["SRC-MS-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "For supported alerts, blue agents perform triage.",
            "For supported alerts, blue agents perform triage.",
        ),
        _evidence(
            "EV-RED-CONDITIONAL",
            by_source["SRC-MS-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "Red simulation runs only in approved bounded test environments during preview.",
            "Red simulation runs only in approved bounded test environments during preview.",
        ),
        _evidence(
            "EV-CROWD-CONDITIONAL",
            by_source["SRC-CROWDSTRIKE-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "Automated triage requires the Falcon Complete service tier.",
            "Automated triage requires the Falcon Complete service tier.",
        ),
        _evidence(
            "EV-SENTINEL-INVESTIGATE",
            by_source["SRC-SENTINELONE-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "Purple AI investigates supported security incidents.",
            "Purple AI investigates supported security incidents.",
        ),
        _evidence(
            "EV-AUTH",
            by_source["SRC-MS-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "Every MDASH agent tool call is evaluated against scoped authorization policy.",
            "Every MDASH agent tool call is evaluated against scoped authorization policy.",
        ),
        _evidence(
            "EV-MARKETING-AUTONOMY",
            by_source["SRC-MS-BLOG"],
            SourceClass.P2,
            EvidenceMaturity.E1,
            "Project Perception remediates threats autonomously.",
            "Project Perception remediates threats autonomously.",
        ),
        _evidence(
            "EV-DOCS-GATE",
            by_source["SRC-MS-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "Remediation actions require human approval before execution.",
            "Remediation actions require human approval before execution.",
        ),
        _evidence(
            "EV-PREVIEW",
            by_source["SRC-MS-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "Project Perception is available in limited public preview.",
            "Project Perception is available in limited public preview.",
        ),
        _evidence(
            "EV-GA",
            by_source["SRC-MS-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "Project Perception became generally available on 2026-08-20.",
            "Project Perception became generally available on 2026-08-20.",
        ),
        _evidence(
            "EV-GREEN-AGENT",
            by_source["SRC-MS-DOCS"],
            SourceClass.P1,
            EvidenceMaturity.E1,
            "A green verification agent checks red and blue agent output.",
            "A green verification agent checks red and blue agent output.",
        ),
        _evidence(
            "EV-VENDOR-BENCHMARK",
            by_source["SRC-MS-BLOG"],
            SourceClass.P2,
            EvidenceMaturity.E1,
            "The vendor reports a score of 82% on Example Security Benchmark v1.",
            "The vendor reports a score of 82% on Example Security Benchmark v1.",
            facets=vendor_facets,
            purpose=ClaimPurpose.BENCHMARK_RESULT,
        ),
        _evidence(
            "EV-PRESS-BENCHMARK",
            by_source["SRC-PRESS"],
            SourceClass.S1,
            EvidenceMaturity.E1,
            "Security Press repeats the vendor's reported benchmark score of 82%.",
            "Security Press repeats the vendor's reported benchmark score of 82%.",
            derivative_of="EV-VENDOR-BENCHMARK",
        ),
        _evidence(
            "EV-INDEPENDENT-GRANT",
            by_source["SRC-UNIVERSITY"],
            SourceClass.I1,
            EvidenceMaturity.E3,
            "The university independently designed, ran, and published "
            "the reproducible evaluation.",
            "The university independently designed, ran, and published "
            "the reproducible evaluation.",
            facets=independent_facets,
            purpose=ClaimPurpose.INDEPENDENT_VALIDATION,
        ),
    )
    snapshots = tuple(record[0] for record in records)
    evidence = tuple(record[1] for record in records)
    assertions = (
        _assertion(
            "ASRT-TRIAGE",
            AssertionSlots(
                system="project-perception",
                agent="perception-blue-agents",
                subject_type=SubjectType.CAPABILITY,
                subject="alert-triage",
                action="perform",
                object="supported-security-alert",
            ),
            "Blue agents triage supported security alerts.",
            ("EV-TRIAGE", "EV-TRIAGE-PARAPHRASE"),
        ),
        _assertion(
            "ASRT-RED-CONDITIONAL",
            AssertionSlots(
                system="project-perception",
                agent="perception-red-agents",
                subject_type=SubjectType.CAPABILITY,
                subject="attack-simulation",
                action="perform",
                object="bounded-test-environment",
                scope_key="approved-preview",
            ),
            "Red agents perform attack simulation in approved preview environments.",
            ("EV-RED-CONDITIONAL",),
            state=AssertionState.CONDITIONAL,
        ),
        _assertion(
            "ASRT-CROWD-CONDITIONAL",
            AssertionSlots(
                system="charlotte-ai",
                subject_type=SubjectType.CAPABILITY,
                subject="alert-triage",
                action="perform",
                object="supported-security-alert",
                scope_key="falcon-complete",
            ),
            "Charlotte AI performs automated triage for Falcon Complete customers.",
            ("EV-CROWD-CONDITIONAL",),
            state=AssertionState.CONDITIONAL,
        ),
        _assertion(
            "ASRT-SENTINEL-INVESTIGATE",
            AssertionSlots(
                system="purple-ai",
                subject_type=SubjectType.CAPABILITY,
                subject="autonomous-investigation",
                action="perform",
                object="security-incident",
            ),
            "Purple AI investigates supported security incidents.",
            ("EV-SENTINEL-INVESTIGATE",),
        ),
        _assertion(
            "ASRT-MDASH-AUTH",
            AssertionSlots(
                system="mdash",
                subject_type=SubjectType.CONTROL,
                subject="authorization",
                action="require",
                object="agent-tool-call",
            ),
            "MDASH applies scoped authorization to agent tool calls.",
            ("EV-AUTH",),
        ),
        _assertion(
            "ASRT-REMEDIATION-DISPUTED",
            AssertionSlots(
                system="project-perception",
                subject_type=SubjectType.CAPABILITY,
                subject="remediation",
                action="perform",
                object="approved-remediation-action",
            ),
            "Project Perception performs remediation without a human gate.",
            ("EV-MARKETING-AUTONOMY",),
            state=AssertionState.DISPUTED,
            contradicting=("EV-DOCS-GATE",),
            confidence=SupportConfidence.LOW,
        ),
        _assertion(
            "ASRT-GREEN-AGENT",
            AssertionSlots(
                system="project-perception",
                agent="perception-green-agent",
                subject_type=SubjectType.ARCHITECTURE_PATTERN,
                subject="generator-verifier",
                action="add",
                object="green-verification-agent",
            ),
            "Project Perception includes a green verification agent.",
            ("EV-GREEN-AGENT",),
        ),
    )
    vendors = (
        Vendor(id="microsoft", name="Microsoft", website=HttpUrl("https://www.microsoft.com/")),
        Vendor(
            id="crowdstrike",
            name="CrowdStrike",
            website=HttpUrl("https://www.crowdstrike.com/"),
        ),
        Vendor(
            id="sentinelone",
            name="SentinelOne",
            website=HttpUrl("https://www.sentinelone.com/"),
        ),
    )
    capabilities = (
        Capability(
            id="alert-triage",
            name="Alert triage",
            description="Prioritize and contextualize supported security alerts.",
            taxonomy_version=TAXONOMY,
        ),
        Capability(
            id="autonomous-investigation",
            name="Autonomous investigation",
            description="Investigate supported incidents without step-by-step prompting.",
            taxonomy_version=TAXONOMY,
        ),
        Capability(
            id="attack-simulation",
            name="Attack simulation",
            description="Execute bounded adversarial simulation.",
            taxonomy_version=TAXONOMY,
        ),
        Capability(
            id="remediation",
            name="Remediation",
            description="Apply a change to address a security issue.",
            taxonomy_version=TAXONOMY,
        ),
    )
    controls = (
        Control(
            id="authorization",
            name="Authorization",
            description="Scoped permission to invoke agent tools.",
            taxonomy_version=TAXONOMY,
        ),
        Control(
            id="approval-gate",
            name="Approval gate",
            description="Human approval required before selected actions.",
            taxonomy_version=TAXONOMY,
        ),
    )
    architecture_patterns = (
        ArchitecturePattern(
            id="red-blue-green",
            name="Red/blue/green",
            description="Offensive, defensive, and verification agent roles.",
            taxonomy_version=TAXONOMY,
        ),
        ArchitecturePattern(
            id="generator-verifier",
            name="Generator/verifier",
            description="Generated work is checked by a separate verifier.",
            taxonomy_version=TAXONOMY,
        ),
    )
    models = (
        ModelEntity(
            id="vendor-model-v1", provider="fixture-vendor", name="Vendor Model", version="1"
        ),
    )
    harnesses = (
        Harness(
            id="vendor-agent-harness-v1",
            name="Vendor Agent Harness",
            version="1",
            repository_url=None,
        ),
    )
    benchmarks = (
        Benchmark(
            id="example-security-benchmark-v1",
            name="Example Security Benchmark",
            version="1",
            task_definition="Resolve bounded security investigation tasks.",
            success_criterion="Task-specific verifier reports success.",
        ),
    )
    systems = (
        System(
            id="project-perception",
            vendor_id="microsoft",
            name="Project Perception",
            category="enterprise-agentic-security",
            description="Fixture multi-agent security system.",
            first_observed_at=NOW,
            last_verified_at=NOW,
        ),
        System(
            id="mdash",
            vendor_id="microsoft",
            name="MDASH",
            category="application-security",
            description="Fixture specialized-agent initiative.",
            first_observed_at=NOW,
            last_verified_at=NOW,
        ),
        System(
            id="charlotte-ai",
            vendor_id="crowdstrike",
            name="Charlotte AI",
            category="soc-agent",
            description="Fixture non-Microsoft system.",
            first_observed_at=NOW,
            last_verified_at=NOW,
        ),
        System(
            id="purple-ai",
            vendor_id="sentinelone",
            name="Purple AI",
            category="soc-agent",
            description="Fixture non-Microsoft system.",
            first_observed_at=NOW,
            last_verified_at=NOW,
        ),
    )
    agents = (
        Agent(
            id="perception-blue-agents",
            system_id="project-perception",
            name="Blue agents",
            category="defensive",
            description="Defensive triage agents.",
            first_observed_at=NOW,
            last_verified_at=NOW,
        ),
        Agent(
            id="perception-red-agents",
            system_id="project-perception",
            name="Red agents",
            category="offensive",
            description="Bounded simulation agents.",
            first_observed_at=NOW,
            last_verified_at=NOW,
        ),
        Agent(
            id="perception-green-agent",
            system_id="project-perception",
            name="Green verification agent",
            category="verifier",
            description="Checks red and blue agent output.",
            first_observed_at=NOW,
            last_verified_at=NOW,
        ),
    )
    lifecycle = (
        LifecycleEvent(
            id="LIFE-PERCEPTION-PREVIEW",
            system_id="project-perception",
            state=AvailabilityState.LIMITED_PUBLIC_PREVIEW,
            modifiers=LifecycleModifiers(
                regions=("North America",), conditions=("approved preview tenants",)
            ),
            effective_at=datetime(2026, 7, 1, tzinfo=UTC),
            evidence_id="EV-PREVIEW",
            source_class=SourceClass.P1,
            retrieved_at=datetime(2026, 7, 2, tzinfo=UTC),
            rationale="Primary documentation states limited public preview.",
        ),
        LifecycleEvent(
            id="LIFE-PERCEPTION-GA",
            system_id="project-perception",
            state=AvailabilityState.GA,
            effective_at=datetime(2026, 8, 20, tzinfo=UTC),
            evidence_id="EV-GA",
            source_class=SourceClass.P1,
            retrieved_at=NOW,
            rationale="Primary documentation states general availability.",
        ),
    )

    def facet(value: str, evidence_id: str) -> AutonomyFacetEvidence:
        return AutonomyFacetEvidence(
            value=value,
            evidence_id=evidence_id,
            support_confidence=SupportConfidence.HIGH,
            methodology_version=METHODOLOGY,
            last_verified_at=NOW,
        )

    autonomy = (
        AutonomyAssessment(
            id="AUTO-PERCEPTION",
            system_id="project-perception",
            trigger=facet("EVENT_DRIVEN", "EV-TRIAGE"),
            persistence=facet("PERSISTENT", "EV-TRIAGE"),
            permission_scope=facet("SCOPED_WRITE", "EV-DOCS-GATE"),
            human_gate=facet("PRE_ACTION", "EV-DOCS-GATE"),
            action_human_gates={
                "autonomous-investigation": facet("NOTIFY_ONLY", "EV-TRIAGE"),
                "remediation": facet("PRE_ACTION", "EV-DOCS-GATE"),
            },
        ),
    )
    benchmark_results = (
        BenchmarkResult(
            id="RESULT-VENDOR-82",
            benchmark_id="example-security-benchmark-v1",
            model_id="vendor-model-v1",
            harness_id="vendor-agent-harness-v1",
            tools=("browser", "terminal-sandbox"),
            score="82%",
            retries=3,
            time_budget="30 minutes/task",
            sample_size=100,
            environment="Vendor-operated private evaluation environment",
            limitations=("No independent reproduction", "Vendor-selected methodology"),
            result_date=date(2026, 8, 1),
            evidence_id="EV-VENDOR-BENCHMARK",
            source_class=SourceClass.P2,
            maturity=EvidenceMaturity.E1,
            reporting_party="Microsoft fixture vendor",
            independence_facets=vendor_facets,
        ),
    )
    changes = (
        MaterialChange(
            id="CHANGE-GREEN-AGENT-ADDED",
            assertion_ids=("ASRT-GREEN-AGENT",),
            description="A green verification agent was added to Project Perception.",
            dimensions=(SubjectType.ARCHITECTURE_PATTERN,),
            decision_impacts=frozenset(
                {DecisionImpact.ARCHITECTURE, DecisionImpact.RISK, DecisionImpact.EVALUATION}
            ),
            human_confirmed=True,
            confirmed_by="gate-a-fixture-analyst",
            confirmed_at=NOW,
        ),
    )
    observations = (
        Observation(
            id="OBS-TRIAGE-ORIGINAL",
            assertion_id="ASRT-TRIAGE",
            evidence_id="EV-TRIAGE",
            observed_statement="Blue agents triage supported security alerts.",
            observed_at=NOW,
            first_seen_at=NOW,
            retrieved_at=NOW,
            last_seen_at=NOW,
            last_verified_at=NOW,
            scope=AssertionScope(),
        ),
        Observation(
            id="OBS-TRIAGE-PARAPHRASE",
            assertion_id="ASRT-TRIAGE",
            evidence_id="EV-TRIAGE-PARAPHRASE",
            observed_statement="For supported alerts, blue agents perform triage.",
            observed_at=NOW,
            first_seen_at=NOW,
            retrieved_at=NOW,
            last_seen_at=NOW,
            last_verified_at=NOW,
            is_paraphrase=True,
            scope=AssertionScope(),
        ),
        Observation(
            id="OBS-RED-CONDITIONAL",
            assertion_id="ASRT-RED-CONDITIONAL",
            evidence_id="EV-RED-CONDITIONAL",
            observed_statement=(
                "Red simulation runs only in approved bounded test environments during preview."
            ),
            observed_at=NOW,
            first_seen_at=NOW,
            retrieved_at=NOW,
            last_seen_at=NOW,
            last_verified_at=NOW,
            scope=AssertionScope(
                availability=AvailabilityState.LIMITED_PUBLIC_PREVIEW,
                conditions=("approved bounded test environments only",),
            ),
        ),
        Observation(
            id="OBS-CROWD-CONDITIONAL",
            assertion_id="ASRT-CROWD-CONDITIONAL",
            evidence_id="EV-CROWD-CONDITIONAL",
            observed_statement="Automated triage requires the Falcon Complete service tier.",
            observed_at=NOW,
            first_seen_at=NOW,
            retrieved_at=NOW,
            last_seen_at=NOW,
            last_verified_at=NOW,
            scope=AssertionScope(
                license_tier="Falcon Complete",
                conditions=("Falcon Complete service tier required",),
            ),
        ),
    )
    return GateAPacket(
        taxonomy_version=TAXONOMY,
        methodology_version=METHODOLOGY,
        vendors=vendors,
        systems=systems,
        agents=agents,
        capabilities=capabilities,
        controls=controls,
        architecture_patterns=architecture_patterns,
        models=models,
        harnesses=harnesses,
        benchmarks=benchmarks,
        sources=sources,
        provenance_edges=(
            ProvenanceEdge(
                source_id="SRC-PRESS",
                derivative_of_source_id="SRC-MS-BLOG",
                rationale="Press fixture explicitly re-reports the vendor benchmark post.",
            ),
        ),
        snapshots=snapshots,
        evidence=evidence,
        assertions=assertions,
        observations=observations,
        lifecycle_events=lifecycle,
        autonomy_assessments=autonomy,
        benchmark_results=benchmark_results,
        material_changes=changes,
        metadata={
            "fixture_only": True,
            "live_collection_performed": False,
            "independence_evidence_id": "EV-INDEPENDENT-GRANT",
        },
    )
