"""Generate publication-safe static-site data from explicit ledger inputs."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentic_security.derivations import (
    derive_autonomy_label,
    derive_capability_evidence_panel,
    derive_current_scope,
    derive_freshness,
    derive_independence,
    derive_support_confidence,
)
from agentic_security.editorial.reports import build_daily_brief, build_weekly_pack
from agentic_security.fixtures import NOW, gate_a_packet
from agentic_security.models import ClaimPurpose, IndependenceDesignation, SubjectType
from agentic_security.pass2_fixtures import gate_b_fixture
from agentic_security.storage.read_models import (
    PublicationLedgerData,
    configured_database_path,
    read_demo_packet,
    read_publication_ledger,
)
from agentic_security.trend_primitives.queries import preview_to_ga_velocity


def _publication_data(
    *,
    database_path: Path | None,
    demo: bool,
    demo_input: Path | None,
) -> tuple[PublicationLedgerData, datetime]:
    if sum((database_path is not None, demo, demo_input is not None)) > 1:
        raise ValueError("choose exactly one of database_path, demo, or demo_input")
    if demo:
        packet = gate_a_packet()
        gate_b = gate_b_fixture()
        data = PublicationLedgerData.from_packet(
            packet,
            conflicts=gate_b["conflicts"],
            candidates=gate_b["diffs"],
            latest_review_decisions=gate_b["reviews"],
        )
        return (
            replace(
                data,
                evidence=(*data.evidence, gate_b["evidence_status_flow"]["evidence"]),
            ),
            NOW,
        )
    if demo_input is not None:
        return read_demo_packet(demo_input), NOW
    return read_publication_ledger(database_path or configured_database_path()), datetime.now(UTC)


def build_site_data(
    *,
    database_path: Path | None = None,
    demo: bool = False,
    demo_input: Path | None = None,
    ledger_data: PublicationLedgerData | None = None,
    generated_at: datetime | None = None,
    semantic_as_of: datetime | None = None,
    canonical_base: str = "https://agentic-security-intelligence.pages.dev",
) -> dict[str, Any]:
    if ledger_data is not None:
        if database_path is not None or demo or demo_input is not None:
            raise ValueError("ledger_data cannot be combined with another input")
        data = ledger_data
        default_generated_at = datetime.now(UTC)
    else:
        data, default_generated_at = _publication_data(
            database_path=database_path,
            demo=demo,
            demo_input=demo_input,
        )
    generated_at = generated_at or default_generated_at
    semantic_as_of = semantic_as_of or generated_at
    vendors = {item.id: item for item in data.vendors}
    capabilities = {item.id: item for item in data.capabilities}
    excluded_source_ids = {
        item.id
        for item in data.sources
        if item.role.value == "OUTPUT" or item.trust_class.value == "SELF"
    }
    evidence = {
        item.id: item for item in data.evidence if item.source_id not in excluded_source_ids
    }
    assertions_by_id = {item.id: item for item in data.assertions}
    change_classifications = {
        change_id: review.human_classification.value
        for change_id, review in data.change_reviews.items()
        if review.human_classification is not None
    }
    changes = [
        {
            "id": item.id,
            "system_id": next(
                (
                    assertions_by_id[assertion_id].system_id
                    for assertion_id in item.assertion_ids
                    if assertion_id in assertions_by_id
                ),
                "unknown",
            ),
            "description": item.description,
            "classification": change_classifications.get(item.id, "HUMAN_CONFIRMED"),
            "decision_impacts": sorted(value.value for value in item.decision_impacts),
            "date": item.confirmed_at.date().isoformat() if item.confirmed_at else None,
        }
        for item in data.confirmed_changes
    ]
    if demo:
        evidence_review = gate_b_fixture()["evidence_status_flow"]["human_review"]
        assert evidence_review.human_classification is not None
        assert evidence_review.evidence_status_subtype is not None
        assert evidence_review.reviewed_at is not None
        changes.append(
            {
                "id": "CHANGE-INDEPENDENT-VALIDATION",
                "system_id": "project-perception",
                "description": "Independent I1/E3 validation was added for alert triage.",
                "classification": evidence_review.human_classification.value,
                "subtype": evidence_review.evidence_status_subtype.value,
                "decision_impacts": sorted(
                    value.value for value in evidence_review.confirmed_decision_impacts
                ),
                "date": evidence_review.reviewed_at.date().isoformat(),
            }
        )
    systems: list[dict[str, Any]] = []
    claims: list[dict[str, Any]] = []
    for system in data.systems:
        system_assertions = [item for item in data.assertions if item.system_id == system.id]
        capability_rows: list[dict[str, Any]] = []
        for assertion in system_assertions:
            if assertion.slots.subject_type is not SubjectType.CAPABILITY:
                continue
            evidence_ids = list(assertion.evidence_ids)
            if demo and assertion.id == "ASRT-TRIAGE":
                evidence_ids.append("EV-TRIAGE-INDEPENDENT")
            items = [evidence[item] for item in evidence_ids if item in evidence]
            excluded_evidence = len(items) != len(evidence_ids)
            panel = derive_capability_evidence_panel(assertion.slots.subject, items)
            scope = derive_current_scope(assertion.id, data.observations)
            capability = capabilities.get(assertion.slots.subject)
            support_confidence = (
                derive_support_confidence(
                    items,
                    derive_freshness(assertion.last_verified_at, as_of=semantic_as_of),
                    has_unresolved_contradiction=bool(assertion.contradicting_evidence_ids),
                )
                if excluded_evidence
                else assertion.support_confidence
            )
            row: dict[str, Any] = {
                "assertion_id": assertion.id,
                "agent_id": assertion.agent_id,
                "capability_id": assertion.slots.subject,
                "name": (
                    capability.name
                    if capability is not None
                    else assertion.slots.subject.replace("-", " ").title()
                ),
                "statement": assertion.statement,
                "state": assertion.state.value,
                "scope": scope.model_dump(mode="json"),
                "support_confidence": {
                    "value": support_confidence.value,
                    "rationale": (
                        "Recomputed after excluding SELF/OUTPUT sources."
                        if excluded_evidence
                        else assertion.support_confidence_rationale
                    ),
                    "methodology_version": assertion.methodology_version,
                },
                "evidence_panel": panel.model_dump(mode="json"),
                "evidence": [
                    {
                        "id": item.id,
                        "source_id": item.source_id,
                        "source_class": item.source_class.value,
                        "maturity": item.maturity.value,
                        "purpose": item.claim_purpose.value,
                        "quote": item.anchor.quote,
                        "independence": (
                            derive_independence(item.independence_facets).value
                            if item.independence_facets
                            else IndependenceDesignation.UNDETERMINED.value
                        ),
                    }
                    for item in items
                ],
            }
            capability_rows.append(row)
            independent: list[dict[str, Any]] = [
                item
                for item in row["evidence"]
                if item["independence"] == "INDEPENDENT"
                and item["purpose"] == ClaimPurpose.INDEPENDENT_VALIDATION.value
                and item["maturity"] in {"E3", "E4", "E5"}
            ]
            claims.append(
                {
                    "system_id": system.id,
                    "system_name": system.name,
                    "capability": row["name"],
                    "vendor_claims": assertion.statement,
                    "primary_documentation": (
                        assertion.statement
                        if any(item["source_class"] == "P1" for item in row["evidence"])
                        else "NONE_FOUND"
                    ),
                    "demonstrated": (
                        "Public demonstration evidence is recorded."
                        if row["evidence_panel"]["public_demonstration"] != "NONE_FOUND"
                        else "NONE_FOUND"
                    ),
                    "benchmarked": (
                        "Benchmark evidence is recorded."
                        if any(item["maturity"] in {"E4", "E5"} for item in row["evidence"])
                        else "NONE_FOUND"
                    ),
                    "independently_validated": (
                        independent[0]["quote"]
                        if independent
                        else f"No independent validation published as of {semantic_as_of.date()}."
                    ),
                    "unknown": (
                        "Production effectiveness remains UNKNOWN."
                        if row["evidence_panel"]["production_effectiveness"] == "UNKNOWN"
                        else "No additional production-effectiveness unknown recorded."
                    ),
                    "evidence_panel": row["evidence_panel"],
                }
            )
        autonomy = next(
            (item for item in data.autonomy_assessments if item.system_id == system.id),
            None,
        )
        lifecycle = [
            {
                "state": item.state.value,
                "effective_at": (
                    item.effective_at.date().isoformat() if item.effective_at else "UNKNOWN"
                ),
                "conditions": item.modifiers.conditions,
                "regions": item.modifiers.regions,
                "evidence_id": item.evidence_id,
            }
            for item in data.lifecycle_events
            if item.system_id == system.id
        ]
        systems.append(
            {
                "id": system.id,
                "name": system.name,
                "vendor": vendors[system.vendor_id].name,
                "category": system.category,
                "description": system.description,
                "first_observed_at": system.first_observed_at.date().isoformat(),
                "last_verified_at": system.last_verified_at.date().isoformat(),
                "freshness": derive_freshness(
                    system.last_verified_at,
                    as_of=semantic_as_of,
                ).value,
                "agents": [
                    {
                        **item.model_dump(mode="json"),
                        "capabilities": [
                            capability_row["name"]
                            for capability_row in capability_rows
                            if capability_row["agent_id"] == item.id
                        ],
                        "controls": [
                            assertion.statement
                            for assertion in system_assertions
                            if assertion.agent_id == item.id
                            and assertion.slots.subject_type is SubjectType.CONTROL
                        ],
                    }
                    for item in data.agents
                    if item.system_id == system.id
                ],
                "lifecycle": lifecycle,
                "autonomy": (
                    {
                        "derived_label": derive_autonomy_label(autonomy),
                        "trigger": autonomy.trigger.model_dump(mode="json"),
                        "persistence": autonomy.persistence.model_dump(mode="json"),
                        "permission_scope": autonomy.permission_scope.model_dump(mode="json"),
                        "human_gate": autonomy.human_gate.model_dump(mode="json"),
                        "action_human_gates": {
                            key: value.model_dump(mode="json")
                            for key, value in autonomy.action_human_gates.items()
                        },
                    }
                    if autonomy
                    else None
                ),
                "controls": [
                    {
                        "statement": item.statement,
                        "state": item.state.value,
                        "evidence_ids": item.evidence_ids,
                    }
                    for item in system_assertions
                    if item.slots.subject_type is SubjectType.CONTROL
                ],
                "architecture": [
                    {
                        "statement": item.statement,
                        "state": item.state.value,
                        "evidence_ids": item.evidence_ids,
                    }
                    for item in system_assertions
                    if item.slots.subject_type is SubjectType.ARCHITECTURE_PATTERN
                ],
                "capabilities": capability_rows,
                "conflicts": [
                    item.model_dump(mode="json")
                    for item in data.conflicts
                    if any(
                        assertion_id in {a.id for a in system_assertions}
                        for assertion_id in item.assertion_ids
                    )
                ],
                "recent_changes": [item for item in changes if item["system_id"] == system.id],
                "sources": [
                    {
                        "id": source.id,
                        "publisher": source.publisher,
                        "name": source.name,
                    }
                    for source in data.sources
                    if source.id
                    in {
                        item["source_id"]
                        for capability_row in capability_rows
                        for item in capability_row["evidence"]
                    }
                    | {
                        evidence[evidence_id].source_id
                        for assertion in system_assertions
                        for evidence_id in assertion.contradicting_evidence_ids
                        if evidence_id in evidence
                    }
                ],
                "methodology_version": data.methodology_version,
                "taxonomy_version": data.taxonomy_version,
            }
        )
    has_report_content = bool(
        data.systems
        or data.assertions
        or data.candidates
        or data.confirmed_changes
        or data.conflicts
        or data.latest_review_decisions
    )
    if has_report_content:
        daily = build_daily_brief(
            semantic_as_of.date(),
            data.confirmed_changes,
            data.candidates,
            data.latest_review_decisions,
        )
        freshness = {
            item.id: derive_freshness(item.last_verified_at, as_of=semantic_as_of)
            for item in data.assertions
        }
        weekly = build_weekly_pack(
            semantic_as_of.date(),
            data.confirmed_changes,
            data.conflicts,
            freshness,
            {"preview_to_ga_days": preview_to_ga_velocity(data.lifecycle_events)},
        )
        daily_rows = [
            {
                "date": str(daily.date),
                "status": daily.status.value,
                "markdown": daily.markdown,
            }
        ]
        weekly_rows = [{"date": str(weekly.week_ending), "markdown": weekly.markdown}]
    else:
        daily_rows = []
        weekly_rows = []
    public_source_ids = {source["id"] for system in systems for source in system["sources"]}
    return {
        "generated_at": generated_at.isoformat(),
        "canonical_base": canonical_base.rstrip("/"),
        "methodology_version": data.methodology_version,
        "taxonomy_version": data.taxonomy_version,
        "systems": systems,
        "claims": claims,
        "changes": changes,
        "daily": daily_rows,
        "weekly": weekly_rows,
        "sources": [
            {
                "id": item.id,
                "publisher": item.publisher,
                "name": item.name,
                "role": item.role.value,
                "contributes_evidence": item.id not in excluded_source_ids,
            }
            for item in data.sources
            if item.id in public_source_ids
        ],
    }


def write_site_data(
    output: Path,
    *,
    dry_run: bool,
    database_path: Path | None = None,
    demo: bool = False,
    demo_input: Path | None = None,
) -> dict[str, Any]:
    data = build_site_data(
        database_path=database_path,
        demo=demo,
        demo_input=demo_input,
    )
    if not dry_run:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return data
