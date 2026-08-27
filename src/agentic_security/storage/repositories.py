"""Typed repositories for Pass 1 ledger records."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable

from pydantic import BaseModel

from agentic_security.evidence.validation import (
    validate_evidence_anchor,
    validate_evidence_classification,
    validate_evidence_purpose,
)
from agentic_security.lifecycle.state_machine import validate_transition
from agentic_security.models import (
    Assertion,
    ChangeReviewItem,
    ContradictionFlag,
    ContradictionResolution,
    Evidence,
    GateAPacket,
    LifecycleEvent,
    MaterialChange,
    Observation,
    Snapshot,
    Source,
    StructuredDiff,
)
from agentic_security.storage.initialization import (
    load_authoritative_metadata,
    seed_authoritative_metadata,
)


def _json(model: BaseModel) -> str:
    return model.model_dump_json()


class SourceRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def add(self, source: Source) -> None:
        self.connection.execute(
            """INSERT INTO sources
               (id,publisher,name,kind,trust_class,status,enabled,payload_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                source.id,
                source.publisher,
                source.name,
                source.kind.value,
                source.trust_class.value,
                source.status.value,
                source.enabled,
                _json(source),
            ),
        )

    def sync(self, source: Source) -> None:
        row = self.connection.execute(
            "SELECT payload_json FROM sources WHERE id=?",
            (source.id,),
        ).fetchone()
        if row is None:
            self.add(source)
            return
        existing = Source.model_validate_json(row[0])
        if existing == source:
            return
        self.connection.execute(
            """UPDATE sources
               SET publisher=?,name=?,kind=?,trust_class=?,status=?,enabled=?,payload_json=?
               WHERE id=?""",
            (
                source.publisher,
                source.name,
                source.kind.value,
                source.trust_class.value,
                source.status.value,
                source.enabled,
                _json(source),
                source.id,
            ),
        )


class SnapshotRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def add(self, snapshot: Snapshot) -> None:
        self.connection.execute(
            """INSERT INTO snapshots
               (id,source_id,canonical_uri,retrieved_at,normalizer_version,sha256,content_type,
                raw_content,normalized_text,duplicate_of,repository,commit_sha,file_path)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                snapshot.id,
                snapshot.source_id,
                snapshot.canonical_uri,
                snapshot.retrieved_at.isoformat(),
                snapshot.normalizer_version,
                snapshot.sha256,
                snapshot.content_type,
                snapshot.raw_content,
                snapshot.normalized_text,
                snapshot.duplicate_of,
                snapshot.repository,
                snapshot.commit_sha,
                snapshot.file_path,
            ),
        )


class EvidenceRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def add(self, evidence: Evidence) -> None:
        source_row = self.connection.execute(
            "SELECT payload_json FROM sources WHERE id=?", (evidence.source_id,)
        ).fetchone()
        if source_row is None:
            raise ValueError(f"unknown source: {evidence.source_id}")
        snapshot_row = self.connection.execute(
            """SELECT id,source_id,canonical_uri,retrieved_at,normalizer_version,sha256,
                      content_type,raw_content,normalized_text,duplicate_of,repository,
                      commit_sha,file_path
               FROM snapshots WHERE id=?""",
            (evidence.anchor.snapshot_id,),
        ).fetchone()
        if snapshot_row is None:
            raise ValueError(f"unknown snapshot: {evidence.anchor.snapshot_id}")
        snapshot = Snapshot.model_validate(dict(snapshot_row))
        if evidence.source_id != snapshot.source_id:
            raise ValueError("evidence source_id must match snapshot source_id")
        validate_evidence_anchor(evidence, snapshot)
        validate_evidence_classification(evidence)
        validate_evidence_purpose(evidence, Source.model_validate_json(source_row[0]))
        self.connection.execute(
            """INSERT INTO evidence
               (id,source_id,snapshot_id,source_class,maturity,claim_purpose,
                derivative_of_evidence_id,payload_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                evidence.id,
                evidence.source_id,
                evidence.anchor.snapshot_id,
                evidence.source_class.value,
                evidence.maturity.value,
                evidence.claim_purpose.value,
                evidence.derivative_of_evidence_id,
                _json(evidence),
            ),
        )


class AssertionRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def add(self, assertion: Assertion) -> None:
        self.connection.execute(
            """INSERT INTO assertions
               (id,assertion_key,taxonomy_version,system_id,agent_id,state,statement,published_at,
                modified_at,first_seen_at,retrieved_at,last_seen_at,last_verified_at,effective_at,
                superseded_by,payload_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                assertion.id,
                assertion.assertion_key,
                assertion.taxonomy_version,
                assertion.system_id,
                assertion.agent_id,
                assertion.state.value,
                assertion.statement,
                assertion.published_at.isoformat() if assertion.published_at else None,
                assertion.modified_at.isoformat() if assertion.modified_at else None,
                assertion.first_seen_at.isoformat(),
                assertion.retrieved_at.isoformat(),
                assertion.last_seen_at.isoformat(),
                assertion.last_verified_at.isoformat(),
                assertion.effective_at.isoformat() if assertion.effective_at else None,
                assertion.superseded_by,
                _json(assertion),
            ),
        )
        links: Iterable[tuple[str, str]] = (
            *((evidence_id, "SUPPORTS") for evidence_id in assertion.evidence_ids),
            *((evidence_id, "CONTRADICTS") for evidence_id in assertion.contradicting_evidence_ids),
        )
        self.connection.executemany(
            "INSERT INTO assertion_evidence(assertion_id,evidence_id,relation) VALUES (?,?,?)",
            ((assertion.id, evidence_id, relation) for evidence_id, relation in links),
        )

    def by_key(self, key: str) -> Assertion | None:
        row = self.connection.execute(
            "SELECT payload_json FROM assertions WHERE assertion_key=?", (key,)
        ).fetchone()
        return Assertion.model_validate_json(row[0]) if row else None


class ObservationRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def add(self, observation: Observation) -> None:
        self.connection.execute(
            """INSERT INTO observations
               (id,assertion_id,evidence_id,observed_statement,observed_at,published_at,modified_at,
                first_seen_at,retrieved_at,last_seen_at,last_verified_at,effective_at,is_paraphrase,
                accepted,scope_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                observation.id,
                observation.assertion_id,
                observation.evidence_id,
                observation.observed_statement,
                observation.observed_at.isoformat(),
                observation.published_at.isoformat() if observation.published_at else None,
                observation.modified_at.isoformat() if observation.modified_at else None,
                observation.first_seen_at.isoformat(),
                observation.retrieved_at.isoformat(),
                observation.last_seen_at.isoformat(),
                observation.last_verified_at.isoformat(),
                observation.effective_at.isoformat() if observation.effective_at else None,
                observation.is_paraphrase,
                observation.accepted,
                observation.scope.model_dump_json(),
            ),
        )


class LifecycleRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def history(self, entity_type: str, entity_id: str) -> list[LifecycleEvent]:
        entity_column = "system_id" if entity_type == "system" else "agent_id"
        rows = self.connection.execute(
            f"""SELECT id,system_id,agent_id,state,modifiers_json,effective_at,evidence_id,
                       source_class,retrieved_at,rationale
                FROM lifecycle_events WHERE {entity_column}=? ORDER BY sequence""",
            (entity_id,),
        ).fetchall()
        events = []
        for row in rows:
            values = dict(row)
            modifiers = values.pop("modifiers_json")
            values["modifiers"] = dict(json.loads(modifiers))
            events.append(LifecycleEvent.model_validate(values))
        return events

    def append(self, event: LifecycleEvent) -> None:
        validate_transition(self.history(event.entity_type, event.entity_id), event)
        self.connection.execute(
            """INSERT INTO lifecycle_events
               (id,system_id,agent_id,state,modifiers_json,effective_at,evidence_id,source_class,
                retrieved_at,rationale) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                event.id,
                event.system_id,
                event.agent_id,
                event.state.value,
                event.modifiers.model_dump_json(),
                event.effective_at.isoformat() if event.effective_at else None,
                event.evidence_id,
                event.source_class.value,
                event.retrieved_at.isoformat(),
                event.rationale,
            ),
        )


class GateAPacketRepository:
    """Persist the complete deterministic Gate A corpus in dependency order."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def load(self, packet: GateAPacket) -> None:
        metadata = load_authoritative_metadata()
        if (
            packet.methodology_version != metadata.methodology.id
            or packet.taxonomy_version != metadata.current_taxonomy.id
        ):
            raise ValueError("fixture packet version does not match authoritative metadata")
        seed_authoritative_metadata(self.connection, metadata)
        self.connection.executemany(
            "INSERT INTO vendors(id,name,website) VALUES (?,?,?)",
            ((item.id, item.name, str(item.website)) for item in packet.vendors),
        )
        self.connection.executemany(
            """INSERT INTO systems
               (id,vendor_id,name,category,description,first_observed_at,last_verified_at)
               VALUES (?,?,?,?,?,?,?)""",
            (
                (
                    item.id,
                    item.vendor_id,
                    item.name,
                    item.category,
                    item.description,
                    item.first_observed_at.isoformat(),
                    item.last_verified_at.isoformat(),
                )
                for item in packet.systems
            ),
        )
        self.connection.executemany(
            """INSERT INTO agents
               (id,system_id,name,category,description,first_observed_at,last_verified_at)
               VALUES (?,?,?,?,?,?,?)""",
            (
                (
                    item.id,
                    item.system_id,
                    item.name,
                    item.category,
                    item.description,
                    item.first_observed_at.isoformat(),
                    item.last_verified_at.isoformat(),
                )
                for item in packet.agents
            ),
        )
        self.connection.executemany(
            "INSERT INTO capabilities(id,name,description,taxonomy_version) VALUES (?,?,?,?)",
            (
                (item.id, item.name, item.description, item.taxonomy_version)
                for item in packet.capabilities
            ),
        )
        self.connection.executemany(
            "INSERT INTO controls(id,name,description,taxonomy_version) VALUES (?,?,?,?)",
            (
                (item.id, item.name, item.description, item.taxonomy_version)
                for item in packet.controls
            ),
        )
        self.connection.executemany(
            """INSERT INTO architecture_patterns(id,name,description,taxonomy_version)
               VALUES (?,?,?,?)""",
            (
                (item.id, item.name, item.description, item.taxonomy_version)
                for item in packet.architecture_patterns
            ),
        )
        self.connection.executemany(
            "INSERT INTO models(id,provider,name,version) VALUES (?,?,?,?)",
            ((item.id, item.provider, item.name, item.version) for item in packet.models),
        )
        self.connection.executemany(
            "INSERT INTO harnesses(id,name,version,repository_url) VALUES (?,?,?,?)",
            (
                (
                    item.id,
                    item.name,
                    item.version,
                    str(item.repository_url) if item.repository_url else None,
                )
                for item in packet.harnesses
            ),
        )
        self.connection.executemany(
            """INSERT INTO benchmarks(id,name,version,task_definition,success_criterion)
               VALUES (?,?,?,?,?)""",
            (
                (
                    item.id,
                    item.name,
                    item.version,
                    item.task_definition,
                    item.success_criterion,
                )
                for item in packet.benchmarks
            ),
        )
        source_repository = SourceRepository(self.connection)
        for source in packet.sources:
            source_repository.add(source)
        self.connection.executemany(
            """INSERT INTO source_provenance
               (source_id,derivative_of_source_id,rationale) VALUES (?,?,?)""",
            (
                (item.source_id, item.derivative_of_source_id, item.rationale)
                for item in packet.provenance_edges
            ),
        )
        snapshot_repository = SnapshotRepository(self.connection)
        for snapshot in packet.snapshots:
            snapshot_repository.add(snapshot)
        evidence_repository = EvidenceRepository(self.connection)
        for evidence in packet.evidence:
            evidence_repository.add(evidence)
        assertion_repository = AssertionRepository(self.connection)
        for assertion in packet.assertions:
            assertion_repository.add(assertion)
        observation_repository = ObservationRepository(self.connection)
        for observation in packet.observations:
            observation_repository.add(observation)
        lifecycle_repository = LifecycleRepository(self.connection)
        for lifecycle_event in packet.lifecycle_events:
            lifecycle_repository.append(lifecycle_event)
        self.connection.executemany(
            "INSERT INTO autonomy_assessments(id,system_id,agent_id,payload_json) VALUES (?,?,?,?)",
            (
                (item.id, item.system_id, item.agent_id, _json(item))
                for item in packet.autonomy_assessments
            ),
        )
        self.connection.executemany(
            """INSERT INTO benchmark_results
               (id,benchmark_id,model_id,harness_id,evidence_id,payload_json)
               VALUES (?,?,?,?,?,?)""",
            (
                (
                    item.id,
                    item.benchmark_id,
                    item.model_id,
                    item.harness_id,
                    item.evidence_id,
                    _json(item),
                )
                for item in packet.benchmark_results
            ),
        )
        self.connection.executemany(
            "INSERT INTO material_change_examples(id,payload_json) VALUES (?,?)",
            ((_item.id, _json(_item)) for _item in packet.material_changes),
        )

    def table_count(self, table: str) -> int:
        allowed = {
            "vendors",
            "systems",
            "agents",
            "sources",
            "snapshots",
            "evidence",
            "assertions",
            "observations",
            "lifecycle_events",
            "benchmark_results",
        }
        if table not in allowed:
            raise ValueError("table is not countable through this repository")
        row = self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        assert row is not None
        return int(row[0])


class Pass2Repository:
    """Persist deterministic diffs and human-gated review artifacts."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def add_diff(self, diff: StructuredDiff) -> None:
        self.connection.execute(
            """INSERT INTO structured_diffs
               (id,source_id,old_snapshot_id,new_snapshot_id,material_candidate,payload_json)
               VALUES (?,?,?,?,?,?)""",
            (
                diff.id,
                diff.source_id,
                diff.old_snapshot_id,
                diff.new_snapshot_id,
                diff.material_candidate,
                _json(diff),
            ),
        )

    def add_review(self, review: ChangeReviewItem) -> None:
        self.connection.execute(
            """INSERT INTO change_review_queue(
                 id,candidate_id,prior_review_id,machine_classification,machine_rationale,
                 machine_decision_impacts_json,evidence_status_subtype,status,reviewer,reviewed_at,
                 human_classification,confirmed_decision_impacts_json,human_rationale,
                 methodology_version,payload_json
               ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                review.id,
                review.candidate_id,
                review.prior_review_id,
                review.machine_classification.value,
                review.machine_rationale,
                json.dumps(sorted(item.value for item in review.machine_decision_impacts)),
                (
                    review.evidence_status_subtype.value
                    if review.evidence_status_subtype is not None
                    else None
                ),
                review.status.value,
                review.reviewer,
                review.reviewed_at.isoformat() if review.reviewed_at else None,
                (
                    review.human_classification.value
                    if review.human_classification is not None
                    else None
                ),
                json.dumps(sorted(item.value for item in review.confirmed_decision_impacts)),
                review.human_rationale,
                review.methodology_version,
                _json(review),
            ),
        )

    def add_confirmed_change(self, change: MaterialChange, review_id: str) -> None:
        if not change.human_confirmed or change.confirmed_at is None:
            raise ValueError("only human-confirmed material changes enter the ledger")
        row = self.connection.execute(
            "SELECT status FROM change_review_queue WHERE id=?", (review_id,)
        ).fetchone()
        if row is None or row[0] != "CONFIRMED":
            raise ValueError("material change requires a confirmed human review")
        self.connection.execute(
            """INSERT INTO confirmed_changes(id,review_id,confirmed_at,payload_json)
               VALUES (?,?,?,?)""",
            (change.id, review_id, change.confirmed_at.isoformat(), _json(change)),
        )

    def add_conflict(self, conflict: ContradictionFlag) -> None:
        self.connection.execute(
            """INSERT INTO contradiction_flags(id,status,payload_json) VALUES (?,?,?)""",
            (conflict.id, conflict.status.value, _json(conflict)),
        )

    def add_resolution(self, resolution: ContradictionResolution) -> None:
        self.connection.execute(
            """INSERT INTO contradiction_resolutions(id,conflict_id,reviewed_at,payload_json)
               VALUES (?,?,?,?)""",
            (
                resolution.id,
                resolution.conflict_id,
                resolution.reviewed_at.isoformat(),
                _json(resolution),
            ),
        )
        self.connection.execute(
            "UPDATE contradiction_flags SET status='CONFIRMED' WHERE id=?",
            (resolution.conflict_id,),
        )
