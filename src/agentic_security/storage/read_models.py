"""Read models for publication and reporting from the SQLite ledger."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TypeVar

import yaml
from pydantic import BaseModel

from agentic_security.models import (
    Agent,
    ArchitecturePattern,
    Assertion,
    AutonomyAssessment,
    Capability,
    ChangeReviewItem,
    ContradictionFlag,
    Control,
    Evidence,
    GateAPacket,
    LifecycleEvent,
    MaterialChange,
    Observation,
    Source,
    StructuredDiff,
    System,
    Vendor,
)
from agentic_security.storage.database import configure_connection
from agentic_security.storage.initialization import (
    AuthoritativeMetadata,
    load_authoritative_metadata,
    verify_authoritative_metadata,
)

ROOT = Path(__file__).resolve().parents[3]
SETTINGS_PATH = ROOT / "config" / "settings.yaml"
ModelT = TypeVar("ModelT", bound=BaseModel)


@dataclass(frozen=True)
class PublicationLedgerData:
    taxonomy_version: str
    methodology_version: str
    methodology_published_at: datetime
    vendors: tuple[Vendor, ...]
    systems: tuple[System, ...]
    agents: tuple[Agent, ...]
    capabilities: tuple[Capability, ...]
    controls: tuple[Control, ...]
    architecture_patterns: tuple[ArchitecturePattern, ...]
    sources: tuple[Source, ...]
    evidence: tuple[Evidence, ...]
    assertions: tuple[Assertion, ...]
    observations: tuple[Observation, ...]
    lifecycle_events: tuple[LifecycleEvent, ...]
    autonomy_assessments: tuple[AutonomyAssessment, ...]
    candidates: tuple[StructuredDiff, ...]
    confirmed_changes: tuple[MaterialChange, ...]
    change_reviews: dict[str, ChangeReviewItem]
    conflicts: tuple[ContradictionFlag, ...]
    latest_review_decisions: tuple[ChangeReviewItem, ...]

    @classmethod
    def from_packet(
        cls,
        packet: GateAPacket,
        *,
        conflicts: tuple[ContradictionFlag, ...] = (),
        candidates: tuple[StructuredDiff, ...] = (),
        latest_review_decisions: tuple[ChangeReviewItem, ...] = (),
    ) -> PublicationLedgerData:
        metadata = load_authoritative_metadata()
        return cls(
            taxonomy_version=packet.taxonomy_version,
            methodology_version=packet.methodology_version,
            methodology_published_at=metadata.methodology.published_at,
            vendors=packet.vendors,
            systems=packet.systems,
            agents=packet.agents,
            capabilities=packet.capabilities,
            controls=packet.controls,
            architecture_patterns=packet.architecture_patterns,
            sources=packet.sources,
            evidence=packet.evidence,
            assertions=packet.assertions,
            observations=tuple(item for item in packet.observations if item.accepted),
            lifecycle_events=packet.lifecycle_events,
            autonomy_assessments=packet.autonomy_assessments,
            candidates=candidates,
            confirmed_changes=packet.material_changes,
            change_reviews={},
            conflicts=conflicts,
            latest_review_decisions=latest_review_decisions,
        )


def configured_database_path(settings_path: Path = SETTINGS_PATH) -> Path:
    settings = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    configured = Path(str(settings["database_path"]))
    return configured if configured.is_absolute() else ROOT / configured


class LedgerReadRepository:
    """Query validated publication inputs from an initialized SQLite ledger."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        metadata: AuthoritativeMetadata | None = None,
    ) -> None:
        self.connection = connection
        self.metadata = metadata or load_authoritative_metadata()

    def _payloads(self, table: str, model: type[ModelT]) -> tuple[ModelT, ...]:
        allowed = {
            "sources",
            "evidence",
            "assertions",
            "autonomy_assessments",
            "confirmed_changes",
            "contradiction_flags",
            "change_review_queue",
            "structured_diffs",
        }
        if table not in allowed:
            raise ValueError(f"unsupported payload table: {table}")
        rows = self.connection.execute(
            f"SELECT payload_json FROM {table} ORDER BY rowid"
        ).fetchall()
        return tuple(model.model_validate_json(row[0]) for row in rows)

    def taxonomy_version(self) -> str:
        row = self.connection.execute(
            "SELECT id FROM taxonomy_versions ORDER BY published_at DESC, id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise ValueError("ledger has no taxonomy version")
        return str(row[0])

    def methodology_version(self) -> str:
        row = self.connection.execute(
            "SELECT id FROM methodology_versions ORDER BY published_at DESC, id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise ValueError("ledger has no methodology version")
        return str(row[0])

    def vendors(self) -> tuple[Vendor, ...]:
        rows = self.connection.execute("SELECT id,name,website FROM vendors ORDER BY id").fetchall()
        return tuple(Vendor.model_validate(dict(row)) for row in rows)

    def systems(self) -> tuple[System, ...]:
        rows = self.connection.execute(
            """SELECT id,vendor_id,name,category,description,first_observed_at,last_verified_at
               FROM systems ORDER BY id"""
        ).fetchall()
        return tuple(System.model_validate(dict(row)) for row in rows)

    def agents(self) -> tuple[Agent, ...]:
        rows = self.connection.execute(
            """SELECT id,system_id,name,category,description,first_observed_at,last_verified_at
               FROM agents ORDER BY id"""
        ).fetchall()
        return tuple(Agent.model_validate(dict(row)) for row in rows)

    def capabilities(self) -> tuple[Capability, ...]:
        rows = self.connection.execute(
            "SELECT id,name,description,taxonomy_version FROM capabilities ORDER BY id"
        ).fetchall()
        return tuple(Capability.model_validate(dict(row)) for row in rows)

    def controls(self) -> tuple[Control, ...]:
        rows = self.connection.execute(
            "SELECT id,name,description,taxonomy_version FROM controls ORDER BY id"
        ).fetchall()
        return tuple(Control.model_validate(dict(row)) for row in rows)

    def architecture_patterns(self) -> tuple[ArchitecturePattern, ...]:
        rows = self.connection.execute(
            """SELECT id,name,description,taxonomy_version
               FROM architecture_patterns ORDER BY id"""
        ).fetchall()
        return tuple(ArchitecturePattern.model_validate(dict(row)) for row in rows)

    def sources(self) -> tuple[Source, ...]:
        return self._payloads("sources", Source)

    def evidence(self) -> tuple[Evidence, ...]:
        return self._payloads("evidence", Evidence)

    def assertions(self) -> tuple[Assertion, ...]:
        return self._payloads("assertions", Assertion)

    def accepted_observations(self) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            """SELECT id,assertion_id,evidence_id,observed_statement,observed_at,published_at,
                      modified_at,first_seen_at,retrieved_at,last_seen_at,last_verified_at,
                      effective_at,is_paraphrase,accepted,scope_json
               FROM observations WHERE accepted=1 ORDER BY observed_at,id"""
        ).fetchall()
        observations = []
        for row in rows:
            values = dict(row)
            values["is_paraphrase"] = bool(values["is_paraphrase"])
            values["accepted"] = bool(values["accepted"])
            values["scope"] = json.loads(values.pop("scope_json"))
            observations.append(Observation.model_validate(values))
        return tuple(observations)

    def lifecycle(self) -> tuple[LifecycleEvent, ...]:
        rows = self.connection.execute(
            """SELECT id,system_id,agent_id,state,modifiers_json,effective_at,evidence_id,
                      source_class,retrieved_at,rationale
               FROM lifecycle_events ORDER BY sequence"""
        ).fetchall()
        events = []
        for row in rows:
            values = dict(row)
            values["modifiers"] = json.loads(values.pop("modifiers_json"))
            events.append(LifecycleEvent.model_validate(values))
        return tuple(events)

    def autonomy_assessments(self) -> tuple[AutonomyAssessment, ...]:
        return self._payloads("autonomy_assessments", AutonomyAssessment)

    def confirmed_changes(self) -> tuple[MaterialChange, ...]:
        return self._payloads("confirmed_changes", MaterialChange)

    def candidates(self) -> tuple[StructuredDiff, ...]:
        return self._payloads("structured_diffs", StructuredDiff)

    def confirmed_change_reviews(self) -> dict[str, ChangeReviewItem]:
        rows = self.connection.execute(
            """SELECT changes.id,reviews.payload_json
               FROM confirmed_changes changes
               JOIN change_review_queue reviews ON reviews.id=changes.review_id
               ORDER BY changes.confirmed_at,changes.id"""
        ).fetchall()
        return {str(row[0]): ChangeReviewItem.model_validate_json(row[1]) for row in rows}

    def conflicts(self) -> tuple[ContradictionFlag, ...]:
        return self._payloads("contradiction_flags", ContradictionFlag)

    def latest_reviews(self) -> tuple[ChangeReviewItem, ...]:
        rows = self.connection.execute(
            """SELECT current.payload_json
               FROM change_review_queue current
               WHERE NOT EXISTS (
                 SELECT 1 FROM change_review_queue newer
                 WHERE newer.prior_review_id=current.id
               )
               ORDER BY current.rowid"""
        ).fetchall()
        return tuple(ChangeReviewItem.model_validate_json(row[0]) for row in rows)

    def publication_data(self) -> PublicationLedgerData:
        authoritative = verify_authoritative_metadata(self.connection, self.metadata)
        systems = self.systems()
        return PublicationLedgerData(
            taxonomy_version=self.taxonomy_version(),
            methodology_version=self.methodology_version(),
            methodology_published_at=authoritative.methodology.published_at,
            vendors=self.vendors(),
            systems=systems,
            agents=self.agents(),
            capabilities=self.capabilities(),
            controls=self.controls(),
            architecture_patterns=self.architecture_patterns(),
            sources=self.sources(),
            evidence=self.evidence(),
            assertions=self.assertions(),
            observations=self.accepted_observations(),
            lifecycle_events=self.lifecycle(),
            autonomy_assessments=self.autonomy_assessments(),
            candidates=self.candidates(),
            confirmed_changes=self.confirmed_changes(),
            change_reviews=self.confirmed_change_reviews(),
            conflicts=self.conflicts(),
            latest_review_decisions=self.latest_reviews(),
        )


def read_publication_ledger(
    path: Path,
    *,
    settings_path: Path = SETTINGS_PATH,
) -> PublicationLedgerData:
    if not path.is_file():
        raise FileNotFoundError(
            f"configured SQLite ledger does not exist: {path}. "
            "Initialize/load it or select explicit demo mode."
        )
    connection = configure_connection(sqlite3.connect(path), enable_wal=False)
    try:
        return LedgerReadRepository(
            connection,
            load_authoritative_metadata(settings_path),
        ).publication_data()
    except sqlite3.OperationalError as exc:
        raise ValueError(f"SQLite ledger is not initialized or is incompatible: {path}") from exc
    finally:
        connection.close()


def read_demo_packet(path: Path) -> PublicationLedgerData:
    if path.is_dir():
        gate_a_path = path / "gate_a.json"
        gate_b_path = path / "gate_b.json"
    else:
        gate_a_path = path
        gate_b_path = None
    if not gate_a_path.is_file():
        raise FileNotFoundError(f"committed demo input does not exist: {path}")
    conflicts: tuple[ContradictionFlag, ...] = ()
    candidates: tuple[StructuredDiff, ...] = ()
    latest_reviews: tuple[ChangeReviewItem, ...] = ()
    if gate_b_path is not None:
        if not gate_b_path.is_file():
            raise FileNotFoundError(f"committed demo input does not exist: {gate_b_path}")
        pass2 = json.loads(gate_b_path.read_text(encoding="utf-8"))
        conflicts = tuple(
            ContradictionFlag.model_validate(item) for item in pass2.get("conflicts", ())
        )
        candidates = tuple(StructuredDiff.model_validate(item) for item in pass2.get("diffs", ()))
        latest_reviews = tuple(
            ChangeReviewItem.model_validate(item) for item in pass2.get("reviews", ())
        )
    return PublicationLedgerData.from_packet(
        GateAPacket.model_validate_json(gate_a_path.read_text(encoding="utf-8")),
        conflicts=conflicts,
        candidates=candidates,
        latest_review_decisions=latest_reviews,
    )
