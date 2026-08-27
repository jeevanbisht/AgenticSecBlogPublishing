"""Bounded live collection into private snapshots without claim derivation."""

from __future__ import annotations

import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from agentic_security.collection.base import (
    PersistentRetrievalCache,
    RetrievalLimits,
    SnapshotStore,
)
from agentic_security.collection.http import FailClosedRobotsPolicy, HttpRetriever
from agentic_security.jobs.models import FailureCategory
from agentic_security.models import (
    RegistryStatus,
    Snapshot,
    Source,
    SourceKind,
    SourceRole,
    TrustClass,
)
from agentic_security.runtime import RuntimeConfig
from agentic_security.sources.registry import SourceRegistry
from agentic_security.storage.database import Database
from agentic_security.storage.repositories import SnapshotRepository, SourceRepository


class LiveCollectionError(RuntimeError):
    def __init__(self, category: FailureCategory, safe_message: str) -> None:
        super().__init__(safe_message)
        self.category = category
        self.safe_message = safe_message


@dataclass(frozen=True)
class CollectionResult:
    fetched_count: int
    persisted_count: int
    duplicate_count: int
    source_ids: tuple[str, ...]


class LiveCollectionService:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        registry: SourceRegistry | None = None,
        transports: dict[str, httpx.BaseTransport] | None = None,
    ) -> None:
        self.config = config
        self._registry = registry
        self.transports = transports or {}

    def collect(self) -> CollectionResult:
        sources = self._validated_sources()
        registry = self._source_registry()
        limits = RetrievalLimits(
            timeout_seconds=self.config.collection_timeout_seconds,
            max_retries=self.config.collection_max_retries,
            max_response_bytes=self.config.collection_max_response_bytes,
        )
        cache = PersistentRetrievalCache(
            self.config.jobs_path / "cache" / "http",
            max_age_seconds=self.config.collection_cache_ttl_seconds,
        )
        fetched: list[tuple[Source, Snapshot]] = []
        for source in sources:
            transport = self.transports.get(source.id)
            policy = FailClosedRobotsPolicy(
                registry,
                source.id,
                limits=limits,
                transport=transport,
            )
            retriever = HttpRetriever(
                registry,
                limits=limits,
                robots=policy,
                cache=cache,
                transport=transport,
                user_agent=self.config.collection_user_agent,
            )
            try:
                assert source.base_url is not None
                snapshot = retriever.retrieve(
                    source.id,
                    str(source.base_url),
                    self._snapshot_id(source.id),
                )
            except PermissionError as exc:
                raise LiveCollectionError(
                    FailureCategory.COLLECTION_FAILED,
                    "Collection was denied by the configured source access policy.",
                ) from exc
            except (httpx.HTTPError, UnicodeDecodeError, ValueError) as exc:
                raise LiveCollectionError(
                    FailureCategory.COLLECTION_FAILED,
                    "One or more configured sources could not be collected.",
                ) from exc
            fetched.append((source, snapshot))
        return self._persist(fetched)

    def _validated_sources(self) -> tuple[Source, ...]:
        source_ids = self.config.collection_source_ids
        if not source_ids:
            raise LiveCollectionError(
                FailureCategory.CONFIGURATION_UNAVAILABLE,
                "No live collection sources are configured.",
            )
        if len(source_ids) > self.config.collection_max_sources_per_run:
            raise LiveCollectionError(
                FailureCategory.CONFIGURATION_UNAVAILABLE,
                "Configured live collection sources exceed the run limit.",
            )
        sources = []
        registry = self._source_registry()
        for source_id in source_ids:
            try:
                source = registry.get(source_id)
            except ValueError as exc:
                raise LiveCollectionError(
                    FailureCategory.CONFIGURATION_UNAVAILABLE,
                    "A configured live collection source is not governed.",
                ) from exc
            if (
                not source.enabled
                or source.status is not RegistryStatus.APPROVED
                or source.role is not SourceRole.INPUT
                or source.trust_class is TrustClass.SELF
                or source.kind is not SourceKind.HTTP
                or source.base_url is None
            ):
                raise LiveCollectionError(
                    FailureCategory.CONFIGURATION_UNAVAILABLE,
                    "A configured source is not approved for live HTTP collection.",
                )
            sources.append(source)
        return tuple(sources)

    def _source_registry(self) -> SourceRegistry:
        if self._registry is None:
            try:
                self._registry = SourceRegistry.from_yaml(
                    self.config.root / "config" / "sources.yaml",
                    publication_base_url=str(self.config.canonical_base),
                )
            except (FileNotFoundError, ValueError) as exc:
                raise LiveCollectionError(
                    FailureCategory.CONFIGURATION_UNAVAILABLE,
                    "The governed source registry is unavailable.",
                ) from exc
        return self._registry

    def _persist(self, fetched: list[tuple[Source, Snapshot]]) -> CollectionResult:
        database = Database(self.config.database_path)
        snapshot_store = SnapshotStore(self.config.snapshot_path)
        created_paths: list[Path] = []
        persisted_ids: list[str] = []
        duplicate_count = 0
        try:
            with database.transaction(immediate=True) as connection:
                source_repository = SourceRepository(connection)
                snapshot_repository = SnapshotRepository(connection)
                for source, _ in fetched:
                    source_repository.sync(source)
                for _, snapshot in fetched:
                    duplicate = connection.execute(
                        """SELECT id FROM snapshots
                           WHERE source_id=? AND sha256=?
                           ORDER BY retrieved_at,id LIMIT 1""",
                        (snapshot.source_id, snapshot.sha256),
                    ).fetchone()
                    if duplicate is not None:
                        duplicate_count += 1
                        continue
                    created_paths.append(snapshot_store.save(snapshot))
                    snapshot_repository.add(snapshot)
                    persisted_ids.append(snapshot.id)
        except Exception:
            for path in created_paths:
                path.unlink(missing_ok=True)
            raise
        self._verify_persisted(persisted_ids, tuple(source for source, _ in fetched))
        return CollectionResult(
            fetched_count=len(fetched),
            persisted_count=len(persisted_ids),
            duplicate_count=duplicate_count,
            source_ids=tuple(source.id for source, _ in fetched),
        )

    def _verify_persisted(
        self,
        snapshot_ids: list[str],
        sources: tuple[Source, ...],
    ) -> None:
        with closing(Database(self.config.database_path).connect()) as connection:
            for source in sources:
                row = connection.execute(
                    "SELECT payload_json FROM sources WHERE id=?",
                    (source.id,),
                ).fetchone()
                if row is None or Source.model_validate_json(row[0]) != source:
                    raise LiveCollectionError(
                        FailureCategory.COLLECTION_FAILED,
                        "Governed source persistence could not be verified.",
                    )
            for snapshot_id in snapshot_ids:
                row = connection.execute(
                    "SELECT 1 FROM snapshots WHERE id=?",
                    (snapshot_id,),
                ).fetchone()
                if row is None or not (self.config.snapshot_path / f"{snapshot_id}.json").is_file():
                    raise LiveCollectionError(
                        FailureCategory.COLLECTION_FAILED,
                        "Collected snapshot persistence could not be verified.",
                    )

    @staticmethod
    def _snapshot_id(source_id: str) -> str:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        suffix = source_id.removeprefix("SRC-")
        nonce = uuid.uuid4().hex[:8].upper()
        return f"SNAP-{suffix}-{timestamp}-{nonce}"
