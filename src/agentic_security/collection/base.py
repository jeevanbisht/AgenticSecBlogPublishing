"""Collection protocols, limits, cache, and private snapshot storage."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from agentic_security.models import Snapshot, SourceId
from agentic_security.normalization import NORMALIZER_VERSION, content_sha256, normalize


@dataclass(frozen=True)
class RetrievalLimits:
    timeout_seconds: float = 10.0
    max_retries: int = 2
    max_response_bytes: int = 2_000_000
    max_redirects: int = 5
    min_interval_seconds: float = 0.25
    allowed_content_types: tuple[str, ...] = (
        "text/html",
        "text/plain",
        "text/markdown",
        "application/xhtml+xml",
    )


class RobotsPolicy(Protocol):
    def allowed(self, user_agent: str, url: str) -> bool: ...


class AllowAllRobots:
    """Tests/fixtures policy. Live deployments should inject a robots.txt implementation."""

    def allowed(self, user_agent: str, url: str) -> bool:
        return True


@dataclass(frozen=True)
class CachedResponse:
    content: bytes
    content_type: str


class RetrievalCache:
    def __init__(self) -> None:
        self._content: dict[str, CachedResponse] = {}

    def get(self, uri: str) -> CachedResponse | None:
        return self._content.get(uri)

    def put(self, uri: str, value: bytes, content_type: str) -> None:
        self._content[uri] = CachedResponse(value, content_type)


class PersistentRetrievalCache(RetrievalCache):
    """Private content-addressed response cache that survives worker restarts."""

    def __init__(self, root: Path, *, max_age_seconds: float | None = None) -> None:
        super().__init__()
        self.root = root
        self.max_age_seconds = max_age_seconds
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _paths(self, uri: str) -> tuple[Path, Path]:
        key = hashlib.sha256(uri.encode("utf-8")).hexdigest()
        return self.root / f"{key}.body", self.root / f"{key}.json"

    def get(self, uri: str) -> CachedResponse | None:
        body_path, metadata_path = self._paths(uri)
        if not body_path.is_file() or not metadata_path.is_file():
            return None
        try:
            content = body_path.read_bytes()
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if (
                self.max_age_seconds is not None
                and time.time() - float(metadata["stored_at"]) > self.max_age_seconds
            ):
                return None
            if hashlib.sha256(content).hexdigest() != metadata["sha256"]:
                return None
            return CachedResponse(content, str(metadata["content_type"]))
        except (KeyError, OSError, TypeError, ValueError):
            return None

    def put(self, uri: str, value: bytes, content_type: str) -> None:
        body_path, metadata_path = self._paths(uri)
        nonce = uuid.uuid4().hex
        body_stage = self.root / f".{body_path.name}.{nonce}"
        metadata_stage = self.root / f".{metadata_path.name}.{nonce}"
        try:
            body_stage.write_bytes(value)
            metadata_stage.write_text(
                json.dumps(
                    {
                        "content_type": content_type,
                        "sha256": hashlib.sha256(value).hexdigest(),
                        "stored_at": time.time(),
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            os.replace(body_stage, body_path)
            os.replace(metadata_stage, metadata_path)
        finally:
            body_stage.unlink(missing_ok=True)
            metadata_stage.unlink(missing_ok=True)


class SnapshotStore:
    """Private JSON snapshot persistence; raw bytes are intentionally not published."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, snapshot: Snapshot) -> Path:
        path = self.root / f"{snapshot.id}.json"
        path.write_text(snapshot.model_dump_json(indent=2), encoding="utf-8")
        return path

    def load(self, snapshot_id: str) -> Snapshot:
        raw = json.loads((self.root / f"{snapshot_id}.json").read_text(encoding="utf-8"))
        return Snapshot.model_validate(raw)


def build_snapshot(
    *,
    snapshot_id: str,
    source_id: SourceId,
    canonical_uri: str,
    content_type: str,
    raw_text: str,
    retrieved_at: datetime | None = None,
    repository: str | None = None,
    commit_sha: str | None = None,
    file_path: str | None = None,
) -> Snapshot:
    normalized = normalize(raw_text)
    return Snapshot(
        id=snapshot_id,
        source_id=source_id,
        canonical_uri=canonical_uri,
        retrieved_at=retrieved_at or datetime.now(UTC),
        normalizer_version=NORMALIZER_VERSION,
        sha256=content_sha256(normalized),
        content_type=content_type,
        raw_content=raw_text,
        normalized_text=normalized,
        repository=repository,
        commit_sha=commit_sha,
        file_path=file_path,
    )
