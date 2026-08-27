"""Bounded docs-as-git retrieval with deterministic commit provenance."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Protocol

from agentic_security.collection.base import build_snapshot
from agentic_security.models import Snapshot
from agentic_security.sources.registry import SourceRegistry

_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/-]+$")


class GitBackend(Protocol):
    def sync(self, repository_url: str, destination: Path) -> None: ...

    def head(self, destination: Path) -> str: ...

    def read(self, destination: Path, commit_sha: str, file_path: str) -> str: ...


class SubprocessGitBackend:
    """Git backend using argument arrays only; no downloaded code is executed."""

    def sync(self, repository_url: str, destination: Path) -> None:
        if (destination / ".git").exists():
            subprocess.run(
                ["git", "-C", str(destination), "fetch", "--quiet", "--depth=1", "origin"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", str(destination), "reset", "--quiet", "--hard", "origin/HEAD"],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                ["git", "clone", "--quiet", "--depth=1", repository_url, str(destination)],
                check=True,
                capture_output=True,
                text=True,
            )

    def head(self, destination: Path) -> str:
        return subprocess.run(
            ["git", "-C", str(destination), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def read(self, destination: Path, commit_sha: str, file_path: str) -> str:
        return subprocess.run(
            ["git", "-C", str(destination), "show", f"{commit_sha}:{file_path}"],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout


class GitRetriever:
    def __init__(
        self, registry: SourceRegistry, checkout_root: Path, backend: GitBackend | None = None
    ) -> None:
        self.registry = registry
        self.checkout_root = checkout_root
        self.backend = backend or SubprocessGitBackend()

    def retrieve(self, source_id: str, file_path: str, snapshot_id: str) -> Snapshot:
        source = self.registry.get(source_id)
        if (
            not source.enabled
            or source.kind.value != "GIT"
            or not source.base_url
            or not source.repository
        ):
            raise ValueError("source is not an enabled git source")
        if not _SAFE_PATH.fullmatch(file_path) or ".." in Path(file_path).parts:
            raise ValueError("unsafe git file path")
        destination = self.checkout_root / source_id
        repository_url = str(source.base_url)
        self.backend.sync(repository_url, destination)
        commit_sha = self.backend.head(destination)
        if not re.fullmatch(r"[a-f0-9]{40}", commit_sha):
            raise ValueError("git backend returned an invalid commit SHA")
        text = self.backend.read(destination, commit_sha, file_path)
        return build_snapshot(
            snapshot_id=snapshot_id,
            source_id=source.id,
            canonical_uri=f"{repository_url}@{commit_sha}:{file_path}",
            content_type="text/markdown",
            raw_text=text,
            repository=source.repository,
            commit_sha=commit_sha,
            file_path=file_path,
        )
