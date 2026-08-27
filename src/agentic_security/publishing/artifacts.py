"""Generate auditable, PR-ready artifacts without merging or publishing."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import Field

from agentic_security.models import FrozenModel


class PublicationFile(FrozenModel):
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)


class PullRequestArtifact(FrozenModel):
    branch: str = Field(pattern=r"^agent/[a-z0-9][a-z0-9._/-]*$")
    base_branch: str
    title: str
    body: str
    draft: bool = True
    files: tuple[PublicationFile, ...]
    generated_at: datetime
    human_merge_required: bool = True
    auto_merge: bool = False


def build_pull_request_artifact(
    paths: tuple[Path, ...],
    *,
    branch: str,
    base_branch: str,
    title: str,
    body: str,
    generated_at: datetime | None = None,
) -> PullRequestArtifact:
    files = tuple(
        PublicationFile(
            path=path.as_posix(),
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            size_bytes=path.stat().st_size,
        )
        for path in sorted(paths)
    )
    return PullRequestArtifact(
        branch=branch,
        base_branch=base_branch,
        title=title,
        body=body,
        files=files,
        generated_at=generated_at or datetime.now(UTC),
    )


def write_pull_request_artifact(
    artifact: PullRequestArtifact, output: Path, *, dry_run: bool
) -> bool:
    if dry_run:
        return False
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(artifact.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    return True
