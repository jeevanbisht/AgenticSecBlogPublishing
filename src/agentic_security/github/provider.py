"""Provider boundary for branch and pull-request operations."""

from __future__ import annotations

from typing import Protocol

from agentic_security.publishing.artifacts import PullRequestArtifact


class GitHubProvider(Protocol):
    def prepare_pull_request(
        self, artifact: PullRequestArtifact, *, dry_run: bool
    ) -> PullRequestArtifact: ...


class MockGitHubProvider:
    """Deterministic provider used by tests and local pipelines."""

    def __init__(self) -> None:
        self.requests: list[PullRequestArtifact] = []

    def prepare_pull_request(
        self, artifact: PullRequestArtifact, *, dry_run: bool
    ) -> PullRequestArtifact:
        if not dry_run:
            self.requests.append(artifact)
        return artifact
