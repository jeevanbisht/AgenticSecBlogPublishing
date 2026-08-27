"""Draft-only downstream GitHub publisher."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pydantic import Field, HttpUrl

from agentic_security.jobs.models import FailureCategory
from agentic_security.models import FrozenModel
from agentic_security.publishing.validation import (
    PublicationManifest,
    validate_publication_bundle,
)
from agentic_security.runtime import RuntimeConfig


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class CommandRunner(Protocol):
    def run(self, args: tuple[str, ...], *, cwd: Path | None = None) -> CommandResult: ...


class SubprocessRunner:
    def run(self, args: tuple[str, ...], *, cwd: Path | None = None) -> CommandResult:
        result = subprocess.run(
            args,
            cwd=cwd,
            capture_output=True,
            check=False,
            text=True,
        )
        return CommandResult(result.returncode, result.stdout, result.stderr)


class PublicationError(RuntimeError):
    def __init__(self, category: FailureCategory, safe_message: str) -> None:
        super().__init__(safe_message)
        self.category = category
        self.safe_message = safe_message


class PublishResult(FrozenModel):
    repository: str
    branch: str = Field(pattern=r"^asi/[a-z0-9][a-z0-9-]*$")
    base_branch: str = "main"
    artifact_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    pull_request_number: int = Field(ge=1)
    pull_request_url: HttpUrl
    draft: bool = True
    duplicate: bool


def publication_artifact_hash(manifest: PublicationManifest) -> str:
    canonical = "\n".join(f"{item.path}:{item.sha256}" for item in manifest.files)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class GitHubDraftPublisher:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        runner: CommandRunner | None = None,
    ) -> None:
        self.config = config
        self.runner = runner or SubprocessRunner()

    def _run(
        self,
        args: tuple[str, ...],
        *,
        cwd: Path | None = None,
        category: FailureCategory = FailureCategory.INTERNAL_ERROR,
        safe_message: str,
    ) -> CommandResult:
        try:
            result = self.runner.run(args, cwd=cwd)
        except OSError as exc:
            raise PublicationError(category, safe_message) from exc
        if result.returncode != 0:
            raise PublicationError(category, safe_message)
        return result

    def _existing_pr(self, branch: str) -> PublishResult | None:
        result = self._run(
            (
                "gh",
                "pr",
                "list",
                "--repo",
                self.config.downstream_repository,
                "--head",
                branch,
                "--state",
                "all",
                "--json",
                "number,url,isDraft,headRefName,baseRefName",
            ),
            category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
            safe_message="GitHub pull-request lookup failed.",
        )
        try:
            rows = json.loads(result.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise PublicationError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "GitHub returned an invalid pull-request response.",
            ) from exc
        if not isinstance(rows, list):
            raise PublicationError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "GitHub returned an invalid pull-request response.",
            )
        if not rows:
            return None
        row = rows[0]
        if (
            not isinstance(row, dict)
            or row.get("headRefName") != branch
            or row.get("baseRefName") != "main"
            or row.get("isDraft") is not True
        ):
            raise PublicationError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "An existing publication pull request is not draft-only against main.",
            )
        artifact_hash = branch.rsplit("-", 1)[-1]
        if len(artifact_hash) != 16:
            raise PublicationError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "The existing publication branch is malformed.",
            )
        try:
            pull_request_url = HttpUrl(str(row["url"]))
            if pull_request_url.host != "github.com":
                raise ValueError("unexpected pull request host")
            return PublishResult(
                repository=self.config.downstream_repository,
                branch=branch,
                artifact_hash="0" * 48 + artifact_hash,
                pull_request_number=int(row["number"]),
                pull_request_url=pull_request_url,
                duplicate=True,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PublicationError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "GitHub returned incomplete pull-request metadata.",
            ) from exc

    def _remote_branch_exists(self, clone_url: str, branch: str) -> bool:
        result = self._run(
            ("git", "ls-remote", "--heads", clone_url, f"refs/heads/{branch}"),
            category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
            safe_message="The publication branch could not be inspected.",
        )
        return bool(result.stdout.strip())

    def _worktree(self, branch: str) -> Path:
        publisher_root = self.config.publication_worktree_path
        publisher_root.mkdir(parents=True, exist_ok=True)
        worktree = publisher_root / branch.replace("/", "-")
        if worktree.exists():
            shutil.rmtree(worktree)
        return worktree

    def _validate_remote_branch(
        self,
        *,
        clone_url: str,
        branch: str,
        artifact_hash: str,
        local_manifest: PublicationManifest,
    ) -> None:
        worktree = self._worktree(branch)
        self._run(
            (
                "git",
                "clone",
                "--filter=blob:none",
                "--single-branch",
                "--branch",
                branch,
                clone_url,
                str(worktree),
            ),
            category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
            safe_message="The existing publication branch could not be cloned.",
        )
        try:
            self._run(
                (
                    "git",
                    "fetch",
                    "--quiet",
                    "origin",
                    "main:refs/remotes/origin/main",
                ),
                cwd=worktree,
                category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
                safe_message="The downstream main branch could not be fetched.",
            )
            changed = self._run(
                ("git", "diff", "--name-only", "origin/main...HEAD"),
                cwd=worktree,
                safe_message="The existing publication branch scope could not be verified.",
            )
            changed_paths = tuple(
                line.strip() for line in changed.stdout.splitlines() if line.strip()
            )
            if not changed_paths or any(
                not path.startswith("publication/") for path in changed_paths
            ):
                raise PublicationError(
                    FailureCategory.PUBLICATION_VALIDATION_FAILED,
                    "The existing publication branch changes files outside publication/.",
                )
            try:
                remote_manifest = validate_publication_bundle(worktree / "publication")
            except (OSError, ValueError) as exc:
                raise PublicationError(
                    FailureCategory.PUBLICATION_VALIDATION_FAILED,
                    "The existing publication branch contains an invalid public bundle.",
                ) from exc
            if publication_artifact_hash(remote_manifest) != artifact_hash:
                raise PublicationError(
                    FailureCategory.PUBLICATION_VALIDATION_FAILED,
                    "The existing publication branch does not match the requested artifact.",
                )
            if remote_manifest.model_dump(exclude={"generated_at"}) != local_manifest.model_dump(
                exclude={"generated_at"}
            ):
                raise PublicationError(
                    FailureCategory.PUBLICATION_VALIDATION_FAILED,
                    "The existing publication manifest does not match the requested artifact.",
                )
        finally:
            if worktree.exists():
                shutil.rmtree(worktree)

    def _create_and_verify_pr(
        self,
        *,
        branch: str,
        artifact_hash: str,
        cwd: Path | None,
        duplicate: bool,
    ) -> PublishResult:
        try:
            self._run(
                (
                    "gh",
                    "pr",
                    "create",
                    "--repo",
                    self.config.downstream_repository,
                    "--draft",
                    "--base",
                    "main",
                    "--head",
                    branch,
                    "--title",
                    f"ASI publication bundle {artifact_hash[:16]}",
                    "--body",
                    ("Validated public-safe ASI projection. Human review and merge are required."),
                ),
                cwd=cwd,
                category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
                safe_message="The draft publication pull request could not be created.",
            )
        except PublicationError:
            raced = self._existing_pr(branch)
            if raced is not None:
                return raced.model_copy(update={"artifact_hash": artifact_hash, "duplicate": True})
            raise
        created = self._existing_pr(branch)
        if created is None:
            raise PublicationError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "The draft publication pull request could not be verified.",
            )
        return created.model_copy(update={"artifact_hash": artifact_hash, "duplicate": duplicate})

    def publish(
        self,
        bundle_root: Path,
        *,
        artifact_type: str = "publication",
    ) -> PublishResult:
        if not artifact_type or any(
            character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in artifact_type
        ):
            raise PublicationError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "The publication artifact type is invalid.",
            )
        try:
            manifest = validate_publication_bundle(bundle_root)
        except (OSError, ValueError) as exc:
            raise PublicationError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "The public bundle failed validation.",
            ) from exc
        artifact_hash = publication_artifact_hash(manifest)
        branch = f"asi/{artifact_type}-{artifact_hash[:16]}"
        self._run(
            ("gh", "auth", "status"),
            category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
            safe_message="GitHub authentication is unavailable.",
        )
        existing = self._existing_pr(branch)
        clone_url = f"https://github.com/{self.config.downstream_repository}.git"
        remote_exists = self._remote_branch_exists(clone_url, branch)
        if existing is not None:
            if not remote_exists:
                raise PublicationError(
                    FailureCategory.PUBLICATION_VALIDATION_FAILED,
                    "The existing publication branch was not found.",
                )
            self._validate_remote_branch(
                clone_url=clone_url,
                branch=branch,
                artifact_hash=artifact_hash,
                local_manifest=manifest,
            )
            return existing.model_copy(update={"artifact_hash": artifact_hash})
        if remote_exists:
            self._validate_remote_branch(
                clone_url=clone_url,
                branch=branch,
                artifact_hash=artifact_hash,
                local_manifest=manifest,
            )
            return self._create_and_verify_pr(
                branch=branch,
                artifact_hash=artifact_hash,
                cwd=None,
                duplicate=True,
            )

        worktree = self._worktree(branch)
        self._run(
            (
                "git",
                "clone",
                "--filter=blob:none",
                "--single-branch",
                "--branch",
                "main",
                clone_url,
                str(worktree),
            ),
            category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
            safe_message="The downstream publication repository could not be cloned.",
        )
        try:
            self._run(
                ("git", "checkout", "-b", branch),
                cwd=worktree,
                safe_message="The draft publication branch could not be created.",
            )
            publication_target = worktree / "publication"
            if publication_target.exists():
                shutil.rmtree(publication_target)
            shutil.copytree(bundle_root, publication_target)
            validate_publication_bundle(publication_target)
            self._run(
                ("git", "config", "user.name", "ASI Runtime"),
                cwd=worktree,
                safe_message="The local publication identity could not be configured.",
            )
            self._run(
                (
                    "git",
                    "config",
                    "user.email",
                    "223556219+Copilot@users.noreply.github.com",
                ),
                cwd=worktree,
                safe_message="The local publication identity could not be configured.",
            )
            self._run(
                ("git", "add", "--", "publication"),
                cwd=worktree,
                safe_message="The public bundle could not be staged.",
            )
            staged = self._run(
                ("git", "diff", "--cached", "--name-only"),
                cwd=worktree,
                safe_message="The staged publication files could not be verified.",
            )
            paths = tuple(line.strip() for line in staged.stdout.splitlines() if line.strip())
            if not paths or any(
                not path.startswith("publication/")
                or Path(path).suffix.lower() in {".db", ".sqlite", ".sqlite3"}
                for path in paths
            ):
                raise PublicationError(
                    FailureCategory.PUBLICATION_VALIDATION_FAILED,
                    "Only validated public bundle files may be committed.",
                )
            self._run(
                (
                    "git",
                    "commit",
                    "-m",
                    (
                        f"Publish ASI bundle {artifact_hash[:16]}\n\n"
                        "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
                    ),
                ),
                cwd=worktree,
                safe_message="The public bundle commit could not be created.",
            )
            self._run(
                ("git", "push", "origin", f"HEAD:refs/heads/{branch}"),
                cwd=worktree,
                category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
                safe_message="The draft publication branch could not be pushed.",
            )
            verified = self._run(
                ("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}"),
                cwd=worktree,
                category=FailureCategory.GITHUB_AUTH_UNAVAILABLE,
                safe_message="The pushed publication branch could not be verified.",
            )
            if not verified.stdout.strip():
                raise PublicationError(
                    FailureCategory.PUBLICATION_VALIDATION_FAILED,
                    "The pushed publication branch was not found.",
                )
            return self._create_and_verify_pr(
                branch=branch,
                artifact_hash=artifact_hash,
                cwd=worktree,
                duplicate=False,
            )
        finally:
            if worktree.exists():
                shutil.rmtree(worktree)
