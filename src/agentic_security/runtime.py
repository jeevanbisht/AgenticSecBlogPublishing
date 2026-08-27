"""Validated runtime configuration and local readiness checks."""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import uuid
from contextlib import suppress
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from agentic_security.storage.database import configure_connection

ROOT = Path(__file__).resolve().parents[2]
SETTINGS_PATH = ROOT / "config" / "settings.yaml"
PUBLISHING_REPOSITORY = "jeevanbisht/AgenticSecBlogPublishing"


def _resolve(root: Path, value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else root / path


def _parse_explicit_bool(name: str, value: str) -> bool:
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError(f"{name} must be explicitly set to true or false")


class RuntimeConfig(BaseModel):
    """Secret-free process configuration loaded from YAML and environment."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    root: Path
    settings_path: Path
    database_path: Path
    snapshot_path: Path
    jobs_path: Path
    export_path: Path
    locks_path: Path
    generated_path: Path
    publication_worktree_path: Path
    canonical_base: HttpUrl
    downstream_repository: str = PUBLISHING_REPOSITORY
    downstream_base_branch: str = "main"
    min_free_bytes: int = Field(default=104_857_600, ge=0)
    worker_heartbeat_ttl_seconds: int = Field(default=60, ge=5, le=600)
    pipeline_lease_seconds: int = Field(default=3_600, ge=30, le=86_400)
    max_restart_retries: int = Field(default=1, ge=0, le=10)
    require_mtls_header: bool = True
    collection_source_ids: tuple[str, ...] = ()
    collection_user_agent: str = Field(
        default="agentic-security-intelligence/0.1",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._/@()+-]*$",
    )
    collection_timeout_seconds: float = Field(default=10, gt=0, le=120)
    collection_max_retries: int = Field(default=2, ge=0, le=10)
    collection_max_response_bytes: int = Field(default=2_000_000, ge=1, le=20_000_000)
    collection_cache_ttl_seconds: int = Field(default=3_600, ge=0, le=86_400)
    collection_max_sources_per_run: int = Field(default=20, ge=1, le=100)

    @field_validator("collection_source_ids")
    @classmethod
    def validate_collection_source_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("collection_source_ids cannot contain duplicates")
        if any(re.fullmatch(r"SRC-[A-Z0-9-]+", item) is None for item in value):
            raise ValueError("collection_source_ids contains an invalid source id")
        return value

    @model_validator(mode="after")
    def fixed_publication_target(self) -> RuntimeConfig:
        if self.downstream_repository != PUBLISHING_REPOSITORY:
            raise ValueError(f"downstream_repository must be {PUBLISHING_REPOSITORY}")
        if self.downstream_base_branch != "main":
            raise ValueError("downstream_base_branch must be main")
        if (
            self.canonical_base.scheme != "https"
            or self.canonical_base.username is not None
            or self.canonical_base.password is not None
            or self.canonical_base.query is not None
            or self.canonical_base.fragment is not None
            or self.canonical_base.path not in {None, "/"}
        ):
            raise ValueError("canonical_base must be an HTTPS origin without path or credentials")
        return self


def load_runtime_config(
    settings_path: Path = SETTINGS_PATH,
    *,
    environ: dict[str, str] | None = None,
) -> RuntimeConfig:
    env = os.environ if environ is None else environ
    root = settings_path.resolve().parents[1]
    raw = yaml.safe_load(settings_path.read_text(encoding="utf-8"))
    runtime = dict(raw.get("runtime", {}))
    publication = dict(raw.get("publication", {}))
    database_value = env.get("ASI_DATABASE_PATH", str(raw["database_path"]))
    snapshot_value = env.get("ASI_SNAPSHOT_PATH", str(raw["snapshot_path"]))
    jobs_value = env.get("ASI_JOBS_PATH", str(runtime["jobs_path"]))
    export_value = env.get("ASI_EXPORT_PATH", str(runtime["export_path"]))
    locks_value = env.get("ASI_LOCKS_PATH", str(runtime["locks_path"]))
    generated_value = env.get("ASI_GENERATED_PATH", str(runtime["generated_path"]))
    worktree_value = env.get(
        "ASI_PUBLICATION_WORKTREE_PATH",
        str(runtime["publication_worktree_path"]),
    )
    configured_source_ids = runtime.get("collection_source_ids", ())
    source_ids_value = env.get(
        "ASI_COLLECTION_SOURCE_IDS",
        ",".join(str(item) for item in configured_source_ids),
    )
    collection_source_ids = tuple(
        item.strip() for item in source_ids_value.split(",") if item.strip()
    )
    canonical = env.get("ASI_PUBLICATION_DOMAIN", str(publication["canonical_base"]))
    require_header = _parse_explicit_bool(
        "ASI_REQUIRE_MTLS_HEADER",
        env.get(
            "ASI_REQUIRE_MTLS_HEADER",
            str(runtime.get("require_mtls_header", True)),
        ),
    )
    return RuntimeConfig(
        root=root,
        settings_path=settings_path,
        database_path=_resolve(root, database_value),
        snapshot_path=_resolve(root, snapshot_value),
        jobs_path=_resolve(root, jobs_value),
        export_path=_resolve(root, export_value),
        locks_path=_resolve(root, locks_value),
        generated_path=_resolve(root, generated_value),
        publication_worktree_path=_resolve(root, worktree_value),
        canonical_base=HttpUrl(canonical),
        downstream_repository=str(publication["downstream_repository"]),
        downstream_base_branch=str(publication["downstream_base_branch"]),
        min_free_bytes=int(runtime["min_free_bytes"]),
        worker_heartbeat_ttl_seconds=int(runtime["worker_heartbeat_ttl_seconds"]),
        pipeline_lease_seconds=int(runtime["pipeline_lease_seconds"]),
        max_restart_retries=int(runtime["max_restart_retries"]),
        require_mtls_header=require_header,
        collection_source_ids=collection_source_ids,
        collection_user_agent=str(raw["collection"]["user_agent"]),
        collection_timeout_seconds=float(raw["collection"]["timeout_seconds"]),
        collection_max_retries=int(raw["collection"]["max_retries"]),
        collection_max_response_bytes=int(raw["collection"]["max_response_bytes"]),
        collection_cache_ttl_seconds=int(raw["collection"]["cache_ttl_seconds"]),
        collection_max_sources_per_run=int(raw["cost_controls"]["max_sources_per_run"]),
    )


def ledger_reachable(config: RuntimeConfig) -> bool:
    if not config.database_path.is_file():
        return False
    try:
        connection = configure_connection(
            sqlite3.connect(
                f"file:{config.database_path.as_posix()}?mode=ro",
                uri=True,
                timeout=5,
            ),
            enable_wal=False,
        )
        try:
            connection.execute("SELECT 1 FROM systems LIMIT 1").fetchone()
            connection.execute("SELECT 1 FROM jobs LIMIT 1").fetchone()
            from agentic_security.storage.initialization import (
                load_authoritative_metadata,
                verify_authoritative_metadata,
            )

            verify_authoritative_metadata(
                connection,
                load_authoritative_metadata(config.settings_path),
            )
        finally:
            connection.close()
    except (OSError, sqlite3.Error, ValueError):
        return False
    return True


def runtime_writable(config: RuntimeConfig) -> bool:
    paths = (
        config.database_path.parent,
        config.snapshot_path,
        config.jobs_path,
        config.export_path,
        config.locks_path,
        config.generated_path,
        config.publication_worktree_path,
    )
    for path in paths:
        marker = path / f".write-check-{uuid.uuid4().hex}"
        descriptor: int | None = None
        try:
            path.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                marker,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            os.write(descriptor, b"ok")
            os.close(descriptor)
            descriptor = None
        except OSError:
            return False
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            with suppress(OSError):
                marker.unlink()
    return True


def disk_guard(config: RuntimeConfig) -> None:
    path = config.jobs_path
    path.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(path).free
    if free < config.min_free_bytes:
        raise RuntimeError("DISK_GUARD")


def safe_runtime_checks(config: RuntimeConfig, *, worker_available: bool) -> dict[str, Any]:
    return {
        "config_valid": True,
        "ledger_reachable": ledger_reachable(config),
        "runtime_writable": runtime_writable(config),
        "worker_available": worker_available,
    }
