"""Strict public models for runtime jobs."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import Field

from agentic_security.models import FrozenModel


class JobType(StrEnum):
    COLLECT = "COLLECT"
    RESEARCH = "RESEARCH"
    DAILY = "DAILY"
    WEEKLY_PACK = "WEEKLY_PACK"
    PUBLICATION_EXPORT = "PUBLICATION_EXPORT"
    PUBLICATION_PR = "PUBLICATION_PR"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class FailureCategory(StrEnum):
    CONFIGURATION_UNAVAILABLE = "CONFIGURATION_UNAVAILABLE"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    COLLECTION_FAILED = "COLLECTION_FAILED"
    DISK_GUARD = "DISK_GUARD"
    LEDGER_UNAVAILABLE = "LEDGER_UNAVAILABLE"
    GITHUB_AUTH_UNAVAILABLE = "GITHUB_AUTH_UNAVAILABLE"
    PUBLICATION_VALIDATION_FAILED = "PUBLICATION_VALIDATION_FAILED"
    CONCURRENCY_TIMEOUT = "CONCURRENCY_TIMEOUT"
    INTERRUPTED = "INTERRUPTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class JobRecord(FrozenModel):
    job_id: str = Field(pattern=r"^[a-f0-9-]{36}$")
    job_type: JobType
    requested_by: str
    idempotency_key: str
    created_at: datetime
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    updated_at: datetime
    status: JobStatus
    retry_count: int = Field(ge=0)
    failure_category: FailureCategory | None = None
    sanitized_failure_message: str | None = None
