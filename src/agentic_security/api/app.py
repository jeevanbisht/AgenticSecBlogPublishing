"""Thin authenticated API for durable ASI runtime jobs."""

from __future__ import annotations

import re
import sqlite3
from typing import Annotated

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from agentic_security import __version__
from agentic_security.jobs.models import JobRecord, JobStatus, JobType
from agentic_security.jobs.store import IdempotencyConflictError, JobStore
from agentic_security.runtime import (
    RuntimeConfig,
    disk_guard,
    load_runtime_config,
    safe_runtime_checks,
)
from agentic_security.storage.database import Database

API_PREFIX = "/api/v1"
MTLS_VERIFY_HEADER = "X-ASI-Client-Verify"
MTLS_IDENTITY_HEADER = "X-ASI-Client-DN"


class JobCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_type: JobType
    requested_by: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._:@/+=,-]*$",
    )
    idempotency_key: str = Field(
        min_length=8,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )


class JobCreateResponse(BaseModel):
    job: JobRecord
    idempotent_replay: bool


class ReviewPendingItem(BaseModel):
    review_id: str
    candidate_id: str
    machine_classification: str
    evidence_status_subtype: str | None
    decision_impacts: tuple[str, ...]
    status: str


class StatusJobSummary(BaseModel):
    job_id: str
    job_type: JobType
    status: JobStatus
    started_at: str | None
    finished_at: str | None

    @classmethod
    def from_job(cls, job: JobRecord | None) -> StatusJobSummary | None:
        if job is None:
            return None
        return cls(
            job_id=job.job_id,
            job_type=job.job_type,
            status=job.status,
            started_at=job.started_at.isoformat() if job.started_at else None,
            finished_at=job.finished_at.isoformat() if job.finished_at else None,
        )


class RuntimeStatusResponse(BaseModel):
    service: str
    asi_version: str
    config_valid: bool
    ledger_reachable: bool
    runtime_writable: bool
    worker_available: bool
    methodology_version: str | None
    taxonomy_version: str | None
    source_ledger_version: str | None
    queued_jobs: int
    running_jobs: int
    failed_jobs: int
    pending_review_count: int
    last_successful_job: StatusJobSummary | None
    active_job: StatusJobSummary | None
    last_collection: StatusJobSummary | None
    last_daily_output: StatusJobSummary | None
    last_weekly_output: StatusJobSummary | None
    last_publication_export: StatusJobSummary | None


def _runtime_store(config: RuntimeConfig) -> JobStore:
    if config.database_path.is_file():
        Database(config.database_path).initialize()
    return JobStore(config.database_path)


def create_app(config: RuntimeConfig | None = None) -> FastAPI:
    runtime_config = config or load_runtime_config()
    store = _runtime_store(runtime_config)
    app = FastAPI(
        title="Agentic Security Intelligence Runtime",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=f"{API_PREFIX}/openapi.json",
    )
    app.state.runtime_config = runtime_config
    app.state.job_store = store

    def require_mtls(
        request: Request,
        client_verify: Annotated[str | None, Header(alias=MTLS_VERIFY_HEADER)] = None,
    ) -> str | None:
        if not runtime_config.require_mtls_header:
            return request.headers.get(MTLS_IDENTITY_HEADER)
        if client_verify != "SUCCESS":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"category": "AUTHENTICATION_REQUIRED", "message": "mTLS is required."},
            )
        identity = request.headers.get(MTLS_IDENTITY_HEADER)
        if not identity:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "category": "AUTHENTICATION_REQUIRED",
                    "message": "An authenticated mTLS client identity is required.",
                },
            )
        return identity

    @app.get(f"{API_PREFIX}/health")
    def health(_identity: str | None = Depends(require_mtls)) -> JSONResponse:
        try:
            worker = store.worker_available(runtime_config.worker_heartbeat_ttl_seconds)
        except sqlite3.Error:
            worker = False
        checks = safe_runtime_checks(runtime_config, worker_available=worker)
        healthy = all(bool(value) for value in checks.values())
        return JSONResponse(
            status_code=status.HTTP_200_OK if healthy else status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"service": "asi-runtime", "healthy": healthy, **checks},
        )

    @app.get(f"{API_PREFIX}/status", response_model=RuntimeStatusResponse)
    def runtime_status(
        _identity: str | None = Depends(require_mtls),
    ) -> RuntimeStatusResponse:
        try:
            worker = store.worker_available(runtime_config.worker_heartbeat_ttl_seconds)
            counts = store.queue_counts()
            pending_reviews = store.pending_review_count()
            methodology, taxonomy, source_ledger = store.ledger_versions()
            last_successful = store.latest_successful()
            active = store.active_job()
            last_collection = store.latest_successful(JobType.COLLECT)
            last_daily = store.latest_successful(JobType.DAILY)
            last_weekly = store.latest_successful(JobType.WEEKLY_PACK)
            last_export = store.latest_successful(JobType.PUBLICATION_EXPORT)
        except sqlite3.Error:
            worker = False
            counts = {item: 0 for item in JobStatus}
            pending_reviews = 0
            methodology = None
            taxonomy = None
            source_ledger = None
            last_successful = None
            active = None
            last_collection = None
            last_daily = None
            last_weekly = None
            last_export = None
        checks = safe_runtime_checks(runtime_config, worker_available=worker)
        return RuntimeStatusResponse(
            service="asi-runtime",
            asi_version=__version__,
            **checks,
            methodology_version=methodology,
            taxonomy_version=taxonomy,
            source_ledger_version=source_ledger,
            queued_jobs=counts[JobStatus.QUEUED],
            running_jobs=counts[JobStatus.RUNNING],
            failed_jobs=counts[JobStatus.FAILED],
            pending_review_count=pending_reviews,
            last_successful_job=StatusJobSummary.from_job(last_successful),
            active_job=StatusJobSummary.from_job(active),
            last_collection=StatusJobSummary.from_job(last_collection),
            last_daily_output=StatusJobSummary.from_job(last_daily),
            last_weekly_output=StatusJobSummary.from_job(last_weekly),
            last_publication_export=StatusJobSummary.from_job(last_export),
        )

    @app.post(
        f"{API_PREFIX}/jobs",
        response_model=JobCreateResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    def create_job(
        payload: JobCreateRequest,
        identity: str | None = Depends(require_mtls),
    ) -> JobCreateResponse:
        try:
            disk_guard(runtime_config)
            requested_by = identity or payload.requested_by
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._:@/+=,-]*", requested_by) is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={
                        "category": "INVALID_REQUESTER",
                        "message": "The requester identity is invalid.",
                    },
                )
            job, replay = store.enqueue(
                payload.job_type,
                requested_by=requested_by[:200],
                idempotency_key=payload.idempotency_key,
            )
        except RuntimeError as exc:
            if str(exc) == "DISK_GUARD":
                raise HTTPException(
                    status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
                    detail={
                        "category": "DISK_GUARD",
                        "message": "Insufficient free disk space for a new job.",
                    },
                ) from exc
            raise
        except IdempotencyConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "category": "IDEMPOTENCY_CONFLICT",
                    "message": "The idempotency key belongs to a different request.",
                },
            ) from exc
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "category": "LEDGER_UNAVAILABLE",
                    "message": "The runtime ledger is unavailable.",
                },
            ) from exc
        return JobCreateResponse(job=job, idempotent_replay=replay)

    @app.get(f"{API_PREFIX}/jobs/{{job_id}}", response_model=JobRecord)
    def get_job(
        job_id: str,
        _identity: str | None = Depends(require_mtls),
    ) -> JobRecord:
        try:
            job = store.get(job_id)
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "category": "LEDGER_UNAVAILABLE",
                    "message": "The runtime ledger is unavailable.",
                },
            ) from exc
        if job is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
        return job

    @app.get(f"{API_PREFIX}/jobs", response_model=tuple[JobRecord, ...])
    def list_jobs(
        _identity: str | None = Depends(require_mtls),
        job_status: Annotated[JobStatus | None, Query(alias="status")] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
    ) -> tuple[JobRecord, ...]:
        try:
            return store.list(status=job_status, limit=limit)
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "category": "LEDGER_UNAVAILABLE",
                    "message": "The runtime ledger is unavailable.",
                },
            ) from exc

    @app.get(f"{API_PREFIX}/review/pending", response_model=tuple[ReviewPendingItem, ...])
    def pending_review(
        _identity: str | None = Depends(require_mtls),
        limit: Annotated[int, Query(ge=1, le=100)] = 100,
    ) -> tuple[ReviewPendingItem, ...]:
        try:
            return tuple(
                ReviewPendingItem.model_validate(item)
                for item in store.pending_reviews(limit=limit)
            )
        except sqlite3.Error as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "category": "LEDGER_UNAVAILABLE",
                    "message": "The runtime ledger is unavailable.",
                },
            ) from exc

    return app


def main() -> None:
    config = load_runtime_config()
    uvicorn.run(
        create_app(config),
        host="127.0.0.1",
        port=8787,
        access_log=False,
        server_header=False,
    )
