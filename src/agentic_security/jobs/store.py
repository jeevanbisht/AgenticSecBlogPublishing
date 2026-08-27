"""Transactional SQLite persistence, restart recovery, and the pipeline lease."""

from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agentic_security.jobs.models import FailureCategory, JobRecord, JobStatus, JobType
from agentic_security.storage.database import Database

PIPELINE_LEASE = "mutating-pipeline"


class IdempotencyConflictError(ValueError):
    """An idempotency key was reused for a different effective request."""


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat(timespec="microseconds")


def _record(row: sqlite3.Row) -> JobRecord:
    return JobRecord.model_validate(dict(row))


def _validate_idempotent_replay(
    job: JobRecord,
    *,
    job_type: JobType,
    requested_by: str,
) -> JobRecord:
    if job.job_type is not job_type or job.requested_by != requested_by:
        raise IdempotencyConflictError(
            "idempotency key conflicts with the original effective request"
        )
    return job


class JobStore:
    def __init__(self, database_path: Path | str) -> None:
        self.database = Database(database_path)

    def enqueue(
        self,
        job_type: JobType,
        *,
        requested_by: str,
        idempotency_key: str,
    ) -> tuple[JobRecord, bool]:
        created_at = _now()
        with self.database.transaction(immediate=True) as connection:
            existing = connection.execute(
                "SELECT * FROM jobs WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                return (
                    _validate_idempotent_replay(
                        _record(existing),
                        job_type=job_type,
                        requested_by=requested_by,
                    ),
                    True,
                )
            job_id = str(uuid.uuid4())
            try:
                connection.execute(
                    """INSERT INTO jobs(
                           job_id,job_type,requested_by,idempotency_key,created_at,queued_at,
                           updated_at,status,retry_count
                       ) VALUES (?,?,?,?,?,?,?,?,0)""",
                    (
                        job_id,
                        job_type.value,
                        requested_by,
                        idempotency_key,
                        _iso(created_at),
                        _iso(created_at),
                        _iso(created_at),
                        JobStatus.QUEUED.value,
                    ),
                )
            except sqlite3.IntegrityError:
                replay = connection.execute(
                    "SELECT * FROM jobs WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                if replay is None:
                    raise
                return (
                    _validate_idempotent_replay(
                        _record(replay),
                        job_type=job_type,
                        requested_by=requested_by,
                    ),
                    True,
                )
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            assert row is not None
            return _record(row), False

    def get(self, job_id: str) -> JobRecord | None:
        with closing(self.database.connect()) as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return _record(row) if row is not None else None

    def list(
        self,
        *,
        status: JobStatus | None = None,
        limit: int = 100,
    ) -> tuple[JobRecord, ...]:
        with closing(self.database.connect()) as connection:
            if status is None:
                rows = connection.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC,job_id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            else:
                rows = connection.execute(
                    """SELECT * FROM jobs WHERE status=?
                       ORDER BY created_at DESC,job_id DESC LIMIT ?""",
                    (status.value, limit),
                ).fetchall()
        return tuple(_record(row) for row in rows)

    def queue_counts(self) -> dict[JobStatus, int]:
        counts = {status: 0 for status in JobStatus}
        with closing(self.database.connect()) as connection:
            rows = connection.execute(
                "SELECT status,COUNT(*) AS count FROM jobs GROUP BY status"
            ).fetchall()
        for row in rows:
            counts[JobStatus(str(row["status"]))] = int(row["count"])
        return counts

    def latest_successful(self, job_type: JobType | None = None) -> JobRecord | None:
        with closing(self.database.connect()) as connection:
            if job_type is None:
                row = connection.execute(
                    """SELECT * FROM jobs WHERE status=?
                       ORDER BY finished_at DESC,job_id DESC LIMIT 1""",
                    (JobStatus.SUCCEEDED.value,),
                ).fetchone()
            else:
                row = connection.execute(
                    """SELECT * FROM jobs WHERE status=? AND job_type=?
                       ORDER BY finished_at DESC,job_id DESC LIMIT 1""",
                    (JobStatus.SUCCEEDED.value, job_type.value),
                ).fetchone()
        return _record(row) if row is not None else None

    def active_job(self) -> JobRecord | None:
        with closing(self.database.connect()) as connection:
            row = connection.execute(
                """SELECT * FROM jobs WHERE status=?
                   ORDER BY started_at,job_id LIMIT 1""",
                (JobStatus.RUNNING.value,),
            ).fetchone()
        return _record(row) if row is not None else None

    def ledger_versions(self) -> tuple[str | None, str | None, str]:
        with closing(self.database.connect()) as connection:
            methodology = connection.execute(
                "SELECT id FROM methodology_versions ORDER BY published_at DESC,id DESC LIMIT 1"
            ).fetchone()
            taxonomy = connection.execute(
                "SELECT id FROM taxonomy_versions ORDER BY published_at DESC,id DESC LIMIT 1"
            ).fetchone()
            schema_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        return (
            str(methodology[0]) if methodology is not None else None,
            str(taxonomy[0]) if taxonomy is not None else None,
            f"sqlite-schema-{schema_version}",
        )

    def heartbeat(self, worker_id: str, *, started_at: datetime) -> None:
        heartbeat_at = _now()
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """INSERT INTO worker_heartbeats(worker_id,started_at,heartbeat_at)
                   VALUES (?,?,?)
                   ON CONFLICT(worker_id) DO UPDATE SET heartbeat_at=excluded.heartbeat_at""",
                (worker_id, _iso(started_at), _iso(heartbeat_at)),
            )

    def worker_available(self, ttl_seconds: float) -> bool:
        threshold = _iso(_now() - timedelta(seconds=ttl_seconds))
        with closing(self.database.connect()) as connection:
            row = connection.execute(
                "SELECT 1 FROM worker_heartbeats WHERE heartbeat_at>=? LIMIT 1",
                (threshold,),
            ).fetchone()
        return row is not None

    def pending_review_count(self) -> int:
        with closing(self.database.connect()) as connection:
            row = connection.execute(
                """SELECT COUNT(*)
                   FROM change_review_queue current
                   WHERE current.status='PENDING'
                     AND NOT EXISTS (
                       SELECT 1 FROM change_review_queue newer
                       WHERE newer.prior_review_id=current.id
                     )"""
            ).fetchone()
        assert row is not None
        return int(row[0])

    def recover_interrupted(self, *, max_retries: int) -> int:
        recovered = 0
        current = _now()
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                "DELETE FROM pipeline_leases WHERE expires_at<=?",
                (_iso(current),),
            )
            active = connection.execute(
                "SELECT holder_id FROM pipeline_leases WHERE name=?",
                (PIPELINE_LEASE,),
            ).fetchone()
            active_job = str(active["holder_id"]) if active is not None else None
            rows = connection.execute(
                "SELECT job_id,retry_count FROM jobs WHERE status=?",
                (JobStatus.RUNNING.value,),
            ).fetchall()
            for row in rows:
                job_id = str(row["job_id"])
                if job_id == active_job:
                    continue
                retry_count = int(row["retry_count"])
                if retry_count < max_retries:
                    connection.execute(
                        """UPDATE jobs
                           SET status=?,started_at=NULL,queued_at=?,updated_at=?,
                               retry_count=retry_count+1,failure_category=NULL,
                               sanitized_failure_message=NULL
                           WHERE job_id=? AND status=?""",
                        (
                            JobStatus.QUEUED.value,
                            _iso(current),
                            _iso(current),
                            job_id,
                            JobStatus.RUNNING.value,
                        ),
                    )
                else:
                    connection.execute(
                        """UPDATE jobs
                           SET status=?,finished_at=?,updated_at=?,failure_category=?,
                               sanitized_failure_message=?
                           WHERE job_id=? AND status=?""",
                        (
                            JobStatus.FAILED.value,
                            _iso(current),
                            _iso(current),
                            FailureCategory.INTERRUPTED.value,
                            "The worker stopped before the job completed.",
                            job_id,
                            JobStatus.RUNNING.value,
                        ),
                    )
                recovered += 1
        return recovered

    def claim_next(self, *, lease_seconds: int) -> JobRecord | None:
        current = _now()
        expires_at = current + timedelta(seconds=lease_seconds)
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                "DELETE FROM pipeline_leases WHERE expires_at<=?",
                (_iso(current),),
            )
            active = connection.execute(
                "SELECT 1 FROM pipeline_leases WHERE name=?",
                (PIPELINE_LEASE,),
            ).fetchone()
            if active is not None:
                return None
            row = connection.execute(
                """SELECT * FROM jobs WHERE status=?
                   ORDER BY queued_at,created_at,job_id LIMIT 1""",
                (JobStatus.QUEUED.value,),
            ).fetchone()
            if row is None:
                return None
            job_id = str(row["job_id"])
            connection.execute(
                """INSERT INTO pipeline_leases(name,holder_id,acquired_at,expires_at)
                   VALUES (?,?,?,?)""",
                (PIPELINE_LEASE, job_id, _iso(current), _iso(expires_at)),
            )
            connection.execute(
                """UPDATE jobs SET status=?,started_at=?,updated_at=?
                   WHERE job_id=? AND status=?""",
                (
                    JobStatus.RUNNING.value,
                    _iso(current),
                    _iso(current),
                    job_id,
                    JobStatus.QUEUED.value,
                ),
            )
            claimed = connection.execute(
                "SELECT * FROM jobs WHERE job_id=?",
                (job_id,),
            ).fetchone()
            assert claimed is not None
            return _record(claimed)

    def finish(
        self,
        job_id: str,
        *,
        status: JobStatus,
        failure_category: FailureCategory | None = None,
        sanitized_failure_message: str | None = None,
    ) -> JobRecord:
        if status not in {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELLED}:
            raise ValueError("finish requires a terminal job status")
        finished_at = _now()
        with self.database.transaction(immediate=True) as connection:
            cursor = connection.execute(
                """UPDATE jobs
                   SET status=?,finished_at=?,updated_at=?,failure_category=?,
                       sanitized_failure_message=?
                   WHERE job_id=? AND status=?""",
                (
                    status.value,
                    _iso(finished_at),
                    _iso(finished_at),
                    failure_category.value if failure_category else None,
                    sanitized_failure_message,
                    job_id,
                    JobStatus.RUNNING.value,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("job is not running")
            connection.execute(
                "DELETE FROM pipeline_leases WHERE name=? AND holder_id=?",
                (PIPELINE_LEASE, job_id),
            )
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            assert row is not None
            return _record(row)

    def pending_reviews(self, *, limit: int = 100) -> tuple[dict[str, Any], ...]:
        with closing(self.database.connect()) as connection:
            rows = connection.execute(
                """SELECT current.id,current.candidate_id,current.machine_classification,
                          current.evidence_status_subtype,
                          current.machine_decision_impacts_json,current.status
                   FROM change_review_queue current
                   WHERE current.status='PENDING'
                     AND NOT EXISTS (
                       SELECT 1 FROM change_review_queue newer
                       WHERE newer.prior_review_id=current.id
                     )
                   ORDER BY current.rowid LIMIT ?""",
                (limit,),
            ).fetchall()
        return tuple(
            {
                "review_id": str(row["id"]),
                "candidate_id": str(row["candidate_id"]),
                "machine_classification": str(row["machine_classification"]),
                "evidence_status_subtype": (
                    str(row["evidence_status_subtype"])
                    if row["evidence_status_subtype"] is not None
                    else None
                ),
                "decision_impacts": tuple(
                    str(item) for item in json.loads(str(row["machine_decision_impacts_json"]))
                ),
                "status": str(row["status"]),
            }
            for row in rows
        )
