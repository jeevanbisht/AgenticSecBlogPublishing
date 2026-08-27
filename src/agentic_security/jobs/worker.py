"""Separate-process durable job worker."""

from __future__ import annotations

import argparse
import sqlite3
import threading
import time
import uuid
from datetime import UTC, datetime
from types import TracebackType

from agentic_security.jobs.executor import JobExecutionError, RuntimeJobExecutor
from agentic_security.jobs.lock import LocalPipelineLock
from agentic_security.jobs.models import FailureCategory, JobStatus
from agentic_security.jobs.store import JobStore
from agentic_security.runtime import RuntimeConfig, load_runtime_config
from agentic_security.storage.database import Database


class HeartbeatUpdater:
    def __init__(
        self,
        store: JobStore,
        *,
        worker_id: str,
        started_at: datetime,
        interval_seconds: float,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("heartbeat interval must be positive")
        self.store = store
        self.worker_id = worker_id
        self.started_at = started_at
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"asi-heartbeat-{worker_id}",
            daemon=True,
        )

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.store.heartbeat(self.worker_id, started_at=self.started_at)
            except sqlite3.Error:
                continue

    def __enter__(self) -> HeartbeatUpdater:
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._thread.join()


class Worker:
    def __init__(
        self,
        config: RuntimeConfig,
        *,
        worker_id: str | None = None,
        heartbeat_interval_seconds: float | None = None,
    ) -> None:
        self.config = config
        self.worker_id = worker_id or str(uuid.uuid4())
        self.started_at = datetime.now(UTC)
        self.heartbeat_interval_seconds = (
            max(1.0, config.worker_heartbeat_ttl_seconds / 3)
            if heartbeat_interval_seconds is None
            else heartbeat_interval_seconds
        )
        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat interval must be positive")
        self.store = JobStore(config.database_path)
        self.executor = RuntimeJobExecutor(config)
        self.pipeline_lock = LocalPipelineLock(config.locks_path / "pipeline.lock")

    def run_once(self) -> bool:
        self.store.heartbeat(self.worker_id, started_at=self.started_at)
        with self.pipeline_lock.acquire() as acquired:
            if not acquired:
                return False
            self.store.recover_interrupted(max_retries=self.config.max_restart_retries)
            job = self.store.claim_next(lease_seconds=self.config.pipeline_lease_seconds)
            if job is None:
                return False
            try:
                with HeartbeatUpdater(
                    self.store,
                    worker_id=self.worker_id,
                    started_at=self.started_at,
                    interval_seconds=self.heartbeat_interval_seconds,
                ):
                    self.executor.execute(job)
            except JobExecutionError as exc:
                self.store.finish(
                    job.job_id,
                    status=JobStatus.FAILED,
                    failure_category=exc.category,
                    sanitized_failure_message=exc.safe_message,
                )
            except Exception:
                self.store.finish(
                    job.job_id,
                    status=JobStatus.FAILED,
                    failure_category=FailureCategory.INTERNAL_ERROR,
                    sanitized_failure_message=(
                        "The job failed unexpectedly; inspect private service logs."
                    ),
                )
            else:
                self.store.finish(job.job_id, status=JobStatus.SUCCEEDED)
            return True

    def run_forever(self, *, poll_seconds: float = 2.0) -> None:
        while True:
            worked = self.run_once()
            if not worked:
                time.sleep(poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the ASI durable job worker.")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()
    config = load_runtime_config()
    if not config.database_path.is_file():
        raise SystemExit("The configured ASI ledger does not exist.")
    Database(config.database_path).initialize()
    worker = Worker(config)
    if args.once:
        worker.run_once()
        return
    try:
        worker.run_forever(poll_seconds=max(0.1, args.poll_seconds))
    except KeyboardInterrupt:
        return
