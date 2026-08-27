"""Allowlisted job-to-application-service wiring."""

from __future__ import annotations

from pathlib import Path

from agentic_security.collection.service import LiveCollectionError, LiveCollectionService
from agentic_security.jobs.models import FailureCategory, JobRecord, JobType
from agentic_security.pipelines import run_daily_pipeline, run_weekly_pipeline
from agentic_security.publishing.github import GitHubDraftPublisher, PublicationError
from agentic_security.publishing.projection import PublicationProjectionService
from agentic_security.runtime import RuntimeConfig, disk_guard


class JobExecutionError(RuntimeError):
    def __init__(self, category: FailureCategory, safe_message: str) -> None:
        super().__init__(safe_message)
        self.category = category
        self.safe_message = safe_message


class RuntimeJobExecutor:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def execute(self, job: JobRecord) -> None:
        try:
            disk_guard(self.config)
            self._execute_allowlisted(job.job_type, job_root=self._job_root(job))
        except LiveCollectionError as exc:
            raise JobExecutionError(exc.category, exc.safe_message) from exc
        except PublicationError as exc:
            raise JobExecutionError(exc.category, exc.safe_message) from exc
        except FileNotFoundError as exc:
            raise JobExecutionError(
                FailureCategory.LEDGER_UNAVAILABLE,
                "The configured ledger is unavailable.",
            ) from exc
        except ValueError as exc:
            raise JobExecutionError(
                FailureCategory.PUBLICATION_VALIDATION_FAILED,
                "The job input failed repository validation.",
            ) from exc
        except RuntimeError as exc:
            if str(exc) == "DISK_GUARD":
                raise JobExecutionError(
                    FailureCategory.DISK_GUARD,
                    "Insufficient free disk space for the job.",
                ) from exc
            raise

    def _job_root(self, job: JobRecord) -> Path:
        return self.config.generated_path / job.job_id

    def _execute_allowlisted(self, job_type: JobType, *, job_root: Path) -> None:
        if job_type is JobType.COLLECT:
            LiveCollectionService(self.config).collect()
            return
        if job_type is JobType.RESEARCH:
            raise JobExecutionError(
                FailureCategory.PROVIDER_UNAVAILABLE,
                "A production research provider is not configured.",
            )
        if job_type is JobType.DAILY:
            run_daily_pipeline(
                job_root,
                dry_run=False,
                database_path=self.config.database_path,
            )
            return
        if job_type is JobType.WEEKLY_PACK:
            run_weekly_pipeline(
                job_root,
                dry_run=False,
                database_path=self.config.database_path,
            )
            return
        if job_type is JobType.PUBLICATION_EXPORT:
            PublicationProjectionService(self.config).export()
            return
        if job_type is JobType.PUBLICATION_PR:
            GitHubDraftPublisher(self.config).publish(self.config.export_path)
            return
        raise JobExecutionError(
            FailureCategory.CONFIGURATION_UNAVAILABLE,
            "The requested job type is not implemented.",
        )
