"""Deterministic daily and weekly pipelines backed by the evidence ledger."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agentic_security.derivations import derive_freshness
from agentic_security.editorial.reports import build_daily_brief, build_weekly_pack
from agentic_security.fixtures import NOW, gate_a_packet
from agentic_security.pass2_fixtures import gate_b_fixture
from agentic_security.publishing.artifacts import (
    PullRequestArtifact,
    build_pull_request_artifact,
    write_pull_request_artifact,
)
from agentic_security.storage.read_models import (
    PublicationLedgerData,
    configured_database_path,
    read_publication_ledger,
)
from agentic_security.trend_primitives.queries import preview_to_ga_velocity


def _pipeline_data(database_path: Path | None, *, demo: bool) -> PublicationLedgerData:
    if demo and database_path is not None:
        raise ValueError("choose either database_path or demo mode, not both")
    if demo:
        packet = gate_a_packet()
        gate_b = gate_b_fixture()
        return PublicationLedgerData.from_packet(
            packet,
            conflicts=gate_b["conflicts"],
            candidates=gate_b["diffs"],
            latest_review_decisions=gate_b["reviews"],
        )
    return read_publication_ledger(database_path or configured_database_path())


def run_daily_pipeline(
    output_root: Path,
    *,
    dry_run: bool,
    database_path: Path | None = None,
    demo: bool = False,
) -> PullRequestArtifact:
    data = _pipeline_data(database_path, demo=demo)
    generated_at = NOW if demo else datetime.now(UTC)
    reviewed_content_available = bool(
        data.systems
        or data.assertions
        or data.candidates
        or data.confirmed_changes
        or data.latest_review_decisions
    )
    brief = build_daily_brief(
        generated_at.date(),
        data.confirmed_changes,
        data.candidates,
        data.latest_review_decisions,
        reviewed_content_available=reviewed_content_available,
    )
    report_path = output_root / "content" / "daily" / f"{generated_at.date().isoformat()}.md"
    if not dry_run:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(brief.markdown, encoding="utf-8")
    artifact = build_pull_request_artifact(
        (report_path,) if report_path.exists() else (),
        branch=f"agent/daily-{generated_at.date().isoformat()}",
        base_branch="publication",
        title=f"Daily change brief {generated_at.date().isoformat()}",
        body=(
            f"Status: {brief.status.value}\n\n"
            f"Generated from {'explicit demo data' if demo else 'the configured SQLite ledger'}. "
            "Human review and merge are required."
        ),
        generated_at=generated_at,
    )
    write_pull_request_artifact(
        artifact,
        output_root / "artifacts" / "daily-pr.json",
        dry_run=dry_run,
    )
    return artifact


def run_weekly_pipeline(
    output_root: Path,
    *,
    dry_run: bool,
    database_path: Path | None = None,
    demo: bool = False,
) -> PullRequestArtifact:
    data = _pipeline_data(database_path, demo=demo)
    generated_at = NOW if demo else datetime.now(UTC)
    reviewed_content_available = bool(
        data.systems or data.assertions or data.confirmed_changes or data.conflicts
    )
    freshness = {
        item.id: derive_freshness(item.last_verified_at, as_of=generated_at)
        for item in data.assertions
    }
    pack = build_weekly_pack(
        generated_at.date(),
        data.confirmed_changes,
        data.conflicts,
        freshness,
        {"preview_to_ga_days": preview_to_ga_velocity(data.lifecycle_events)},
        reviewed_content_available=reviewed_content_available,
    )
    report_path = output_root / "content" / "weekly" / f"{generated_at.date().isoformat()}.md"
    if not dry_run:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(pack.markdown, encoding="utf-8")
    artifact = build_pull_request_artifact(
        (report_path,) if report_path.exists() else (),
        branch=f"agent/weekly-{generated_at.date().isoformat()}",
        base_branch="publication",
        title=f"Weekly evidence pack {generated_at.date().isoformat()}",
        body="Ledger-derived evidence pack. Interpretation and merge remain human-controlled.",
        generated_at=generated_at,
    )
    write_pull_request_artifact(
        artifact,
        output_root / "artifacts" / "weekly-pr.json",
        dry_run=dry_run,
    )
    return artifact
