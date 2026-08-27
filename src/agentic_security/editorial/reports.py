"""Deterministic daily brief and weekly evidence-pack generation."""

from collections.abc import Iterable, Mapping
from datetime import date

from agentic_security.models import (
    ChangeReviewItem,
    ContradictionFlag,
    DailyBrief,
    DailyStatus,
    Freshness,
    MaterialChange,
    ReviewStatus,
    StructuredDiff,
    WeeklyEvidencePack,
)


def build_daily_brief(
    day: date,
    changes: Iterable[MaterialChange],
    candidates: Iterable[StructuredDiff] = (),
    reviews: Iterable[ChangeReviewItem] = (),
    *,
    reviewed_content_available: bool = True,
) -> DailyBrief:
    confirmed = tuple(item for item in changes if item.human_confirmed)
    surviving = tuple(item for item in candidates if item.material_candidate)
    completed_candidate_ids = {
        item.candidate_id for item in reviews if item.status is not ReviewStatus.PENDING
    }
    if confirmed:
        status = DailyStatus.MATERIAL_CHANGES
    elif surviving and any(item.id not in completed_candidate_ids for item in surviving):
        status = DailyStatus.REVIEW_PENDING
    elif surviving:
        status = DailyStatus.NO_CONFIRMED_MATERIAL_CHANGE
    elif not reviewed_content_available:
        status = DailyStatus.NO_REVIEWED_CONTENT
    else:
        status = DailyStatus.NO_MATERIAL_CHANGE
    lines = [
        f"# Agentic Security Change Brief — {day.isoformat()}",
        "",
        "## Material Changes",
    ]
    if status is DailyStatus.NO_REVIEWED_CONTENT:
        lines.extend(
            [
                "",
                "## No Reviewed Content",
                "",
                "The initialized ledger contains no reviewed systems or change candidates. "
                "This is not an observation that tracked systems remained unchanged.",
            ]
        )
    elif status is DailyStatus.NO_MATERIAL_CHANGE:
        lines.extend(
            [
                "",
                "## No Material Change",
                "",
                "No material capability or control change observed.",
            ]
        )
    elif status is DailyStatus.NO_CONFIRMED_MATERIAL_CHANGE:
        lines.extend(
            [
                "",
                "## No Confirmed Material Change",
                "",
                "Candidates were reviewed; none were confirmed as material.",
            ]
        )
    elif status is DailyStatus.REVIEW_PENDING:
        lines.extend(
            [
                "",
                "## Review Pending",
                "",
                "Surviving change candidates await completed human review.",
            ]
        )
    else:
        for change in confirmed:
            impacts = ", ".join(sorted(item.value for item in change.decision_impacts))
            lines.extend(
                [
                    "",
                    f"### {change.description}",
                    f"- Decision impact: {impacts}",
                    f"- Assertions: {', '.join(change.assertion_ids)}",
                ]
            )
    lines.extend(
        [
            "",
            "## Control/Autonomy Changes",
            "",
            "## Availability & Lifecycle Changes",
            "",
            "## Capability Changes",
            "",
            "## Research & Benchmark Changes",
            "",
            "## Evidence Conflicts",
            "",
            "## Why It Matters",
            "",
            "## Sources",
        ]
    )
    return DailyBrief(
        date=day,
        markdown="\n".join(lines) + "\n",
        confirmed_change_ids=tuple(item.id for item in confirmed),
        status=status,
    )


def build_weekly_pack(
    week_ending: date,
    changes: Iterable[MaterialChange],
    conflicts: Iterable[ContradictionFlag],
    freshness: Mapping[str, Freshness],
    trend_results: Mapping[str, object],
    *,
    reviewed_content_available: bool = True,
) -> WeeklyEvidencePack:
    confirmed = tuple(item for item in changes if item.human_confirmed)
    open_conflicts = tuple(item for item in conflicts if item.status.value == "PENDING")
    alerts = tuple(
        assertion_id
        for assertion_id, value in freshness.items()
        if value in {Freshness.STALE, Freshness.REVALIDATION_REQUIRED}
    )
    lines = [
        f"# Weekly Evidence Pack — {week_ending.isoformat()}",
        "",
        "## Executive Summary",
        "",
        *(
            ()
            if reviewed_content_available
            else (
                "### No Reviewed Content",
                "",
                "The initialized ledger contains no reviewed systems or evidence-backed "
                "changes. No weekly change conclusion is implied.",
                "",
            )
        ),
        "## What Changed This Week",
        *[f"- {item.description}" for item in confirmed],
        "",
        "## Evidence Conflicts",
        *[f"- {item.id}: {item.rationale}" for item in open_conflicts],
        "",
        "## Freshness Alerts",
        *[f"- {item}" for item in alerts],
        "",
        "## Trend Primitives",
        *[f"- {name}: {value}" for name, value in sorted(trend_results.items())],
        "",
        "## Architecture/Control Pattern",
        "",
        "## Independent Perspective",
        "",
        "## What Remains Unknown",
        "",
        "## Implications",
        "",
        "## What to Watch Next",
        "",
        "## Methodology",
        "",
        "## Sources",
        "",
        "Interpretation sections remain human-authored.",
    ]
    return WeeklyEvidencePack(
        week_ending=week_ending,
        markdown="\n".join(lines) + "\n",
        confirmed_change_ids=tuple(item.id for item in confirmed),
        open_conflict_ids=tuple(item.id for item in open_conflicts),
        freshness_alert_assertion_ids=alerts,
    )
