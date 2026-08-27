"""Pure deterministic trend primitives; these do not narrate trends."""

from collections import Counter
from collections.abc import Iterable
from datetime import date

from agentic_security.models import Agent, AvailabilityState, LifecycleEvent, MaterialChange


def preview_to_ga_velocity(events: Iterable[LifecycleEvent]) -> dict[str, int]:
    by_system: dict[str, list[LifecycleEvent]] = {}
    for event in events:
        if event.system_id:
            by_system.setdefault(event.system_id, []).append(event)
    result: dict[str, int] = {}
    for system_id, history in by_system.items():
        previews = [
            item
            for item in history
            if item.state
            in {
                AvailabilityState.PRIVATE_PREVIEW,
                AvailabilityState.LIMITED_PUBLIC_PREVIEW,
                AvailabilityState.PUBLIC_PREVIEW,
            }
            and item.effective_at
        ]
        ga = [item for item in history if item.state is AvailabilityState.GA and item.effective_at]
        if previews and ga:
            result[system_id] = (ga[-1].effective_at - previews[0].effective_at).days  # type: ignore[operator]
    return result


def new_agents_by_month(agents: Iterable[Agent]) -> dict[str, int]:
    counts = Counter(item.first_observed_at.strftime("%Y-%m") for item in agents)
    return dict(sorted(counts.items()))


def decision_impact_frequency(changes: Iterable[MaterialChange]) -> dict[str, int]:
    counts = Counter(
        impact.value
        for change in changes
        if change.human_confirmed
        for impact in change.decision_impacts
    )
    return dict(sorted(counts.items()))


def observed_on_or_before(value: date, cutoff: date) -> bool:
    return value <= cutoff
