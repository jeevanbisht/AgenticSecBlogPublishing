"""Evidence-backed append-only lifecycle transition validation."""

from agentic_security.models import AvailabilityState, LifecycleEvent

_ALLOWED: dict[AvailabilityState, frozenset[AvailabilityState]] = {
    AvailabilityState.UNKNOWN: frozenset(AvailabilityState),
    AvailabilityState.PRIVATE_PREVIEW: frozenset(
        {
            AvailabilityState.LIMITED_PUBLIC_PREVIEW,
            AvailabilityState.PUBLIC_PREVIEW,
            AvailabilityState.GA,
            AvailabilityState.DEPRECATED,
        }
    ),
    AvailabilityState.LIMITED_PUBLIC_PREVIEW: frozenset(
        {
            AvailabilityState.PUBLIC_PREVIEW,
            AvailabilityState.GA,
            AvailabilityState.DEPRECATED,
        }
    ),
    AvailabilityState.PUBLIC_PREVIEW: frozenset(
        {
            AvailabilityState.GA,
            AvailabilityState.DEPRECATED,
        }
    ),
    AvailabilityState.GA: frozenset({AvailabilityState.DEPRECATED}),
    AvailabilityState.DEPRECATED: frozenset(),
}


def validate_transition(history: list[LifecycleEvent], event: LifecycleEvent) -> None:
    if history:
        previous = history[-1]
        if previous.entity_type != event.entity_type or previous.entity_id != event.entity_id:
            raise ValueError("lifecycle history contains a different entity")
        if event.state not in _ALLOWED[previous.state]:
            raise ValueError(f"invalid lifecycle transition {previous.state} -> {event.state}")
        if event.retrieved_at < previous.retrieved_at:
            raise ValueError("lifecycle history must be append-only by retrieval time")


def append_event(
    history: list[LifecycleEvent], event: LifecycleEvent
) -> tuple[LifecycleEvent, ...]:
    validate_transition(history, event)
    history.append(event)
    return tuple(history)
