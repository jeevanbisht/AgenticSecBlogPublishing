"""Assertion creation and paraphrase-safe observation attachment."""

from dataclasses import dataclass
from datetime import datetime

from agentic_security.assertions.identity import assertion_key
from agentic_security.derivations import derive_current_scope
from agentic_security.models import (
    Assertion,
    AssertionId,
    AssertionScope,
    AssertionSlots,
    AssertionState,
    EvidenceId,
    MethodologyId,
    Observation,
    ObservationId,
    SupportConfidence,
    TaxonomyId,
)


@dataclass(frozen=True)
class UpsertResult:
    assertion: Assertion
    observation: Observation
    created: bool


class AssertionLedger:
    """In-memory Pass 1 service; persistent repositories expose the same semantics."""

    def __init__(self) -> None:
        self._by_key: dict[str, Assertion] = {}
        self.observations: list[Observation] = []

    def current_scope(self, assertion_id: str) -> AssertionScope:
        """Derive scope from the latest accepted observation."""
        return derive_current_scope(assertion_id, self.observations)

    def upsert(
        self,
        *,
        assertion_id: AssertionId,
        observation_id: ObservationId,
        slots: AssertionSlots,
        statement: str,
        canonical_rendering: str,
        scope: AssertionScope,
        state: AssertionState,
        confidence: SupportConfidence,
        confidence_rationale: str,
        evidence_id: EvidenceId,
        observed_at: datetime,
        methodology_version: MethodologyId,
        taxonomy_version: TaxonomyId,
    ) -> UpsertResult:
        key = assertion_key(slots)
        if state is AssertionState.CONDITIONAL and not scope.conditions:
            raise ValueError("CONDITIONAL assertions require accepted observation scope.conditions")
        existing = self._by_key.get(key)
        observation = Observation(
            id=observation_id,
            assertion_id=existing.id if existing else assertion_id,
            evidence_id=evidence_id,
            observed_statement=statement,
            observed_at=observed_at,
            first_seen_at=observed_at,
            retrieved_at=observed_at,
            last_seen_at=observed_at,
            last_verified_at=observed_at,
            is_paraphrase=existing is not None and existing.statement != statement,
            scope=scope,
        )
        self.observations.append(observation)
        if existing:
            evidence_ids = tuple(dict.fromkeys((*existing.evidence_ids, evidence_id)))
            updated = existing.model_copy(
                update={"last_verified_at": observed_at, "evidence_ids": evidence_ids}
            )
            self._by_key[key] = updated
            return UpsertResult(updated, observation, False)
        assertion = Assertion(
            id=assertion_id,
            assertion_key=key,
            taxonomy_version=taxonomy_version,
            system_id=slots.system,
            agent_id=slots.agent,
            slots=slots,
            statement=statement,
            canonical_rendering=canonical_rendering,
            state=state,
            support_confidence=confidence,
            support_confidence_rationale=confidence_rationale,
            first_seen_at=observed_at,
            retrieved_at=observed_at,
            last_seen_at=observed_at,
            first_observed_at=observed_at,
            last_verified_at=observed_at,
            methodology_version=methodology_version,
            evidence_ids=(evidence_id,),
        )
        self._by_key[key] = assertion
        return UpsertResult(assertion, observation, True)
