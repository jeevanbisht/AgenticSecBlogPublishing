"""Versioned controlled-vocabulary loading and governance."""

from pathlib import Path
from typing import Any

import yaml

from agentic_security.models import TaxonomyMapping, TaxonomyTerm, TaxonomyVersion


def load_taxonomy(path: Path) -> TaxonomyVersion:
    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    vocabularies = {
        name: tuple(TaxonomyTerm.model_validate(item) for item in terms)
        for name, terms in raw["vocabularies"].items()
    }
    mappings = tuple(TaxonomyMapping.model_validate(item) for item in raw.get("mappings", []))
    return TaxonomyVersion(
        id=raw["taxonomy_version"],
        published_at=raw["published_at"],
        previous_version=raw.get("previous_version"),
        mappings=mappings,
        vocabularies=vocabularies,
        reserved_agent_ids=tuple(raw.get("reserved_agent_ids", ())),
        gate_category_reuse=raw.get("gate_category_reuse"),
    )


def validate_term(taxonomy: TaxonomyVersion, vocabulary: str, term: str) -> None:
    if vocabulary not in taxonomy.vocabularies:
        raise ValueError(f"unknown vocabulary: {vocabulary}")
    if term not in {entry.key for entry in taxonomy.vocabularies[vocabulary]}:
        raise ValueError(f"term {term!r} is not approved in {taxonomy.id}")


def propose_term(vocabulary: str, term: str, rationale: str) -> dict[str, str]:
    """Create a review-queue payload; research code cannot mutate taxonomy."""
    return {
        "type": "PROPOSED_TAXONOMY_TERM",
        "vocabulary": vocabulary,
        "term": term,
        "rationale": rationale,
        "human_review_required": "true",
    }
