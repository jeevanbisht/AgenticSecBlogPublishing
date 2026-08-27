"""Hardened snapshot and git anchor validation."""

from agentic_security.models import (
    Evidence,
    EvidenceMaturity,
    Snapshot,
    Source,
    SourceClass,
    SourceRole,
    TrustClass,
)
from agentic_security.normalization import content_sha256


def validate_evidence_anchor(evidence: Evidence, snapshot: Snapshot) -> None:
    anchor = evidence.anchor
    if anchor.snapshot_id != snapshot.id:
        raise ValueError("anchor snapshot_id mismatch")
    actual_hash = content_sha256(snapshot.normalized_text)
    if snapshot.sha256 != actual_hash or anchor.snapshot_sha256 != actual_hash:
        raise ValueError("snapshot hash mismatch")
    if anchor.normalizer_version != snapshot.normalizer_version:
        raise ValueError("normalizer version mismatch")
    if anchor.end_offset > len(snapshot.normalized_text):
        raise ValueError("anchor offset exceeds snapshot")
    if snapshot.normalized_text[anchor.start_offset : anchor.end_offset] != anchor.quote:
        raise ValueError("quote does not resolve at stated offsets")
    anchor_git_fields = (
        anchor.repository,
        anchor.commit_sha,
        anchor.file_path,
        anchor.line_start,
        anchor.line_end,
    )
    if snapshot.repository is not None:
        if any(value is None for value in anchor_git_fields):
            raise ValueError("repository-backed snapshot requires complete git anchor provenance")
        if (
            anchor.repository != snapshot.repository
            or anchor.commit_sha != snapshot.commit_sha
            or anchor.file_path != snapshot.file_path
        ):
            raise ValueError("git anchor provenance mismatch")
        lines = snapshot.normalized_text.splitlines()
        assert anchor.line_start is not None and anchor.line_end is not None
        line_quote = "\n".join(lines[anchor.line_start - 1 : anchor.line_end])
        if line_quote != anchor.quote:
            raise ValueError("git line anchor does not resolve")
    elif any(value is not None for value in anchor_git_fields):
        raise ValueError("git anchor provenance mismatch")


def validate_evidence_classification(evidence: Evidence) -> None:
    if (
        evidence.independence_facets
        and evidence.independence_facets.commercial_relationship.value == "VENDOR_SELF"
        and evidence.maturity in {EvidenceMaturity.E4, EvidenceMaturity.E5}
    ):
        raise ValueError("vendor-self evidence cannot be E4/E5")
    if evidence.derivative_of_evidence_id and evidence.maturity not in {
        EvidenceMaturity.E0,
        EvidenceMaturity.E1,
    }:
        raise ValueError("derivative evidence cannot raise maturity above E1")
    if evidence.source_class is SourceClass.S1 and evidence.maturity not in {
        EvidenceMaturity.E0,
        EvidenceMaturity.E1,
    }:
        raise ValueError("secondary reporting cannot exceed E1")


def validate_evidence_purpose(evidence: Evidence, source: Source) -> None:
    if source.role is SourceRole.OUTPUT or source.trust_class is TrustClass.SELF:
        raise ValueError(f"{source.id} is SELF/OUTPUT and cannot contribute evidence")
    policy = source.policy
    if evidence.claim_purpose in policy.prohibited_claim_purposes:
        raise ValueError(f"{evidence.claim_purpose.value} is prohibited for {source.id}")
    if evidence.claim_purpose not in policy.allowed_claim_purposes:
        raise ValueError(f"{evidence.claim_purpose.value} is not allowed for {source.id}")
