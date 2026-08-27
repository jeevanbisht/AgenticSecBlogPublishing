"""Source trust boundary and URL policy."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from urllib.parse import SplitResult, urlsplit, urlunsplit

import yaml

from agentic_security.models import ClaimPurpose, Source, SourceRole, SubjectType, TrustClass


def canonicalize_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("only absolute HTTP(S) URLs are supported")
    host = parts.hostname.lower()
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise ValueError(f"prohibited host: {host!r}")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise ValueError(f"prohibited non-public address: {host!r}")
    port = parts.port
    netloc = host if port is None else f"{host}:{port}"
    path = parts.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit(SplitResult(parts.scheme.lower(), netloc, path, parts.query, ""))


class SourceRegistry:
    def __init__(self, sources: tuple[Source, ...]) -> None:
        self.sources = sources
        self._by_id = {source.id: source for source in sources}

    @classmethod
    def from_yaml(
        cls,
        path: Path,
        *,
        publication_base_url: str | None = None,
    ) -> SourceRegistry:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if publication_base_url is not None:
            canonical = canonicalize_url(publication_base_url)
            host = urlsplit(canonical).hostname
            assert host is not None
            output_urls = {
                "SRC-ASI-PUBLICATION-SITE": canonical,
                "SRC-ASI-PUBLICATION-RSS": f"{canonical.rstrip('/')}/rss.xml",
                "SRC-ASI-PUBLICATION-ATOM": f"{canonical.rstrip('/')}/atom.xml",
            }
            for item in raw["sources"]:
                if item["id"] in output_urls:
                    item["base_url"] = output_urls[item["id"]]
                    item["domains"] = [host]
        return cls(tuple(Source.model_validate(item) for item in raw["sources"]))

    def get(self, source_id: str) -> Source:
        try:
            return self._by_id[source_id]
        except KeyError as exc:
            raise ValueError(f"unknown source: {source_id}") from exc

    def validate_url(self, source_id: str, url: str) -> str:
        source = self.get(source_id)
        if not source.enabled:
            raise ValueError(f"source {source_id} is disabled")
        if source.role is SourceRole.OUTPUT:
            raise ValueError(f"source {source_id} is publication output and cannot be collected")
        canonical = canonicalize_url(url)
        host = urlsplit(canonical).hostname or ""
        if not any(host == domain or host.endswith(f".{domain}") for domain in source.domains):
            raise ValueError(f"domain {host!r} is not allowlisted for {source_id}")
        return canonical

    def validate_claim_type(self, source_id: str, claim_type: SubjectType) -> None:
        policy = self.get(source_id).policy
        if claim_type in policy.prohibited_claim_types:
            raise ValueError(f"{claim_type} is prohibited for {source_id}")
        if claim_type not in policy.allowed_claim_types:
            raise ValueError(f"{claim_type} is not allowed for {source_id}")

    def validate_claim_purpose(self, source_id: str, purpose: ClaimPurpose) -> None:
        policy = self.get(source_id).policy
        if purpose in policy.prohibited_claim_purposes:
            raise ValueError(f"{purpose} is prohibited for {source_id}")
        if purpose not in policy.allowed_claim_purposes:
            raise ValueError(f"{purpose} is not allowed for {source_id}")

    def can_be_independent(self, source_id: str) -> bool:
        return self.get(source_id).policy.usable_as_independent_evidence

    def can_contribute_evidence(self, source_id: str) -> bool:
        source = self.get(source_id)
        return source.role is SourceRole.INPUT and source.trust_class is not TrustClass.SELF
