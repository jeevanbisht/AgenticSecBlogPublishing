"""Allowlisted, bounded HTTP retrieval."""

from __future__ import annotations

import time
import urllib.robotparser
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx

from agentic_security.collection.base import (
    AllowAllRobots,
    RetrievalCache,
    RetrievalLimits,
    RobotsPolicy,
    build_snapshot,
)
from agentic_security.models import Snapshot
from agentic_security.sources.registry import SourceRegistry


def _read_bounded(response: httpx.Response, max_response_bytes: int) -> bytes:
    encoding = response.headers.get("content-encoding")
    if encoding is not None and encoding.strip().lower() not in {"", "identity"}:
        raise ValueError("response uses an unsupported Content-Encoding")
    declared = response.headers.get("content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise ValueError("response has an invalid Content-Length") from exc
        if declared_size < 0:
            raise ValueError("response has an invalid Content-Length")
        if declared_size > max_response_bytes:
            raise ValueError("response exceeds configured size limit")
    content = bytearray()
    for chunk in response.iter_bytes():
        if len(content) + len(chunk) > max_response_bytes:
            raise ValueError("response exceeds configured size limit")
        content.extend(chunk)
    return bytes(content)


class HttpRetriever:
    def __init__(
        self,
        registry: SourceRegistry,
        *,
        limits: RetrievalLimits | None = None,
        robots: RobotsPolicy | None = None,
        cache: RetrievalCache | None = None,
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        user_agent: str = "agentic-security-intelligence/0.1",
    ) -> None:
        self.registry = registry
        self.limits = limits or RetrievalLimits()
        self.robots = robots or AllowAllRobots()
        self.cache = cache or RetrievalCache()
        self.transport = transport
        self.clock = clock
        self.sleep = sleep
        self.user_agent = user_agent
        self._last_request_at: dict[str, float] = {}

    def retrieve(self, source_id: str, url: str, snapshot_id: str) -> Snapshot:
        canonical = self.registry.validate_url(source_id, url)
        self._validate_hop(source_id, canonical)
        cached = self.cache.get(canonical)
        if cached is None:
            content, content_type = self._request(source_id, canonical)
            self.cache.put(canonical, content, content_type)
        else:
            content = cached.content
            content_type = cached.content_type
        return build_snapshot(
            snapshot_id=snapshot_id,
            source_id=source_id,
            canonical_uri=canonical,
            content_type=content_type,
            raw_text=content.decode("utf-8"),
            retrieved_at=datetime.now(UTC),
        )

    def _validate_hop(self, source_id: str, url: str) -> str:
        canonical = self.registry.validate_url(source_id, url)
        if not self.robots.allowed(self.user_agent, canonical):
            raise PermissionError(f"robots policy denies retrieval: {canonical}")
        return canonical

    def _request(self, source_id: str, canonical: str) -> tuple[bytes, str]:
        last_error: Exception | None = None
        with httpx.Client(
            timeout=self.limits.timeout_seconds,
            follow_redirects=False,
            transport=self.transport,
            headers={
                "User-Agent": self.user_agent,
                "Accept-Encoding": "identity",
            },
        ) as client:
            for attempt in range(self.limits.max_retries + 1):
                try:
                    current = canonical
                    for redirect_count in range(self.limits.max_redirects + 1):
                        now = self.clock()
                        wait = self.limits.min_interval_seconds - (
                            now - self._last_request_at.get(source_id, 0.0)
                        )
                        if wait > 0:
                            self.sleep(wait)
                        with client.stream("GET", current) as response:
                            self._last_request_at[source_id] = self.clock()
                            if response.is_redirect:
                                location = response.headers.get("location")
                                if not location:
                                    raise ValueError("redirect response is missing Location")
                                if redirect_count >= self.limits.max_redirects:
                                    raise httpx.TooManyRedirects(
                                        f"redirect limit exceeded ({self.limits.max_redirects})",
                                        request=response.request,
                                    )
                                current = self._validate_hop(
                                    source_id,
                                    urljoin(str(response.request.url), location),
                                )
                                continue
                            response.raise_for_status()
                            content_type = (
                                response.headers.get("content-type", "").split(";", 1)[0].lower()
                            )
                            if content_type not in self.limits.allowed_content_types:
                                raise ValueError(f"unsupported content type: {content_type}")
                            content = _read_bounded(
                                response,
                                self.limits.max_response_bytes,
                            )
                            return content, content_type
                except (httpx.HTTPError, ValueError) as exc:
                    last_error = exc
                    if attempt < self.limits.max_retries:
                        self.sleep(0.1 * (2**attempt))
        assert last_error is not None
        raise last_error


class FailClosedRobotsPolicy:
    """Fetch and enforce robots.txt; any retrieval or parsing failure denies access."""

    def __init__(
        self,
        registry: SourceRegistry,
        source_id: str,
        *,
        limits: RetrievalLimits | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.registry = registry
        self.source_id = source_id
        self.limits = limits or RetrievalLimits()
        self.transport = transport
        self.sleep = sleep
        self._parsers: dict[str, urllib.robotparser.RobotFileParser | None] = {}

    def allowed(self, user_agent: str, url: str) -> bool:
        try:
            canonical = self.registry.validate_url(self.source_id, url)
            parts = urlsplit(canonical)
            origin = f"{parts.scheme}://{parts.netloc}"
            if origin not in self._parsers:
                self._parsers[origin] = self._fetch(origin, user_agent)
            parser = self._parsers[origin]
            return parser is not None and parser.can_fetch(user_agent, canonical)
        except (httpx.HTTPError, UnicodeDecodeError, ValueError):
            return False

    def _fetch(
        self,
        origin: str,
        user_agent: str,
    ) -> urllib.robotparser.RobotFileParser | None:
        current = self.registry.validate_url(self.source_id, f"{origin}/robots.txt")
        last_error: Exception | None = None
        with httpx.Client(
            timeout=self.limits.timeout_seconds,
            follow_redirects=False,
            transport=self.transport,
            headers={
                "User-Agent": user_agent,
                "Accept-Encoding": "identity",
            },
        ) as client:
            for attempt in range(self.limits.max_retries + 1):
                try:
                    for redirect_count in range(self.limits.max_redirects + 1):
                        with client.stream("GET", current) as response:
                            if response.is_redirect:
                                location = response.headers.get("location")
                                if not location or redirect_count >= self.limits.max_redirects:
                                    return None
                                current = self.registry.validate_url(
                                    self.source_id,
                                    urljoin(str(response.request.url), location),
                                )
                                continue
                            response.raise_for_status()
                            content_type = (
                                response.headers.get("content-type", "").split(";", 1)[0].lower()
                            )
                            if content_type != "text/plain":
                                return None
                            content = _read_bounded(
                                response,
                                self.limits.max_response_bytes,
                            )
                            parser = urllib.robotparser.RobotFileParser()
                            parser.set_url(current)
                            parser.parse(content.decode("utf-8").splitlines())
                            return parser
                except (httpx.HTTPError, ValueError) as exc:
                    last_error = exc
                    if attempt < self.limits.max_retries:
                        self.sleep(0.1 * (2**attempt))
        if last_error is not None:
            return None
        return None
