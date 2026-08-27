"""Public bundle validation and private-field scanning."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from pydantic import Field

from agentic_security.models import FrozenModel

FORBIDDEN_PATH_PARTS = {
    "credentials",
    "private",
    "prompts",
    "snapshots",
    "traces",
}
FORBIDDEN_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
ALLOWED_TEXT_SUFFIXES = {
    ".astro",
    ".css",
    ".csv",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".svg",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
}
FORBIDDEN_NORMALIZED_KEYS = {
    "api_key",
    "api_secret",
    "access_token",
    "authorization",
    "auth_token",
    "aws_access_key_id",
    "aws_secret_access_key",
    "bearer_token",
    "client_token",
    "client_secret",
    "comments",
    "cookie",
    "credentials",
    "encryption_key",
    "github_token",
    "normalized_text",
    "notes",
    "password",
    "passwd",
    "personal_access_token",
    "private_key",
    "prompt",
    "prompts",
    "raw_content",
    "refresh_token",
    "secret",
    "secret_key",
    "service_account_key",
    "signing_key",
    "snapshot_id",
    "snapshots",
    "token",
    "trace",
    "traces",
}
KNOWN_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{20,255}(?![A-Za-z0-9])"),
    re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,255}(?![A-Za-z0-9_])"),
    re.compile(r"(?<![A-Za-z0-9_-])sk-proj-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{20,255}(?![A-Za-z0-9_-])"),
    re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    re.compile(
        r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\."
        r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
    ),
)
SECRET_ASSIGNMENT = re.compile(
    r"\b(?:api[_-]?key|client[_-]?secret|private[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|password|passwd|secret|token)\b\s*[:=]\s*"
    r"['\"]?([A-Za-z0-9_./+=-]{12,})",
    re.IGNORECASE,
)
TOKEN_CANDIDATE = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/=-]{32,}")
SAFE_PLACEHOLDERS = {
    "changeme",
    "example",
    "none",
    "none_found",
    "not_configured",
    "redacted",
    "unknown",
}
HASH_VALUE_LENGTHS = {
    "artifact_hash": 64,
    "commit_sha": 40,
    "fingerprint": 64,
    "sha256": 64,
    "snapshot_sha256": 64,
}
MASKED_SECRET = re.compile(r"(?<!\*)\*{6,}(?!\*)")


class PublicationHash(FrozenModel):
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=0)


class PublicationManifest(FrozenModel):
    generated_at: datetime
    methodology_version: str
    taxonomy_version: str
    source_ledger_version: str
    content_count: int = Field(ge=0)
    confirmed_change_count: int = Field(ge=0)
    pending_review_count: int = Field(ge=0)
    files: tuple[PublicationHash, ...]


def _normalize_key(value: str) -> str:
    with_word_boundaries = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return re.sub(r"[^a-z0-9]+", "_", with_word_boundaries.lower()).strip("_")


def _entropy(value: str) -> float:
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_like_high_entropy_token(
    value: str,
    *,
    allowed_hash_length: int | None,
) -> bool:
    if re.fullmatch(r"[a-fA-F0-9]{32,128}", value):
        return len(value) != allowed_hash_length
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
        value,
    ):
        return False
    classes = sum(
        (
            any(character.islower() for character in value),
            any(character.isupper() for character in value),
            any(character.isdigit() for character in value),
            any(character in "_+/=" for character in value),
        )
    )
    return len(value) >= 32 and classes >= 3 and _entropy(value) >= 4.3


def _scan_non_url_string(
    value: str,
    location: str,
    *,
    allowed_hash_length: int | None = None,
) -> None:
    if MASKED_SECRET.search(value):
        raise ValueError(f"masked secret placeholder found in publication data: {location}")
    for pattern in KNOWN_SECRET_PATTERNS:
        if pattern.search(value):
            raise ValueError(f"credential-like content found in publication data: {location}")
    for match in SECRET_ASSIGNMENT.finditer(value):
        assigned = match.group(1)
        if assigned.lower() not in SAFE_PLACEHOLDERS:
            raise ValueError(f"credential-like content found in publication data: {location}")
    for match in TOKEN_CANDIDATE.finditer(value):
        if _looks_like_high_entropy_token(
            match.group(0),
            allowed_hash_length=allowed_hash_length,
        ):
            raise ValueError(
                f"high-entropy token-like content found in publication data: {location}"
            )


def _scan_string(
    value: str,
    location: str,
    *,
    allowed_hash_length: int | None = None,
) -> None:
    stripped = value.strip()
    if MASKED_SECRET.search(stripped):
        raise ValueError(f"masked secret placeholder found in publication data: {location}")
    for pattern in KNOWN_SECRET_PATTERNS:
        if pattern.search(stripped):
            raise ValueError(f"credential-like content found in publication data: {location}")
    parts = urlsplit(stripped)
    if (
        parts.scheme in {"http", "https"}
        and parts.netloc
        and not any(character.isspace() for character in stripped)
    ):
        if parts.username is not None or parts.password is not None:
            raise ValueError(f"credential-bearing URL found in publication data: {location}")
        for key, values in parse_qs(parts.query, keep_blank_values=True).items():
            if _normalize_key(key) in FORBIDDEN_NORMALIZED_KEYS:
                raise ValueError(f"secret-bearing URL found in publication data: {location}")
            for item in values:
                _scan_non_url_string(item, location)
        for segment in parts.path.split("/"):
            if segment:
                _scan_non_url_string(unquote(segment), location)
        if parts.fragment:
            _scan_non_url_string(unquote(parts.fragment), location)
        return
    _scan_non_url_string(
        stripped,
        location,
        allowed_hash_length=allowed_hash_length,
    )


def _scan_json(
    value: Any,
    location: str,
    *,
    allowed_hash_length: int | None = None,
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = _normalize_key(str(key))
            if normalized in FORBIDDEN_NORMALIZED_KEYS:
                raise ValueError(
                    f"private field is prohibited in publication data: {location}.{key}"
                )
            _scan_json(
                item,
                f"{location}.{key}",
                allowed_hash_length=HASH_VALUE_LENGTHS.get(normalized),
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_json(
                item,
                f"{location}[{index}]",
                allowed_hash_length=allowed_hash_length,
            )
    elif isinstance(value, str):
        _scan_string(
            value,
            location,
            allowed_hash_length=allowed_hash_length,
        )


def scan_public_file(path: Path, *, relative_to: Path) -> None:
    relative = path.relative_to(relative_to)
    lowered_parts = {part.lower() for part in relative.parts}
    if lowered_parts & FORBIDDEN_PATH_PARTS or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError(f"private path is prohibited in publication bundle: {relative.as_posix()}")
    if path.suffix.lower() not in ALLOWED_TEXT_SUFFIXES:
        raise ValueError(f"unapproved publication file type: {relative.as_posix()}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"non-text publication file is prohibited: {relative.as_posix()}") from exc
    if "\x00" in text:
        raise ValueError(f"non-text publication file is prohibited: {relative.as_posix()}")
    if path.suffix.lower() == ".json":
        _scan_json(json.loads(text), relative.as_posix())
    else:
        _scan_string(text, relative.as_posix())


def file_hash(path: Path, *, relative_to: Path) -> PublicationHash:
    return PublicationHash(
        path=path.relative_to(relative_to).as_posix(),
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        size_bytes=path.stat().st_size,
    )


def validate_publication_bundle(root: Path) -> PublicationManifest:
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError("publication/manifest.json is missing")
    manifest = PublicationManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    expected = tuple(sorted(manifest.files, key=lambda item: item.path))
    if manifest.files != expected:
        raise ValueError("publication manifest file hashes are not sorted")
    actual_paths = tuple(
        path for path in sorted(root.rglob("*")) if path.is_file() and path != manifest_path
    )
    if tuple(item.path for item in expected) != tuple(
        path.relative_to(root).as_posix() for path in actual_paths
    ):
        raise ValueError("publication manifest does not exactly enumerate bundle files")
    for path, expected_hash in zip(actual_paths, expected, strict=True):
        scan_public_file(path, relative_to=root)
        if file_hash(path, relative_to=root) != expected_hash:
            raise ValueError(f"publication file hash mismatch: {expected_hash.path}")
    scan_public_file(manifest_path, relative_to=root)
    return manifest
