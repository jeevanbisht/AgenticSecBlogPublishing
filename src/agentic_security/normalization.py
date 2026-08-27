"""Deterministic, versioned text normalization and hashing."""

import hashlib
import html
import re
from collections.abc import Callable

NORMALIZER_VERSION = "norm-1.0"


def normalize_v1(text: str) -> str:
    """Normalize publication text without changing semantic content."""
    text = html.unescape(text).replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"(?is)<(script|style|nav|footer|form)\b.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    lines = []
    for line in text.splitlines():
        compact = re.sub(r"[ \t]+", " ", line).strip()
        is_chrome = re.fullmatch(r"(cookie preferences?|accept all|skip to content)", compact, re.I)
        if compact and not is_chrome:
            lines.append(compact)
    return "\n".join(lines).strip()


NORMALIZERS: dict[str, Callable[[str], str]] = {NORMALIZER_VERSION: normalize_v1}


def normalize(text: str, version: str = NORMALIZER_VERSION) -> str:
    try:
        return NORMALIZERS[version](text)
    except KeyError as exc:
        raise ValueError(f"unsupported normalizer version: {version}") from exc


def content_sha256(normalized_text: str) -> str:
    return hashlib.sha256(normalized_text.encode("utf-8")).hexdigest()
