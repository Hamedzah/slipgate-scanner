"""Deduplication hashing for proxy configs.

Two configs that are functionally identical (same host, port, id, and
core parameters) but differ in cosmetic fields (remark/tag, query
ordering) must hash identically. We therefore normalize before hashing.
"""

from __future__ import annotations

import hashlib
from urllib.parse import parse_qsl, urlsplit

from src.parsers.config_parser import ParsedConfig


def normalize_config(config: ParsedConfig) -> str:
    """Build a canonical string representation ignoring cosmetic fields.

    Args:
        config: A parsed proxy config.

    Returns:
        A normalized string suitable for hashing.
    """
    parts = [
        config.protocol,
        config.host.lower(),
        str(config.port),
        config.identifier or "",
        config.encryption or "",
        config.network_type or "",
        config.path or "",
    ]
    return "|".join(parts)


def compute_config_hash(config: ParsedConfig) -> str:
    """Compute a SHA-256 hex digest for deduplication.

    Args:
        config: A parsed proxy config.

    Returns:
        Hex-encoded SHA-256 digest of the normalized config string.
    """
    normalized = normalize_config(config)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def strip_query_tag(raw_uri: str) -> str:
    """Remove the fragment (#remark) portion of a proxy URI.

    Used before re-tagging with our own channel identifier.

    Args:
        raw_uri: The raw scraped config URI.

    Returns:
        The URI with any trailing `#remark` fragment removed.
    """
    return urlsplit(raw_uri)._replace(fragment="").geturl()


def get_query_params(raw_uri: str) -> dict[str, str]:
    """Parse the query string portion of a config URI into a dict."""
    query = urlsplit(raw_uri).query
    return dict(parse_qsl(query))
