"""Offline, low-confidence technology hints from already collected evidence.

DEPRECATED compatibility helper (retained, not used by any DomainRecon workflow). Superseded by
``domainrecon.intelligence.technology_fingerprint``, which adds sources, versions and confidence.
Kept so existing imports and its regression test keep working; scheduled for removal in the next
major version. Do not build new features on it.
"""
from __future__ import annotations

from typing import Any

_HEADER_HINTS = {"server": "server", "x-powered-by": "runtime", "via": "proxy"}


def fingerprint(http_record: dict[str, Any]) -> dict[str, str]:
    result: dict[str, str] = {}
    headers = http_record.get("headers", {})
    if isinstance(headers, dict):
        for header, label in _HEADER_HINTS.items():
            value = headers.get(header) or headers.get(header.title())
            if isinstance(value, str) and value.strip():
                result[label] = value.strip()[:256]
    for key in ("webserver", "title"):
        value = http_record.get(key)
        if isinstance(value, str) and value.strip():
            result[key] = value.strip()[:256]
    return result
