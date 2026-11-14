"""Normalize TLS details already emitted by authorized HTTPX observations."""
from __future__ import annotations

from typing import Any


def extract_tls(httpx_observation: dict[str, Any]) -> dict[str, Any]:
    raw = httpx_observation.get("tls")
    if not isinstance(raw, dict):
        return {"status": "unknown"}
    keep = ("version", "cipher", "subject_dn", "issuer_dn", "serial", "not_before", "not_after", "dns_names")
    result = {key: raw[key] for key in keep if key in raw}
    return {"status": "success", **result}
