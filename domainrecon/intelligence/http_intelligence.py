"""Offline normalization of HTTPX observations into evidence-backed HTTP findings."""
from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

from domainrecon.analysis.tls import extract_tls

SCHEMA_ID = "domainrecon.http_intelligence"
SCHEMA_VERSION = 1
_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def analyze_http_inventory(inventory: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    """Normalize a stored HTTPX inventory without network access."""
    rows = inventory.get("records", []) if isinstance(inventory, dict) else []
    rows = rows if isinstance(rows, list) else []
    observations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        code = row.get("status_code")
        try:
            status = int(code) if code is not None else None
        except (TypeError, ValueError):
            status = None
        if status in {301, 302, 307, 308}:
            classification = "REDIRECT"
        elif status == 401:
            classification = "AUTH_REQUIRED"
        elif status == 403:
            classification = "ACCESS_FORBIDDEN"
        elif status == 404:
            classification = "HTTP_NOT_FOUND"
        elif status is not None:
            classification = "HTTP_OK" if status == 200 else "HTTP_RESPONDING"
        else:
            old_class = str(row.get("classification", "UNKNOWN_ERROR"))
            classification = {"TIMEOUT": "CONNECTION_TIMEOUT", "CONNECTION_REFUSED": "CONNECTION_REFUSED", "TLS_ERROR": "TLS_ERROR"}.get(old_class, "UNKNOWN_ERROR")
        raw_headers = row.get("headers", row.get("response_headers", {}))
        headers = {str(k).lower(): str(v)[:2048] for k, v in raw_headers.items()} if isinstance(raw_headers, dict) else {}
        security_headers = {name: headers[key] for key, name in _SECURITY_HEADERS.items() if key in headers}
        tls = extract_tls({"tls": row.get("tls")})
        expires = tls.get("not_after")
        tls_expired: bool | None = None
        if isinstance(expires, str):
            try:
                parsed = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            except ValueError:
                try:
                    parsed = parsedate_to_datetime(expires)
                except (TypeError, ValueError, OverflowError):
                    parsed = None
            if parsed is not None:
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                tls_expired = parsed <= datetime.now(timezone.utc)
        final_observed = bool(row.get("status") == "success" and status is not None and row.get("final_url"))
        observation = {
            "hostname": row.get("hostname"), "url": row.get("url"),
            "final_url": row.get("final_url") if final_observed else None,
            "final_url_observed": final_observed,
            "status_code": status, "classification": classification,
            "title": row.get("title"), "web_server": row.get("web_server"),
            "technologies": row.get("technologies", []), "response_time": row.get("response_time"),
            "redirect_destination": row.get("redirect_url"), "tls": tls,
            "tls_expired": tls_expired, "response_headers": headers,
            "response_headers_status": "observed" if headers else "not_collected",
            "security_headers": security_headers,
            "security_header_observations": [
                {"header": label, "classification": "observed" if key in headers else "not_observed_in_available_evidence", "confidence": "high" if key in headers else "unknown", "evidence": {"source": "HTTPX response headers" if headers else "not_collected"}}
                for key, label in _SECURITY_HEADERS.items()
            ],
            "evidence": {"artifact": "live_web_inventory.json", "classification_source": "status_code" if status is not None else "HTTPX classification"},
        }
        observations.append(observation)
        for header in observation["security_header_observations"]:
            if header["classification"] == "not_observed_in_available_evidence" and not headers:
                continue
            findings.append({"finding_id": f"http-header:{row.get('hostname')}:{header['header']}", "hostname": row.get("hostname"), "type": "security_header_observation", **header})
        if tls_expired is True:
            findings.append({"finding_id": f"tls-expired:{row.get('hostname')}", "hostname": row.get("hostname"), "type": "tls_certificate_expired", "confidence": "high", "evidence": {"not_after": expires}})
    return {
        "schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION,
        "root_domain": inventory.get("root_domain") if isinstance(inventory, dict) else None,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "status": "success" if inventory is not None else "not_available",
        "source_artifact": "live_web_inventory.json" if inventory is not None else None,
        "observations": observations, "findings": findings,
        "limitations": ["Response headers are available only when the HTTPX inventory recorded them (-include-response-header); otherwise they are marked not_collected, never absent.", "No redirect is followed; a final URL is emitted only when the source observation establishes one."],
    }
