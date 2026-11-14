"""Offline IOC correlation against imported local feeds; never resolves or contacts indicators."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

SCHEMA_ID = "domainrecon.c2_intelligence"
SCHEMA_VERSION = 1
_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
_DOMAIN_TYPES = {"domain", "domain-name", "domain_name", "fqdn", "hostname", "host"}
_STIX_HASH_NAMES = {"md5": "md5", "sha1": "sha1", "sha-1": "sha1", "sha256": "sha256", "sha-256": "sha256", "sha512": "sha512", "sha-512": "sha512"}
_STIX_OBSERVABLES = {"domain-name": "fqdn", "ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "url": "url"}
_STIX_SIMPLE = re.compile(r"\[\s*(domain-name|ipv4-addr|ipv6-addr|url)\s*:\s*value\s*=\s*'((?:[^'\\]|\\.)+)'\s*\]")
_STIX_HASH = re.compile(r"\[\s*file\s*:\s*hashes\s*\.\s*(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z0-9-]+))\s*=\s*'([0-9A-Fa-f]+)'\s*\]")


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def _domain(value: str) -> str | None:
    text = value.strip().rstrip(".").lower()
    if not text or len(text) > 253 or any(not label or len(label) > 63 for label in text.split(".")):
        return None
    try:
        encoded = text.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return encoded if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in encoded.split(".")) else None


def normalize_indicator(value: str, kind: str | None = None) -> tuple[str, str] | None:
    raw = value.strip()
    if not raw:
        return None
    expected = kind.casefold() if isinstance(kind, str) else ""
    if expected in {"ipv4", "ipv6", "ip"} or not expected:
        try:
            address = ipaddress.ip_address(raw.strip("[]"))
            if expected == "ipv4" and address.version != 4 or expected == "ipv6" and address.version != 6:
                return None
            return ("ipv4" if address.version == 4 else "ipv6", address.compressed)
        except ValueError:
            if expected in {"ipv4", "ipv6", "ip"}:
                return None
    if expected == "url" or raw.casefold().startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        host = _domain(parsed.hostname)
        if host is None:
            try:
                host = ipaddress.ip_address(parsed.hostname).compressed
            except ValueError:
                return None
        try:
            port = parsed.port
        except ValueError:
            return None
        netloc = host if port is None or (parsed.scheme.casefold(), port) in {("http", 80), ("https", 443)} else f"{host}:{port}"
        return "url", urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/", parsed.query, ""))
    if expected in {"md5", "sha1", "sha256", "sha512", "hash", "file_hash"} or not expected:
        if expected in {"hash", "file_hash"}:
            expected = next((algorithm for algorithm, length in _HASH_LENGTHS.items() if len(raw) == length and re.fullmatch(r"[0-9a-fA-F]+", raw)), "")
        if expected in _HASH_LENGTHS and len(raw) == _HASH_LENGTHS[expected] and re.fullmatch(r"[0-9a-fA-F]+", raw):
            return expected, raw.lower()
        if expected in _HASH_LENGTHS:
            return None
    if expected in _DOMAIN_TYPES or not expected:
        host = _domain(raw)
        if host:
            # Domain, FQDN and hostname indicators share one key space so they match discovered names.
            return "fqdn", host
    return None


def parse_stix_pattern(pattern: str) -> tuple[str, str] | None:
    """Parse a single-comparison STIX 2.x indicator pattern into (type, value); compound patterns are unsupported."""
    text = pattern.strip()
    simple = _STIX_SIMPLE.fullmatch(text)
    if simple:
        return _STIX_OBSERVABLES[simple.group(1)], simple.group(2).replace("\\'", "'").replace("\\\\", "\\")
    hashed = _STIX_HASH.fullmatch(text)
    if hashed:
        name = (hashed.group(1) or hashed.group(2) or hashed.group(3) or "").strip().casefold()
        algorithm = _STIX_HASH_NAMES.get(name)
        if algorithm:
            return algorithm, hashed.group(4)
    return None


def _feed_rows(data: Any, errors: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    if not isinstance(data, dict):
        return []
    if data.get("type") == "bundle" and isinstance(data.get("objects"), list):
        rows = []
        for index, obj in enumerate(data["objects"]):
            if not isinstance(obj, dict) or obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern")
            parsed = parse_stix_pattern(pattern) if isinstance(pattern, str) else None
            if parsed is None:
                if errors is not None:
                    errors.append({"index": index, "id": obj.get("id"), "reason": "unsupported_stix_pattern"})
                continue
            rows.append({"value": parsed[1], "type": parsed[0], "source": obj.get("created_by_ref", "stix"), "id": obj.get("id"), "created": obj.get("created"), "modified": obj.get("modified"), "valid_until": obj.get("valid_until"), "labels": obj.get("labels", obj.get("indicator_types", []))})
        return rows
    rows = data.get("indicators", data.get("iocs", data.get("objects", [])))
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def load_ioc_feed(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size > 25_000_000:
        raise ValueError("IOC feed exceeds 25 MB limit.")
    data = path.read_text(encoding="utf-8-sig")
    if path.suffix.casefold() == ".csv":
        rows = list(csv.DictReader(io.StringIO(data)))
        parsed: Any = {"indicators": rows}
    else:
        parsed = json.loads(data)
    if not isinstance(parsed, (dict, list)):
        raise ValueError("IOC feed must be a JSON object/array or CSV file.")
    parse_errors: list[dict[str, Any]] = []
    indicators = _feed_rows(parsed, parse_errors)
    return {"feed_name": path.name, "feed_sha256": hashlib.sha256(data.encode("utf-8")).hexdigest(), "feed_timestamp": None, "indicators": indicators, "parse_errors": parse_errors}


def _asset_indicators(assets: dict[str, Any] | None, dns: dict[str, Any] | None, http: dict[str, Any] | None) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in assets.get("assets", []) if isinstance(assets, dict) and isinstance(assets.get("assets"), list) else []:
        if not isinstance(row, dict):
            continue
        if isinstance(row.get("fqdn"), str):
            result.append({"asset_id": row.get("asset_id", row["fqdn"]), "field": "fqdn", "value": row["fqdn"]})
        for ip in row.get("ip_addresses", []) if isinstance(row.get("ip_addresses"), list) else []:
            if isinstance(ip, str): result.append({"asset_id": row.get("asset_id", row.get("fqdn", ip)), "field": "ip_address", "value": ip})
    for payload, field in ((dns, "dns"), (http, "http")):
        rows = payload.get("records", []) if isinstance(payload, dict) else []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict): continue
            host = row.get("hostname")
            if isinstance(host, str): result.append({"asset_id": host, "field": "hostname", "value": host})
            records = row.get("records", {})
            if isinstance(records, dict):
                for key in ("a", "aaaa"):
                    for ip in records.get(key, []) if isinstance(records.get(key, []), list) else []:
                        result.append({"asset_id": host or ip, "field": key, "value": ip})
            if field == "http" and isinstance(row.get("url"), str): result.append({"asset_id": host or row["url"], "field": "url", "value": row["url"]})
    return result


def confidence_score(value: Any) -> int | None:
    """Normalize feed confidence (0-100 integer, STIX-style words, or high/medium/low) to 0-100."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return max(0, min(100, int(value)))
    text = str(value or "").strip().lower()
    if text.isdigit():
        return max(0, min(100, int(text)))
    return {"high": 85, "medium": 50, "med": 50, "low": 15, "none": 0}.get(text)


def correlate_iocs(feed: dict[str, Any], *, assets: dict[str, Any] | None = None, dns: dict[str, Any] | None = None, http: dict[str, Any] | None = None, now: str | None = None,
                   allowlist: list[str] | set[str] | None = None, min_confidence: int = 0) -> dict[str, Any]:
    allow = {str(value).strip().lower().rstrip(".") for value in allowlist or [] if str(value).strip()}
    suppressed: list[dict[str, Any]] = []
    current = _time(now) if now else datetime.now(timezone.utc)
    if current is None:
        raise ValueError("now must be a timezone-aware ISO timestamp.")
    raw = feed.get("indicators", []) if isinstance(feed, dict) else []
    if not isinstance(raw, list):
        raise ValueError("IOC feed indicators must be a list.")
    canonical: dict[tuple[str, str], dict[str, Any]] = {}
    errors: list[dict[str, Any]] = []
    for index, row in enumerate(raw):
        if not isinstance(row, dict):
            errors.append({"index": index, "reason": "indicator_not_object"}); continue
        value = row.get("value", row.get("indicator"))
        normalized = normalize_indicator(value, row.get("type")) if isinstance(value, str) else None
        if normalized is None:
            errors.append({"index": index, "reason": "invalid_or_unsupported_indicator"}); continue
        key = normalized
        item = canonical.setdefault(key, {"ioc_type": key[0], "ioc_value": key[1], "provenance": []})
        item["provenance"].append({"source_feed": str(row.get("source", feed.get("feed_name", "local_feed")))[:256], "declared_type": row.get("type"), "record_id": row.get("id"), "feed_timestamp": row.get("feed_timestamp", feed.get("feed_timestamp")), "first_observed": row.get("first_seen", row.get("created")), "last_observed": row.get("last_seen", row.get("modified")), "expires_at": row.get("valid_until", row.get("expires_at")), "threat_category": row.get("category", row.get("labels", [])), "confidence": row.get("confidence", "unspecified")})
    expired: set[tuple[str, str]] = set()
    for key, item in canonical.items():
        expiries = [_time(source.get("expires_at")) for source in item["provenance"]]
        known = [value for value in expiries if value is not None]
        if expiries and len(known) == len(expiries) and all(value <= current for value in known):
            expired.add(key)
    matches: list[dict[str, Any]] = []
    for asset in _asset_indicators(assets, dns, http):
        kind = "url" if asset["field"] == "url" else "ipv4" if asset["field"] in {"a", "ip_address"} and ":" not in str(asset["value"]) else "ipv6" if asset["field"] == "aaaa" or asset["field"] == "ip_address" and ":" in str(asset["value"]) else "fqdn"
        normalized = normalize_indicator(str(asset["value"]), kind)
        if not normalized or normalized not in canonical or normalized in expired:
            continue
        ioc = canonical[normalized]
        for prov in ioc["provenance"]:
            digest = hashlib.sha256(f"{normalized}:{asset['asset_id']}:{prov['source_feed']}:{prov['record_id']}".encode()).hexdigest()[:16]
            score = confidence_score(prov["confidence"])
            labels = " ".join(str(x) for x in (prov["threat_category"] if isinstance(prov["threat_category"], list) else [prov["threat_category"]])).lower()
            reason = ("allowlisted by operator" if normalized[1] in allow or str(asset["value"]).lower() in allow
                      else "feed labels the indicator as benign/sinkhole" if any(word in labels for word in ("sinkhole", "benign", "whitelist", "allowlist", "false positive", "false_positive"))
                      else f"feed confidence {score} below threshold {min_confidence}" if score is not None and score < min_confidence else None)
            if reason:
                suppressed.append({"ioc_value": ioc["ioc_value"], "matched_asset": asset["asset_id"], "source_feed": prov["source_feed"], "reason": reason})
                continue
            matches.append({"confidence_score": score, "match_quality": "exact_normalized_value","finding_id": "ioc-" + digest, "ioc_value": ioc["ioc_value"], "ioc_type": ioc["ioc_type"], "threat_category": prov["threat_category"], "source_feed": prov["source_feed"], "feed_timestamp": prov["feed_timestamp"], "confidence": prov["confidence"], "first_observed": prov["first_observed"], "last_observed": prov["last_observed"], "matched_asset": asset["asset_id"], "matched_field": asset["field"], "evidence": {"asset_value": asset["value"], "matching": "exact_normalized_value", "record_id": prov["record_id"]}, "recommended_soc_action": "Validate feed provenance and asset ownership, preserve evidence, and route to an authorized analyst; this offline match alone does not prove compromise."})
    dns_rows = dns.get("records", []) if isinstance(dns, dict) else []
    # DNS behavioral (query-volume/tunneling) analysis needs resolver query telemetry, which a
    # resolution snapshot does not contain; it is reported as not supported rather than guessed.
    dns_summary = {"observations": len(dns_rows) if isinstance(dns_rows, list) else 0, "assessment": "not_supported_without_resolver_query_telemetry"}
    errors.extend({"index": row.get("index"), "id": row.get("id"), "reason": row.get("reason")} for row in (feed.get("parse_errors", []) if isinstance(feed, dict) else []) if isinstance(row, dict))
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": now or datetime.now(timezone.utc).isoformat(), "status": "partial" if errors else "success", "feed_name": feed.get("feed_name") if isinstance(feed, dict) else None, "feed_sha256": feed.get("feed_sha256") if isinstance(feed, dict) else None, "indicators_loaded": len(canonical), "expired_indicators": len(expired), "matches": matches, "findings": matches, "suppressed_matches": suppressed, "feed_errors": errors, "dns_behavior": dns_summary, "limitations": ["No DNS resolution, HTTP request, socket connection, malware execution, or remote feed access occurs.", "IOC matches are not proof of compromise or current maliciousness.", "DNS query-volume/tunneling analysis requires telemetry not represented by a simple DNS resolution snapshot."]}
