"""Offline delivery/exposure intelligence. DNS configuration is never treated as reachability."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone
from typing import Any

SCHEMA_ID = "domainrecon.delivery_intelligence"
SCHEMA_VERSION = 1
_MX_HOST = r"(?:\.|(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.?)"
_MX_VALUE = re.compile(rf"(?:\d{{1,5}}\s+)?{_MX_HOST}", re.IGNORECASE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _records(payload: Any) -> list[dict[str, Any]]:
    rows = payload.get("records", []) if isinstance(payload, dict) else []
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _global_ip(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _texts(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(item).strip() for item in value if isinstance(item, (str, int)) and str(item).strip()]
    return []


def _finding(kind: str, asset: str, evidence: dict[str, Any], confidence: str, severity: str, rationale: str, remediation: str, score: int) -> dict[str, Any]:
    digest = hashlib.sha256((kind + "|" + asset + "|" + repr(sorted(evidence.items()))).encode()).hexdigest()[:16]
    return {"finding_id": f"delivery-{digest}", "type": kind, "asset_id": asset, "evidence": evidence, "source": evidence.get("source", "stored_v2_artifact"), "confidence": confidence, "severity": severity, "risk_score": score, "risk_rationale": rationale, "recommended_remediation": remediation}


def _email_observations(dns_by_host: dict[str, dict[str, Any]], root: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    root_row = dns_by_host.get(root)
    dmarc_host = "_dmarc." + root
    dmarc_row = dns_by_host.get(dmarc_host)
    for key, host, row, record_type in (("MX", root, root_row, "mx"), ("SPF", root, root_row, "txt"), ("DMARC", dmarc_host, dmarc_row, "txt")):
        if not isinstance(row, dict) or str(row.get("status", "")).lower() != "success":
            findings.append({"type": "email_policy_observation", "policy": key, "classification": "not_assessed", "confidence": "none", "evidence": {"queried_name": host, "record_type": record_type, "reason": "query not successfully observed"}})
            continue
        data = row.get("records", {})
        values = _texts(data.get(record_type)) if isinstance(data, dict) else []
        if key == "MX":
            if not values:
                cls, note = "missing", "No MX answer was observed in a successful query; this is not by itself a vulnerability."
            else:
                # DNSx reports MX exchanges as bare hostnames; zone-file style "<preference> <host>" is also accepted.
                valid = all(_MX_VALUE.fullmatch(value.strip()) for value in values)
                cls, note = ("confirmed_configured", "Syntactically plausible MX configuration was observed; this does not prove SMTP reachability.") if valid else ("invalid", "One or more MX values do not match the expected preference/exchange form.")
        elif key == "SPF":
            policies = [value for value in values if value.casefold().startswith("v=spf1")]
            if not policies:
                cls, note = "missing", "No SPF1 TXT record was observed in a successful TXT query; absence alone is not a vulnerability."
            elif len(policies) != 1 or not re.match(r"(?i)^v=spf1(?:\s|$)", policies[0]):
                cls, note = "invalid", "SPF requires exactly one syntactically recognizable SPF1 policy."
            elif re.search(r"(?:^|\s)[+?~]?all(?:\s|$)", policies[0], re.I) and not re.search(r"(?:^|\s)-all(?:\s|$)", policies[0], re.I):
                cls, note = "weak", "SPF ends in a permissive, neutral, or soft-fail all mechanism rather than hard-fail."
            elif not re.search(r"(?:^|\s)-all(?:\s|$)", policies[0], re.I):
                cls, note = "weak", "No restrictive SPF -all mechanism was observed; full SPF evaluation is not performed."
            else:
                cls, note = "confirmed_policy", "One SPF1 policy with -all was observed; mechanisms and lookup limits are not recursively evaluated."
        else:
            policies = [value for value in values if value.casefold().startswith("v=dmarc1")]
            if not policies:
                cls, note = "missing", "No DMARC TXT record was observed for the queried _dmarc name; absence alone is not a vulnerability."
            elif len(policies) != 1 or not re.match(r"(?i)^v=DMARC1(?:;|\s)", policies[0]):
                cls, note = "invalid", "DMARC requires one syntactically recognizable policy record."
            else:
                match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b", policies[0], re.I)
                if not match:
                    cls, note = "invalid", "DMARC policy tag is absent or invalid."
                elif match.group(1).casefold() == "none":
                    cls, note = "weak", "DMARC p=none requests monitoring rather than quarantine or rejection."
                else:
                    cls, note = "confirmed_policy", f"DMARC p={match.group(1).casefold()} was observed; pct and alignment are reported, not fully evaluated."
        findings.append({"type": "email_policy_observation", "policy": key, "classification": cls, "confidence": "high" if cls not in {"missing", "not_assessed"} else "low", "evidence": {"queried_name": host, "record_type": record_type, "records": values, "note": note}})
    return findings


def analyze_delivery_exposure(scope: Any, *, dns: dict[str, Any] | None = None, http: dict[str, Any] | None = None, nmap: dict[str, Any] | None = None, database: dict[str, Any] | None = None, asset_inventory: dict[str, Any] | None = None, generated_at: str | None = None) -> dict[str, Any]:
    """Classify exposure only from direct HTTP/Nmap observations; DNS yields infrastructure config only."""
    payloads = {"dns": dns, "http": http, "nmap": nmap, "database": database, "asset_inventory": asset_inventory}
    for key, payload in payloads.items():
        if isinstance(payload, dict):
            target = payload.get("root_domain", payload.get("target"))
            if target is not None and target != scope.root_domain:
                raise ValueError(f"{key} artifact target does not match scope.")
    exposure: dict[str, dict[str, Any]] = {}

    def add(asset: str, category: str, evidence: dict[str, Any], confidence: str) -> None:
        row = exposure.setdefault(asset, {"asset": asset, "categories": [], "evidence": [], "confidence": confidence})
        if category not in row["categories"]:
            row["categories"].append(category)
        row["evidence"].append(evidence)
        if confidence == "high":
            row["confidence"] = "high"

    for row in _records(http):
        host = row.get("hostname")
        code = row.get("status_code")
        ip = row.get("ip")
        if isinstance(host, str) and scope.permits_hostname(host) and isinstance(code, int) and 100 <= code <= 599 and _global_ip(ip):
            add(scope.require_hostname(host), "PUBLIC_WEB_SERVICE", {"source": "httpx", "url": row.get("url"), "status_code": code, "ip": ip, "classification": row.get("classification")}, "high")
    hosts = nmap.get("hosts", []) if isinstance(nmap, dict) and nmap.get("status") == "success" else []
    if isinstance(hosts, list):
        for hostrow in hosts:
            if not isinstance(hostrow, dict) or not _global_ip(hostrow.get("address")):
                continue
            address = hostrow["address"]
            for port in hostrow.get("ports", []) if isinstance(hostrow.get("ports"), list) else []:
                if not isinstance(port, dict) or port.get("state") != "open" or port.get("protocol", "tcp") != "tcp":
                    continue
                service = str(port.get("service") or "unknown").casefold()
                category = "PUBLIC_NETWORK_SERVICE"
                if any(tag in service for tag in ("mysql", "postgres", "mssql", "mongodb", "redis", "oracle")):
                    category = "DATABASE_EXPOSURE_INDICATOR"
                endpoint = f"{address}/tcp/{port.get('port')}"
                evidence = {"source": "authorized_nmap", "ip": address, "port": port.get("port"), "service": port.get("service"), "product": port.get("product"), "version": port.get("version"), "state": "open"}
                add(endpoint, category, evidence, "high")
    dns_by_host: dict[str, dict[str, Any]] = {}
    for row in _records(dns):
        hostname = row.get("hostname")
        if isinstance(hostname, str) and scope.permits_dns_policy_name(hostname):
            # Narrow exception: _dmarc.<in-scope host> TXT policy rows are analyzed, never treated as assets.
            dns_by_host[scope.require_dns_policy_name(hostname)] = row
            continue
        if isinstance(hostname, str) and scope.permits_hostname(hostname):
            dns_by_host[scope.require_hostname(hostname)] = row
            if str(row.get("status", "")).casefold() == "success":
                raw = row.get("records", {})
                if isinstance(raw, dict) and _texts(raw.get("ns")):
                    add(scope.require_hostname(hostname), "DNS_INFRASTRUCTURE", {"source": "dnsx", "record_type": "NS", "records": _texts(raw.get("ns"))}, "medium")
                if isinstance(raw, dict) and _texts(raw.get("mx")):
                    add(scope.require_hostname(hostname), "EMAIL_INFRASTRUCTURE", {"source": "dnsx", "record_type": "MX", "records": _texts(raw.get("mx")), "note": "Routing configuration, not SMTP reachability."}, "medium")
    email_findings = _email_observations(dns_by_host, scope.root_domain)
    findings: list[dict[str, Any]] = []
    for item in email_findings:
        cls = item["classification"]
        if cls in {"weak", "invalid"}:
            severity = "MEDIUM" if cls == "weak" else "LOW"
            note = "Observed email-policy configuration concern; not evidence of exploitable vulnerability or mail-server reachability."
            findings.append(_finding("email_policy_configuration", scope.root_domain, item["evidence"], item["confidence"], severity, note, "Review the authoritative DNS policy with the mail administrator; validate all includes, alignment, reporting and provider requirements before changing records.", 35 if cls == "weak" else 15))
    for asset, row in sorted(exposure.items()):
        row["categories"].sort()
        direct = any(ev.get("source") in {"httpx", "authorized_nmap"} for ev in row["evidence"])
        if direct and any(x in row["categories"] for x in ("DATABASE_EXPOSURE_INDICATOR", "PUBLIC_NETWORK_SERVICE")):
            category = next(x for x in row["categories"] if x in {"DATABASE_EXPOSURE_INDICATOR", "PUBLIC_NETWORK_SERVICE"})
            findings.append(_finding("observed_public_service", asset, {"source": "authorized_nmap", "observations": row["evidence"]}, "high", "MEDIUM" if category == "DATABASE_EXPOSURE_INDICATOR" else "INFO", "An authorized scan observed an open TCP service at a globally routable address; this establishes scan-time response, not persistent reachability or ownership.", "Confirm business need and intended network controls; restrict management or database listeners to approved source networks where appropriate.", 45 if category == "DATABASE_EXPOSURE_INDICATOR" else 15))
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": generated_at or _now(), "root_domain": scope.root_domain, "status": "success" if any(payload is not None for payload in payloads.values()) else "not_available", "source_status": {key: "available" if value is not None else "not_available" for key, value in payloads.items()}, "exposures": [exposure[key] for key in sorted(exposure)], "email_observations": email_findings, "findings": findings, "limitations": ["DNS A/AAAA/CNAME/MX/SPF/DMARC/NS presence alone is not service reachability evidence.", "No email delivery, SMTP connection, recursive SPF expansion, or DKIM selector guessing is performed.", "Nmap reachability classifications represent the authorized scan vantage and time only."]}
