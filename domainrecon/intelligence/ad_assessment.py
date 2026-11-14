"""Structured import and analysis of authorized Active Directory assessment outputs.

DomainRecon does not query Active Directory. It normalizes findings exported by authorized tools
(generic JSON/CSV, PingCastle health-check XML, Certipy ``find -json`` output) into categories,
preserving the original (secret-redacted) evidence, tool, file name and SHA-256, and maps each
category to MITRE ATT&CK.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from domainrecon.core.redaction import redact
from domainrecon.intelligence.mitre_mapping import techniques_for

SCHEMA_ID = "domainrecon.ad_assessment"
SCHEMA_VERSION = 1
_CATEGORY_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("asrep_roasting", re.compile(r"(?i)as-?rep|dont_?req_?preauth|pre-?auth(entication)? (not required|disabled)")),
    ("kerberoasting", re.compile(r"(?i)kerberoast|service principal|\bspn\b")),
    ("adcs", re.compile(r"(?i)\badcs\b|\besc\d{1,2}\b|certificate template|enrollment|\bpki\b|certificate authority")),
    ("kerberos_delegation", re.compile(r"(?i)delegation|\brbcd\b|trustedfordelegation|allowedtodelegate")),
    ("domain_trust", re.compile(r"(?i)\btrusts?\b|sid ?history|sid filtering")),
    ("gpo_security", re.compile(r"(?i)\bgpo\b|group policy|gpp|cpassword")),
    ("weak_password_policy", re.compile(r"(?i)password (policy|length|age|complexity)|lockout|minpwdlen|pwd(last|never)|reversible|lm ?hash")),
    ("excessive_permissions", re.compile(r"(?i)\bacl\b|\bace\b|genericall|genericwrite|writedacl|writeowner|dcsync|replication rights|permission")),
    ("privileged_account_exposure", re.compile(r"(?i)admin|privileged|krbtgt|adminsdholder|domain admins|enterprise admins|schema admins|protected users")),
)
_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def classify(text: str) -> str:
    return next((category for category, pattern in _CATEGORY_RULES if pattern.search(text)), "other_ad_finding")


def _points_severity(points: Any) -> str:
    try:
        value = int(points)
    except (TypeError, ValueError):
        return "INFO"
    return "HIGH" if value >= 30 else "MEDIUM" if value >= 10 else "LOW" if value > 0 else "INFO"


def _parse_pingcastle(text: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ValueError("XML with DTD/entities is refused.")
    root = ET.fromstring(text)
    domain = (root.findtext("DomainFQDN") or "").strip() or None
    rows = []
    for rule in root.iter("HealthcheckRiskRule"):
        rows.append({"rule_id": rule.findtext("RiskId"), "title": rule.findtext("Rationale"), "category_hint": f"{rule.findtext('Category')} {rule.findtext('Model')}",
                     "severity": _points_severity(rule.findtext("Points")), "points": rule.findtext("Points"), "object": domain})
    return rows, {"format": "pingcastle_healthcheck_xml", "domain": domain, "generated": root.findtext("GenerationDate")}


def _parse_certipy(data: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = []
    for section, label in (("Certificate Templates", "template"), ("Certificate Authorities", "ca")):
        entries = data.get(section, {})
        for entry in entries.values() if isinstance(entries, dict) else []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("Template Name") or entry.get("CA Name") or "unknown"
            for esc, description in (entry.get("[!] Vulnerabilities") or {}).items():
                rows.append({"rule_id": esc, "title": f"{esc} on {label} {name}: {description}", "category_hint": "adcs", "severity": "HIGH", "object": name})
    return rows, {"format": "certipy_find_json"}


def import_ad_findings(path: Path, *, tool: str, max_bytes: int = 50_000_000) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError("AD evidence file exceeds the import size limit.")
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8-sig")
    suffix = path.suffix.lower()
    errors: list[dict[str, Any]] = []
    if suffix == ".xml":
        rows, meta = _parse_pingcastle(text)
    elif suffix == ".csv":
        rows, meta = list(csv.DictReader(io.StringIO(text))), {"format": "generic_csv"}
    else:
        data = json.loads(text)
        if isinstance(data, dict) and ("Certificate Templates" in data or "Certificate Authorities" in data):
            rows, meta = _parse_certipy(data)
        else:
            rows = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else []
            meta = {"format": "generic_json"}
    findings = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict) or not (row.get("title") or row.get("name")):
            errors.append({"record": index, "error": "missing_title"})
            continue
        title = str(row.get("title") or row.get("name"))[:400]
        hint = " ".join(str(row.get(key) or "") for key in ("category", "category_hint", "rule_id", "title", "name"))
        category = str(row.get("category")) if row.get("category") in {name for name, _ in _CATEGORY_RULES} else classify(hint)
        severity = str(row.get("severity") or "INFO").upper()
        severity = severity if severity in _SEVERITIES else "INFO"
        affected = str(row.get("object") or row.get("affected_object") or row.get("account") or meta.get("domain") or "active_directory")[:200]
        identifier = hashlib.sha256(f"ad|{tool}|{row.get('rule_id')}|{affected}|{title}".encode()).hexdigest()[:16]
        findings.append({
            "finding_id": f"ad-{identifier}", "type": "ad_assessment_finding", "category": category, "title": title, "severity": severity, "asset_id": affected,
            "confidence": "as_reported_by_tool", "verified": bool(row.get("verified") is True),
            "evidence": {"original_record": redact(row), "record_number": index, "source_file": path.name, "source_sha256": digest, "tool": tool, "format": meta.get("format")},
            "mitre_attack": techniques_for(category), "source": f"imported:{tool}",
            "recommended_remediation": str(row.get("remediation") or "Review with the directory owner using the source tool's guidance."),
        })
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding["category"]] = counts.get(finding["category"], 0) + 1
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "status": "partial" if errors else "success",
            "source": {"file": path.name, "sha256": digest, "tool": tool, **meta}, "category_counts": counts, "findings": findings, "errors": errors,
            "limitations": ["Imported evidence only; DomainRecon performs no Active Directory queries.", "Severity and accuracy are as reported by the source tool; categories are keyword-derived.", "Secrets in imported records are redacted before storage."]}
