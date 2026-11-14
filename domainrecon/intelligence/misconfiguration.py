"""Externally observable security-misconfiguration assessment plus authorized-tool evidence import.

Rules run only over evidence DomainRecon already holds (HTTPX observations, Nmap services) and
never claim internal configuration was inspected. Checks that need requests DomainRecon does not
make (OPTIONS/TRACE method testing, authenticated checks) are accepted only as imported evidence
from authorized tools (generic JSON/CSV, Nuclei JSONL, testssl.sh JSON), with provenance retained.
Weak TLS and DNS/email policy issues are reported by the certificate, DNS, and delivery modules.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from pathlib import Path
from typing import Any

from domainrecon.core.redaction import redact
from domainrecon.intelligence.mitre_mapping import techniques_for

SCHEMA_ID = "domainrecon.misconfiguration_assessment"
SCHEMA_VERSION = 1
_EXPOSED_PORTS: dict[int, tuple[str, str, str]] = {
    23: ("Telnet", "exposed_remote_service", "HIGH"), 21: ("FTP", "exposed_remote_service", "MEDIUM"), 3389: ("RDP", "exposed_remote_service", "MEDIUM"),
    5900: ("VNC", "exposed_remote_service", "HIGH"), 445: ("SMB", "exposed_remote_service", "HIGH"), 139: ("NetBIOS", "exposed_remote_service", "MEDIUM"),
    5985: ("WinRM (HTTP)", "exposed_remote_service", "MEDIUM"), 5986: ("WinRM (HTTPS)", "exposed_remote_service", "MEDIUM"), 22: ("SSH", "exposed_remote_service", "INFO"),
    3306: ("MySQL", "exposed_database_service", "HIGH"), 5432: ("PostgreSQL", "exposed_database_service", "HIGH"), 1433: ("Microsoft SQL Server", "exposed_database_service", "HIGH"),
    1521: ("Oracle TNS", "exposed_database_service", "HIGH"), 27017: ("MongoDB", "exposed_database_service", "HIGH"), 6379: ("Redis", "exposed_database_service", "HIGH"),
    9200: ("Elasticsearch", "exposed_database_service", "HIGH"), 11211: ("Memcached", "exposed_database_service", "HIGH"), 5984: ("CouchDB", "exposed_database_service", "HIGH"),
    2375: ("Docker API (plaintext)", "exposed_admin_interface", "HIGH"), 2376: ("Docker API (TLS)", "exposed_admin_interface", "MEDIUM"),
    6443: ("Kubernetes API", "exposed_admin_interface", "MEDIUM"), 10250: ("Kubelet API", "exposed_admin_interface", "HIGH"), 9090: ("Admin/metrics console", "exposed_admin_interface", "LOW"),
}
_ADMIN_TITLE = re.compile(r"(?i)\b(admin(istrat(ion|or))?|login|sign in|dashboard|phpmyadmin|jenkins|grafana|kibana|webmin|cpanel|plesk|portainer|router|management console|sonarqube|gitlab|rabbitmq)\b")
_HEADER_CHECKS = (
    ("strict-transport-security", "Strict-Transport-Security (HSTS)", True, "Send Strict-Transport-Security with an appropriate max-age on HTTPS responses."),
    ("content-security-policy", "Content-Security-Policy", False, "Define a Content-Security-Policy appropriate to the application."),
    ("x-content-type-options", "X-Content-Type-Options", False, "Send X-Content-Type-Options: nosniff."),
)
_DISCLOSURE_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator")


def _finding(rule: str, category: str, severity: str, asset: str, title: str, evidence: dict[str, Any], confidence: str, remediation: str, source: str = "misconfiguration_rules") -> dict[str, Any]:
    digest = hashlib.sha256(f"{rule}|{asset}|{json.dumps(evidence, sort_keys=True, default=str)[:400]}".encode()).hexdigest()[:16]
    return {"finding_id": f"misconfig-{digest}", "rule_id": rule, "type": rule, "title": title, "category": category, "severity": severity, "asset_id": asset,
            "evidence": evidence, "confidence": confidence, "recommended_remediation": remediation, "mitre_attack": techniques_for(category), "source": source}


def assess_misconfigurations(*, http_intelligence: dict[str, Any] | None = None, nmap: dict[str, Any] | None = None, imported: list[dict[str, Any]] | None = None, generated_at: str | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    checks_run: list[str] = []
    for obs in (http_intelligence or {}).get("observations", []) if isinstance(http_intelligence, dict) else []:
        if not isinstance(obs, dict) or not isinstance(obs.get("status_code"), int):
            continue
        checks_run.append("http_rules")
        url, host = str(obs.get("url") or ""), str(obs.get("hostname") or "")
        headers = obs.get("response_headers") if isinstance(obs.get("response_headers"), dict) else {}
        collected = obs.get("response_headers_status") == "observed"
        code = obs["status_code"]
        if collected and url.startswith("https://") and 200 <= code < 400:
            for header, label, hsts_only, remediation in _HEADER_CHECKS:
                if header not in headers:
                    findings.append(_finding(f"missing_{header.replace('-', '_')}", "missing_security_header", "LOW", url, f"{label} not observed", {"url": url, "status_code": code, "headers_collected": True}, "high", remediation))
            if "x-frame-options" not in headers and "frame-ancestors" not in str(headers.get("content-security-policy", "")).lower():
                findings.append(_finding("missing_clickjacking_protection", "missing_security_header", "LOW", url, "No X-Frame-Options or CSP frame-ancestors observed", {"url": url, "status_code": code}, "high", "Send X-Frame-Options or a CSP frame-ancestors directive."))
        if url.startswith("http://") and 200 <= code < 300:
            findings.append(_finding("http_served_without_https_redirect", "missing_security_header", "LOW", url, "Content served over plaintext HTTP without redirect", {"url": url, "status_code": code}, "high", "Redirect HTTP to HTTPS and enable HSTS."))
        if collected:
            server = str(headers.get("server", ""))
            if re.search(r"\d+\.\d+", server):
                findings.append(_finding("server_version_disclosure", "information_disclosure", "LOW", host or url, "Server header discloses a version", {"url": url, "server": server[:120]}, "high", "Remove or genericize version information from the Server header."))
            disclosed = {h: str(headers[h])[:120] for h in _DISCLOSURE_HEADERS if h in headers}
            if disclosed:
                findings.append(_finding("technology_header_disclosure", "information_disclosure", "LOW", host or url, "Technology/version headers disclosed", {"url": url, "headers": disclosed}, "high", "Suppress X-Powered-By/X-AspNet-Version style headers."))
        title = str(obs.get("title") or "")
        if title and _ADMIN_TITLE.search(title) and 200 <= code < 500:
            findings.append(_finding("admin_interface_exposed", "exposed_admin_interface", "MEDIUM", url, "Administrative or login interface reachable from the internet", {"url": url, "title": title[:120], "status_code": code}, "medium",
                                     "Restrict administrative interfaces to approved networks or place them behind VPN/SSO with MFA."))
    for host in (nmap or {}).get("hosts", []) if isinstance(nmap, dict) else []:
        if not isinstance(host, dict):
            continue
        checks_run.append("network_service_rules")
        for port in host.get("ports", []) if isinstance(host.get("ports"), list) else []:
            if not isinstance(port, dict) or port.get("state") != "open" or port.get("protocol", "tcp") != "tcp":
                continue
            rule = _EXPOSED_PORTS.get(port.get("port"))
            if rule:
                label, category, severity = rule
                asset = f"{host.get('address')}:{port.get('port')}"
                findings.append(_finding(f"exposed_{category}_{port.get('port')}", category, severity, asset, f"{label} reachable from the scan vantage point",
                                         {"ip": host.get("address"), "hostnames": host.get("hostnames", []), "port": port.get("port"), "service": port.get("service"), "product": port.get("product")}, "high",
                                         "Confirm a business need; restrict the service to approved source networks or a VPN, and require strong authentication."))
    for item in imported or []:
        findings.append(item)
    unique = {row["finding_id"]: row for row in findings}
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": generated_at, "status": "success" if checks_run or imported else "not_available",
            "rules_evaluated": sorted(set(checks_run)), "imported_findings": len(imported or []), "findings": sorted(unique.values(), key=lambda row: row["finding_id"]),
            "limitations": ["Only externally observed evidence is assessed; internal configuration was not inspected.", "Risky HTTP methods are not tested (GET-only policy); import authorized tool output for such checks.",
                            "Missing headers are reported only when response headers were actually collected.", "Weak TLS and DNS/email policy findings are produced by the certificate, DNS, and delivery modules."]}


def _severity(value: Any) -> str:
    text = str(value or "").strip().upper()
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "MODERATE": "MEDIUM", "LOW": "LOW", "INFO": "INFO", "INFORMATIONAL": "INFO", "OK": "INFO", "WARN": "LOW", "FATAL": "HIGH"}.get(text, "INFO")


def import_assessment_evidence(path: Path, *, tool: str, max_bytes: int = 20_000_000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Import findings from an authorized tool's output. Formats: generic JSON/CSV, Nuclei JSONL, testssl.sh JSON."""
    raw = path.read_bytes()
    if len(raw) > max_bytes:
        raise ValueError("Evidence file exceeds the import size limit.")
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8-sig")
    provenance = {"file": path.name, "sha256": digest, "tool": tool}
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    if path.suffix.lower() == ".csv":
        rows = list(csv.DictReader(io.StringIO(text)))
    elif path.suffix.lower() in {".jsonl", ".ndjson"}:
        for number, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    errors.append({"line": number, "error": "invalid_json"})
    else:
        data = json.loads(text)
        rows = data if isinstance(data, list) else data.get("scanResult", data.get("findings", [data])) if isinstance(data, dict) else []
    findings: list[dict[str, Any]] = []
    for index, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            errors.append({"record": index, "error": "record_not_object"})
            continue
        if "template-id" in row:  # Nuclei JSONL
            info = row.get("info") if isinstance(row.get("info"), dict) else {}
            asset, title, severity, rule = row.get("matched-at") or row.get("host"), info.get("name") or row["template-id"], info.get("severity"), f"nuclei:{row['template-id']}"
        elif "finding" in row and "id" in row and ("ip" in row or "port" in row):  # testssl.sh JSON
            asset, title, severity, rule = f"{row.get('ip')}:{row.get('port')}", f"{row['id']}: {row['finding']}", row.get("severity"), f"testssl:{row['id']}"
            if _severity(severity) == "INFO":
                continue
        else:
            asset, title, severity, rule = row.get("asset") or row.get("host") or row.get("target"), row.get("title") or row.get("name"), row.get("severity"), f"import:{row.get('rule_id') or row.get('id') or index}"
        if not asset or not title:
            errors.append({"record": index, "error": "missing_asset_or_title"})
            continue
        category = str(row.get("category") or ("weak_tls" if rule.startswith("testssl:") else "imported_misconfiguration"))
        findings.append(_finding(rule, category, _severity(severity), str(asset)[:300], str(title)[:300], {"original_record": redact(row), "record_number": index, **provenance}, "as_reported_by_tool",
                                 str(row.get("remediation") or "Review the imported finding with the responsible owner."), source=f"imported:{tool}"))
    return findings, {**provenance, "records": len(rows), "errors": errors}
