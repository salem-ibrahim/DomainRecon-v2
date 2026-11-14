"""Deterministic partial JSON/CSV/HTML reports over existing V2 artifacts (20 report sections).

Every artifact is optional: missing stages are ``not_run`` and never treated as clean results.
The whole report is passed through secret redaction before rendering, CSV cells are
formula-neutralized centrally, and HTML is fully escaped under a script-free CSP.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domainrecon import __version__
from domainrecon.core.csv_safe import render_csv
from domainrecon.core.errors import ArtifactExists
from domainrecon.core.redaction import redact
from domainrecon.core.scope import ScopePolicy
from domainrecon.core.storage import write_json_artifact, write_text_artifact

SCHEMA_ID = "domainrecon.unified_report"
SCHEMA_VERSION = 2
KILL_CHAIN_STAGE = {
    "engagement": "00 Engagement", "passive": "01 Reconnaissance", "dns": "01 Reconnaissance", "http": "01 Reconnaissance", "http_intelligence": "01 Reconnaissance",
    "nmap": "01 Reconnaissance", "database": "01 Reconnaissance", "dns_intelligence": "01 Reconnaissance", "wildcard_probe": "01 Reconnaissance", "asset_inventory": "01 Reconnaissance",
    "attack_surface": "01 Reconnaissance", "changes": "01 Reconnaissance", "certificates": "01 Reconnaissance", "technology": "01 Reconnaissance",
    "cloud": "01 Reconnaissance", "takeover": "01 Reconnaissance", "vulnerability": "02 Weaponization / Threat Intelligence",
    "delivery": "03 Delivery / Exposure Intelligence", "misconfiguration": "03 Delivery / Exposure Intelligence",
    "vulnerability_assessment": "04 Exploitation / Safe Vulnerability Assessment", "persistence": "05 Installation / Persistence Intelligence",
    "ad_assessment": "05 Installation / Persistence Intelligence", "c2": "06 Command and Control Intelligence",
    "impact": "07 Actions on Objectives / Impact Analysis", "correlation": "07 Actions on Objectives / Impact Analysis", "mitre": "07 Actions on Objectives / Impact Analysis",
    "lifecycle": "07 Actions on Objectives / Impact Analysis",
}
_STAGE_KEYS = tuple(KILL_CHAIN_STAGE)
# Derived stages re-describe findings from other stages; they are reported in their own sections, not double counted.
# The wildcard probe is raw evidence (random-label DNSx answers); its findings are produced only by dns_intelligence.
# The unified report itself is never an input (it would nest reports recursively).
_DERIVED_STAGES = frozenset({"impact", "correlation", "mitre", "lifecycle", "engagement", "wildcard_probe"})
REPORT_SECTIONS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("executive_summary", "1. Executive Summary", ()),
    ("engagement_scope", "2. Engagement Scope", ("engagement",)),
    ("asset_inventory", "3. Asset Inventory", ("asset_inventory", "passive")),
    ("external_attack_surface", "4. External Attack Surface", ("attack_surface", "delivery", "changes")),
    ("dns_security", "5. DNS Security", ("dns_intelligence", "dns", "wildcard_probe")),
    ("http_tls", "6. HTTP/TLS Assessment", ("http", "http_intelligence", "certificates")),
    ("network_services", "7. Network Services", ("nmap", "database")),
    ("technology_inventory", "8. Technology Inventory", ("technology",)),
    ("cloud_intelligence", "9. Cloud Intelligence", ("cloud",)),
    ("vulnerability_findings", "10. Vulnerability Findings", ("vulnerability", "vulnerability_assessment")),
    ("security_misconfigurations", "11. Security Misconfigurations", ("misconfiguration",)),
    ("takeover_indicators", "12. Takeover Indicators", ("takeover",)),
    ("threat_intelligence", "13. Threat Intelligence and Imported Evidence", ("c2", "persistence", "ad_assessment")),
    ("attack_paths", "14. Attack Path Analysis", ("correlation",)),
    ("mitre_attack", "15. MITRE ATT&CK Mapping", ("mitre",)),
    ("business_impact", "16. Business Impact", ("impact",)),
    ("remediation", "17. Remediation Recommendations", ()),
    ("limitations", "18. Limitations and Unverified Findings", ()),
    ("timeline", "19. Assessment Timeline", ()),
    ("evidence_references", "20. Evidence References", ()),
)


def _finding_asset(finding: dict[str, Any]) -> str:
    """Return the asset a finding refers to, regardless of which analyzer produced it."""
    for key in ("asset_identifier", "hostname", "asset_id", "matched_asset", "host", "ip_address", "asset"):
        value = finding.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _level(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("level")
    return str(value).upper() if isinstance(value, (str, int, float)) and str(value) else None


def _timestamp(payload: dict[str, Any]) -> str | None:
    for key in ("timestamp", "generated_at", "started_at_utc"):
        if isinstance(payload.get(key), str) and payload[key] not in ("fixed",):
            return payload[key]
    return None


def build_unified_report(scope: ScopePolicy, artifacts: dict[str, Any], *, run_id: str, generated_at: str | None = None, timeline: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Build a reproducible partial report; absent artifacts are marked not_run."""
    if not isinstance(run_id, str) or not run_id:
        raise ValueError("run_id must be a non-empty string.")
    stages: dict[str, dict[str, Any]] = {}
    all_findings: list[dict[str, Any]] = []
    all_evidence: list[dict[str, Any]] = []
    for name in _STAGE_KEYS:
        payload = artifacts.get(name)
        if payload is None:
            stages[name] = {"status": "not_run", "artifact_available": False, "kill_chain_stage": KILL_CHAIN_STAGE[name]}
            continue
        if not isinstance(payload, dict):
            stages[name] = {"status": "invalid_input", "artifact_available": False, "kill_chain_stage": KILL_CHAIN_STAGE[name]}
            continue
        target = payload.get("root_domain", payload.get("target"))
        if target is not None and target != scope.root_domain:
            raise ValueError(f"{name} artifact belongs to a different target.")
        artifact_ref = payload.get("artifact_path") or payload.get("source_artifact") or name
        stages[name] = {"status": str(payload.get("status", "success")), "artifact_available": True, "source": artifact_ref, "kill_chain_stage": KILL_CHAIN_STAGE[name], "input_stages": payload.get("input_stages", [])}
        if name not in _DERIVED_STAGES:
            for row in payload.get("findings", []) if isinstance(payload.get("findings"), list) else []:
                if isinstance(row, dict):
                    provenance = {"stage": name, "kill_chain_stage": KILL_CHAIN_STAGE[name], "source_artifact": artifact_ref, "source_run_id": payload.get("run_id", run_id)}
                    all_findings.append({**row, **provenance, "asset_identifier": row.get("asset_identifier", _finding_asset(row))})
        evidence = payload.get("evidence", [])
        if isinstance(evidence, list):
            all_evidence.extend({"stage": name, **row} for row in evidence if isinstance(row, dict))
    assets = artifacts.get("asset_inventory", {}).get("assets", []) if isinstance(artifacts.get("asset_inventory"), dict) else []
    severity_counts: dict[str, int] = {}
    for finding in all_findings:
        severity = _level(finding.get("severity"))
        if severity:
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    kill_chain_coverage: dict[str, list[str]] = {}
    for name, state in stages.items():
        if state["artifact_available"]:
            kill_chain_coverage.setdefault(KILL_CHAIN_STAGE[name], []).append(name)
    impact = artifacts.get("impact") if isinstance(artifacts.get("impact"), dict) else None
    correlation = artifacts.get("correlation") if isinstance(artifacts.get("correlation"), dict) else None
    canonical = correlation.get("canonical_findings", []) if correlation else []
    remediation: dict[str, dict[str, Any]] = {}
    for finding in list(canonical) + all_findings:
        text = finding.get("recommended_remediation") or finding.get("remediation")
        if isinstance(text, dict):
            text = text.get("guidance")
        if isinstance(text, str) and text.strip():
            entry = remediation.setdefault(text.strip(), {"recommendation": text.strip(), "finding_ids": [], "highest_priority": finding.get("priority", "P4"), "assets": []})
            entry["finding_ids"].append(finding.get("finding_id"))
            asset = _finding_asset(finding)
            if asset and asset not in entry["assets"]:
                entry["assets"].append(asset)
            entry["highest_priority"] = min(entry["highest_priority"], finding.get("priority", "P4"))
    unverified = [{"finding_id": f.get("finding_id"), "stage": f.get("stage"), "reason": reason} for f in all_findings for reason in [
        "candidate CVE match" if f.get("match_type") == "candidate_match" else "imported tool assertion" if f.get("confidence") == "as_reported_by_tool"
        else "takeover indicator (no claim attempted)" if f.get("category") == "subdomain_takeover" else None] if reason]
    if correlation:
        unverified += [{"path_id": path["path_id"], "reason": path["verification_status"]} for path in correlation.get("attack_paths", []) if path.get("verification_status") != "verified_by_imported_evidence"]
    stage_limitations = {name: payload.get("limitations") for name, payload in artifacts.items() if isinstance(payload, dict) and isinstance(payload.get("limitations"), list) and name in KILL_CHAIN_STAGE}
    events = [{"at": _timestamp(payload), "event": f"{name} artifact generated", "artifact": payload.get("artifact_path", name)} for name, payload in artifacts.items() if isinstance(payload, dict) and name in KILL_CHAIN_STAGE and _timestamp(payload)]
    for record in timeline or []:
        if isinstance(record, dict):
            events.append({"at": record.get("authorized_at_utc") or record.get("at"), "event": f"authorization {record.get('result')}: {record.get('operation')}", "artifact": record.get("record_id")})
    events.sort(key=lambda item: str(item.get("at")))
    references = [{"stage": name, "kill_chain_stage": KILL_CHAIN_STAGE[name], "artifact": state.get("source"), "status": state["status"]} for name, state in stages.items() if state["artifact_available"]]
    sections: dict[str, Any] = {}
    for key, _title, stage_names in REPORT_SECTIONS:
        if stage_names:
            sections[key] = {name: artifacts.get(name) if artifacts.get(name) is not None else {"status": "not_run", "available": False} for name in stage_names}
    sections["attack_paths"] = {"hypotheses": correlation.get("attack_paths", []) if correlation else [], "canonical_findings": canonical, "status": "available" if correlation else "not_run"}
    mitre = artifacts.get("mitre") if isinstance(artifacts.get("mitre"), dict) else None
    sections["mitre_attack"] = {"matrix": (mitre or {}).get("matrix") or (correlation or {}).get("attack_matrix") or {}, "status": "available" if mitre or correlation else "not_run"}
    sections["remediation"] = sorted(remediation.values(), key=lambda row: (row["highest_priority"], row["recommendation"]))
    sections["limitations"] = {"unverified_items": unverified, "stage_limitations": stage_limitations, "missing_stages": [name for name, state in stages.items() if not state["artifact_available"]]}
    sections["timeline"] = events
    sections["evidence_references"] = references
    engagement = artifacts.get("engagement") if isinstance(artifacts.get("engagement"), dict) else None
    report = {
        "schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "project_version": __version__,
        "target": scope.root_domain, "root_domain": scope.root_domain, "run_id": run_id,
        "stage": "actions_on_objectives", "module": "unified_report",
        "timestamp": generated_at or datetime.now(timezone.utc).isoformat(),
        "status": "partial" if any(x["status"] != "success" for x in stages.values()) else "complete",
        "source": "available_v2_artifacts", "stages": stages,
        "engagement_scope": {"root_domain": scope.root_domain, "excluded_hostnames": sorted(scope.excluded_hostnames), "excluded_networks": list(scope.excluded_networks),
                             "authorized_networks": list(scope.authorized_networks), "engagement": (engagement or {}).get("name"), "operations": (engagement or {}).get("operations")},
        "executive_summary": {
            "asset_count": len(assets) if isinstance(assets, list) else 0, "finding_count": len(all_findings), "canonical_finding_count": len(canonical),
            "observed_stages": sum(1 for x in stages.values() if x["artifact_available"]), "kill_chain_coverage": dict(sorted(kill_chain_coverage.items())),
            "priority_counts": (correlation or {}).get("priority_counts", {}), "attack_path_hypotheses": len((correlation or {}).get("attack_paths", [])),
            "risk_summary": {"observed_severity_counts": severity_counts, "interpretation": "Severity is source-reported intelligence; it is not a claim of confirmed exploitability."},
            "impact_summary": impact.get("executive_summary") if impact else {"status": "not_run"},
        },
        "assets": assets if isinstance(assets, list) else [], "findings": all_findings, "evidence": all_evidence, "sections": sections,
        "limitations": [f"{name} was not run or has no artifact." for name, stage in stages.items() if not stage["artifact_available"]],
    }
    report["source_artifacts"] = sorted(name for name in _STAGE_KEYS if artifacts.get(name) is not None)
    return redact(report)


def render_report_csv(report: dict[str, Any]) -> str:
    fields = ["record_type", "stage", "kill_chain_stage", "source_artifact", "asset_id", "asset_type", "fqdn", "ip_address", "current_status", "discovery_sources", "services", "technologies", "findings",
              "finding_id", "cve_id", "category", "severity", "title", "asset_identifier", "confidence", "priority", "priority_score", "evidence_references", "evidence"]
    rows: list[dict[str, Any]] = []
    for asset in report.get("assets", []):
        if isinstance(asset, dict):
            rows.append({**{key: asset.get(key) for key in fields if key != "record_type"}, "record_type": "asset"})
    for finding in report.get("findings", []):
        if not isinstance(finding, dict):
            continue
        row = {key: finding.get(key) for key in fields if key != "record_type"}
        row.update({"record_type": "finding", "asset_identifier": finding.get("asset_identifier", _finding_asset(finding)), "severity": _level(finding.get("severity")),
                    "confidence": _level(finding.get("confidence")) or _level(finding.get("match_confidence")), "evidence_references": finding.get("evidence_references", finding.get("references", []))})
        rows.append(row)
    for finding in report.get("sections", {}).get("attack_paths", {}).get("canonical_findings", []):
        if isinstance(finding, dict):
            rows.append({"record_type": "canonical_finding", "finding_id": finding.get("finding_id"), "category": finding.get("category"), "severity": finding.get("severity"),
                         "title": finding.get("title"), "asset_identifier": finding.get("asset_id"), "confidence": finding.get("confidence"), "priority": finding.get("priority"),
                         "priority_score": (finding.get("risk") or {}).get("score"), "evidence_references": finding.get("evidence_references"), "stage": ",".join(finding.get("sources", []))})
    # Every cell (including remote titles, headers, URLs and imported evidence) is neutralized centrally.
    return render_csv(fields, rows)


def render_report_html(report: dict[str, Any]) -> str:
    """Render a self-contained HTML report; every dynamic value is HTML-escaped; no scripts are allowed by CSP."""
    esc = lambda value: html.escape(str(value), quote=True)
    dump = lambda value: f"<pre>{esc(json.dumps(value, indent=2, sort_keys=True, default=str))}</pre>"
    summary = report.get("executive_summary", {})
    sections = report.get("sections", {}) if isinstance(report.get("sections"), dict) else {}
    assets = report.get("assets", []) if isinstance(report.get("assets"), list) else []
    findings = report.get("findings", []) if isinstance(report.get("findings"), list) else []

    def label(f: dict[str, Any]) -> str:
        for key in ("title", "type", "classification", "persistence_category", "cve_id", "ioc_value", "finding_id"):
            if f.get(key):
                return str(f[key])
        return "finding"

    stage_rows = "".join(f"<tr><td>{esc(state.get('kill_chain_stage', ''))}</td><td>{esc(name)}</td><td>{esc(state.get('status'))}</td><td>{esc(state.get('source', '')) if state.get('artifact_available') else 'no'}</td></tr>"
                         for name, state in sorted(report.get("stages", {}).items(), key=lambda item: (str(item[1].get("kill_chain_stage", "")), item[0])) if isinstance(state, dict))
    asset_rows = "".join(f"<tr><td>{esc(a.get('fqdn', a.get('ip_address', a.get('asset_id'))))}</td><td>{esc(a.get('asset_type'))}</td><td>{esc(', '.join(a.get('ip_addresses', [])) if isinstance(a.get('ip_addresses'), list) else a.get('ip_address', ''))}</td><td>{esc(a.get('current_status', ''))}</td></tr>" for a in assets if isinstance(a, dict))
    finding_rows = "".join(
        f"<tr><td>{esc(f.get('kill_chain_stage', ''))}</td><td>{esc(label(f))}</td><td>{esc(f.get('asset_identifier') or _finding_asset(f))}</td><td>{esc(_level(f.get('severity')) or '')}</td>"
        f"<td>{esc(_level(f.get('confidence')) or _level(f.get('match_confidence')) or 'UNKNOWN')}</td><td>{esc(f.get('source_artifact', ''))}</td><td>{dump(f.get('evidence', {}))}</td></tr>"
        for f in findings if isinstance(f, dict))
    remediation_rows = "".join(f"<tr><td>{esc(r.get('highest_priority'))}</td><td>{esc(r.get('recommendation'))}</td><td>{esc(', '.join(r.get('assets', [])[:10]))}</td><td>{esc(len(r.get('finding_ids', [])))}</td></tr>" for r in sections.get("remediation", []) if isinstance(r, dict))
    timeline_rows = "".join(f"<tr><td>{esc(e.get('at'))}</td><td>{esc(e.get('event'))}</td><td>{esc(e.get('artifact'))}</td></tr>" for e in sections.get("timeline", []) if isinstance(e, dict))
    body = []
    for key, title, _stages in REPORT_SECTIONS:
        if key == "executive_summary":
            body.append(f"<h2>{esc(title)}</h2><p>{esc(summary.get('asset_count', 0))} assets; {esc(summary.get('finding_count', 0))} findings ({esc(summary.get('canonical_finding_count', 0))} after correlation); "
                        f"{esc(summary.get('observed_stages', 0))} stages with artifacts. Report status: <strong>{esc(report.get('status'))}</strong>.</p>{dump(summary)}"
                        f"<table><thead><tr><th>Kill Chain Stage</th><th>Module</th><th>Status</th><th>Artifact</th></tr></thead><tbody>{stage_rows}</tbody></table>")
        elif key == "engagement_scope":
            body.append(f"<h2>{esc(title)}</h2>{dump(report.get('engagement_scope', {}))}{dump(sections.get(key, {}))}")
        elif key == "asset_inventory":
            body.append(f"<h2>{esc(title)}</h2><table><thead><tr><th>Asset</th><th>Type</th><th>Addresses</th><th>Status</th></tr></thead><tbody>{asset_rows or '<tr><td colspan=4>No asset artifact available.</td></tr>'}</tbody></table>")
        elif key == "remediation":
            body.append(f"<h2>{esc(title)}</h2><table><thead><tr><th>Priority</th><th>Recommendation</th><th>Assets</th><th>Findings</th></tr></thead><tbody>{remediation_rows or '<tr><td colspan=4>No remediation recorded.</td></tr>'}</tbody></table>")
        elif key == "timeline":
            body.append(f"<h2>{esc(title)}</h2><table><thead><tr><th>Time (UTC)</th><th>Event</th><th>Reference</th></tr></thead><tbody>{timeline_rows or '<tr><td colspan=3>No timeline events.</td></tr>'}</tbody></table>")
        elif key == "limitations":
            limits = "".join(f"<li>{esc(x)}</li>" for x in report.get("limitations", []) if isinstance(x, str)) or "<li>None recorded.</li>"
            body.append(f"<h2>{esc(title)}</h2><p>Limitations and Missing Data:</p><ul>{limits}</ul>{dump(sections.get(key, {}))}")
        else:
            body.append(f"<h2>{esc(title)}</h2>{dump(sections.get(key, {'status': 'not_run'}))}")
    body.append(f"<h2>All Findings and Evidence</h2><table><thead><tr><th>Kill Chain Stage</th><th>Finding</th><th>Asset</th><th>Severity</th><th>Confidence</th><th>Source Artifact</th><th>Evidence</th></tr></thead><tbody>{finding_rows or '<tr><td colspan=7>No findings reported.</td></tr>'}</tbody></table>")
    style = "body{font:15px system-ui,sans-serif;max-width:1200px;margin:2rem auto;padding:0 1rem;color:#172033}table{border-collapse:collapse;width:100%;margin:1rem 0 2rem}td,th{border:1px solid #bcc5d3;padding:.5rem;text-align:left;vertical-align:top}th{background:#edf2f8}pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:40rem;overflow:auto}.muted{color:#546174}"
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
            f"<title>DomainRecon report - {esc(report.get('target'))}</title><style>{style}</style></head><body><h1>DomainRecon V2 Security Assessment Report</h1>"
            f"<p>Target: <code>{esc(report.get('target'))}</code> | Run: <code>{esc(report.get('run_id'))}</code> | Generated: {esc(report.get('timestamp'))}</p>{''.join(body)}"
            f"<p class=\"muted\">Observed facts, inferred attributions, candidate matches and theoretical attack paths are labelled separately; absence of an artifact is not evidence of absence. Secrets are redacted.</p></body></html>")


def render_report_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"


def write_report_artifacts(directory: Path, report: dict[str, Any], *, stem: str = "unified_report") -> dict[str, Path]:
    """Create three immutable sibling report files; fail rather than overwrite."""
    report = redact(report)
    json_path = write_json_artifact(directory, f"{stem}.json", json.loads(json.dumps(report, default=str)))
    csv_path = write_text_artifact(directory, f"{stem}.csv", render_report_csv(report))
    html_path = directory / f"{stem}.html"
    try:
        with html_path.open("x", encoding="utf-8", newline="") as handle:
            handle.write(render_report_html(report))
    except FileExistsError as exc:
        raise ArtifactExists(f"Report already exists: {html_path}") from exc
    return {"json": json_path, "csv": csv_path, "html": html_path}
