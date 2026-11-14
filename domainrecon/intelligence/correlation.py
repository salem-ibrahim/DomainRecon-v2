"""Attack-path and risk correlation across every stage's findings.

Builds Assets -> DNS -> IPs -> Services -> Technologies -> CVEs -> Findings -> Business-impact
relationships on top of the attack-surface graph, deduplicates findings into canonical records
with stable ``DRF-`` identifiers, scores risk with explicit inputs, and emits attack-path
*hypotheses*. Hypotheses are theoretical unless an imported record explicitly states
``verified: true``; DomainRecon never exploits anything to test them.
"""
from __future__ import annotations

import hashlib
from typing import Any

from domainrecon.core.scope import ScopePolicy
from domainrecon.intelligence.attack_surface import build_attack_surface
from domainrecon.intelligence.mitre_mapping import TECHNIQUES, _finding_techniques, build_attack_matrix

SCHEMA_ID = "domainrecon.risk_correlation"
SCHEMA_VERSION = 1
SEVERITY_WEIGHT = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.5}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.7, "low": 0.4, "as_reported_by_tool": 0.8}
CRITICALITY_FACTOR = {"CRITICAL": 1.5, "HIGH": 1.25, "MEDIUM": 1.0, "LOW": 0.75, "UNKNOWN": 1.0}
FINDING_STAGES = ("dns_intelligence", "http_intelligence", "vulnerability", "vulnerability_assessment", "delivery", "certificates", "takeover", "misconfiguration", "ad_assessment", "persistence", "c2")
_REMOTE_PORTS = {22, 23, 3389, 5900, 5985, 5986, 445}


def _level(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("level")
    return str(value or "").upper()


def _asset(finding: dict[str, Any]) -> str:
    for key in ("asset_id", "hostname", "matched_asset", "host", "ip_address", "asset"):
        if isinstance(finding.get(key), str) and finding[key]:
            return finding[key]
    if finding.get("ip_address") and finding.get("port"):
        return f"{finding['ip_address']}:{finding['port']}"
    return "unattributed"


def _dedupe_key(stage: str, finding: dict[str, Any]) -> str:
    kind = finding.get("category") or finding.get("type") or finding.get("persistence_category") or stage
    specific = finding.get("cve_id") or finding.get("certificate_id") or finding.get("ioc_value") or finding.get("rule_id") or finding.get("classification") or ""
    if stage == "vulnerability_assessment":
        stage_kind = "vulnerable_software"  # same CVE on same asset as Stage 02 -> same canonical finding
        return f"{stage_kind}|{_asset(finding)}|{specific}"
    if stage == "vulnerability":
        return f"vulnerable_software|{_asset(finding)}|{specific}"
    return f"{kind}|{_asset(finding)}|{specific}"


def canonical_findings(artifacts: dict[str, Any], criticality: dict[str, str] | None = None, public_assets: set[str] | None = None) -> list[dict[str, Any]]:
    """Merge findings from all stages into canonical, deduplicated, risk-scored records."""
    merged: dict[str, dict[str, Any]] = {}
    for stage in FINDING_STAGES:
        payload = artifacts.get(stage)
        if not isinstance(payload, dict):
            continue
        for finding in payload.get("findings", []) if isinstance(payload.get("findings"), list) else []:
            if not isinstance(finding, dict):
                continue
            severity = _level(finding.get("severity")) or ("HIGH" if (finding.get("cvss_score") or 0) >= 7 else "MEDIUM" if finding.get("cve_id") else "INFO")
            if severity not in SEVERITY_WEIGHT:
                severity = "INFO"
            key = _dedupe_key(stage, finding)
            canonical_id = "DRF-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
            confidence = str(_level(finding.get("confidence")) or str(finding.get("match_confidence") or "low")).lower()
            row = merged.setdefault(canonical_id, {
                "finding_id": canonical_id, "dedupe_key": key, "title": finding.get("title") or finding.get("type") or finding.get("cve_id") or finding.get("persistence_category") or stage,
                "category": finding.get("category") or ("vulnerable_software" if finding.get("cve_id") else finding.get("type")), "asset_id": _asset(finding),
                "severity": severity, "confidence": confidence, "sources": [], "source_finding_ids": [], "mitre_attack": [], "evidence_references": [],
                "verified": False, "recommended_remediation": finding.get("recommended_remediation") or (finding.get("remediation") or {}).get("guidance") if isinstance(finding.get("remediation"), dict) else finding.get("recommended_remediation") or finding.get("remediation"),
            })
            if SEVERITY_WEIGHT[severity] > SEVERITY_WEIGHT[row["severity"]]:
                row["severity"] = severity
            if CONFIDENCE_FACTOR.get(confidence, 0.5) > CONFIDENCE_FACTOR.get(row["confidence"], 0.5):
                row["confidence"] = confidence
            if stage not in row["sources"]:
                row["sources"].append(stage)
            row["source_finding_ids"].append(str(finding.get("finding_id", "")))
            row["evidence_references"].append({"stage": stage, "artifact": payload.get("artifact_path", stage), "finding_id": finding.get("finding_id")})
            row["verified"] = row["verified"] or finding.get("verified") is True
            for technique in _finding_techniques(finding):
                if technique not in row["mitre_attack"]:
                    row["mitre_attack"].append(technique)
            if finding.get("cve_id"):
                row["cve_id"] = finding["cve_id"]
                row["match_type"] = finding.get("match_type") or row.get("match_type")
    for row in merged.values():
        crit = (criticality or {}).get(row["asset_id"], "UNKNOWN")
        exposed = row["asset_id"] in (public_assets or set()) or any(part in (public_assets or set()) for part in row["asset_id"].split(":")[:1])
        score = SEVERITY_WEIGHT[row["severity"]] * CONFIDENCE_FACTOR.get(row["confidence"], 0.5) * CRITICALITY_FACTOR.get(crit, 1.0) * (1.0 if exposed else 0.8)
        row["risk"] = {"score": round(min(score, 10.0), 2), "scale": "0-10", "inputs": {"severity": row["severity"], "confidence": row["confidence"], "asset_criticality": crit, "publicly_observed": exposed},
                       "formula": "severity weight x confidence factor x criticality factor x exposure factor (capped at 10)"}
        row["priority"] = "P1" if row["risk"]["score"] >= 7 else "P2" if row["risk"]["score"] >= 4 else "P3" if row["risk"]["score"] >= 1.5 else "P4"
    return sorted(merged.values(), key=lambda row: (-row["risk"]["score"], row["finding_id"]))


def _path(path_id: str, title: str, steps: list[str], techniques: list[str], findings: list[dict[str, Any]], confidence: str) -> dict[str, Any]:
    verified = all(f.get("verified") for f in findings) and findings
    return {"path_id": path_id, "title": title, "steps": steps, "techniques": [{"technique_id": t, "technique_name": TECHNIQUES[t][0], "tactic": TECHNIQUES[t][1]} for t in techniques],
            "supporting_finding_ids": [f["finding_id"] for f in findings], "verification_status": "verified_by_imported_evidence" if verified else "theoretical_unverified", "confidence": confidence}


def attack_path_hypotheses(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_category: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        by_category.setdefault(str(finding.get("category")), []).append(finding)
    paths: list[dict[str, Any]] = []
    for finding in by_category.get("vulnerable_software", []):
        if finding.get("match_type") in {"exact_cpe_match", "version_range_match"} or finding["severity"] in {"HIGH", "CRITICAL"}:
            paths.append(_path(f"AP-{finding['finding_id'][4:]}-exploit", f"Exploitation of public-facing software on {finding['asset_id']} ({finding.get('cve_id')})",
                               [f"asset {finding['asset_id']}", "exposed service", f"{finding.get('cve_id')} applicability", "initial access"], ["T1190"], [finding], "medium" if finding.get("match_type") == "exact_cpe_match" else "low"))
    remote = [f for f in by_category.get("exposed_remote_service", []) if f["severity"] != "INFO"]
    weak_passwords = by_category.get("weak_password_policy", [])
    for finding in remote:
        support = [finding] + weak_passwords[:1]
        paths.append(_path(f"AP-{finding['finding_id'][4:]}-remote", f"Credential attack against exposed remote service {finding['asset_id']}",
                           [f"exposed service {finding['asset_id']}", "password guessing/spraying" + (" (weak AD password policy imported)" if weak_passwords else ""), "valid account access"], ["T1133", "T1110"], support, "medium" if weak_passwords else "low"))
    for finding in by_category.get("subdomain_takeover", []):
        if "strong" in str(finding.get("title", "")) or finding["severity"] in {"HIGH", "MEDIUM"}:
            paths.append(_path(f"AP-{finding['finding_id'][4:]}-takeover", f"Subdomain takeover of {finding['asset_id']} enabling phishing or session theft",
                               [f"dangling alias {finding['asset_id']}", "third party claims resource", "content served on trusted subdomain"], ["T1584.001", "T1566"], [finding], "low"))
    for finding in by_category.get("email_spoofing_risk", []) + [f for f in by_category.get("email_policy_configuration", [])]:
        paths.append(_path(f"AP-{finding['finding_id'][4:]}-spoof", "Email spoofing of the organization's domain", ["weak/absent DMARC enforcement", "spoofed sender", "phishing delivery"], ["T1566"], [finding], "low"))
    ad_escalation = by_category.get("kerberoasting", []) + by_category.get("adcs", []) + by_category.get("kerberos_delegation", [])
    if ad_escalation and by_category.get("privileged_account_exposure"):
        support = ad_escalation[:2] + by_category["privileged_account_exposure"][:1]
        paths.append(_path("AP-ad-escalation", "Active Directory privilege escalation via imported Kerberos/AD CS weaknesses", ["domain user", "ticket/certificate abuse", "privileged account"], ["T1558.003", "T1649", "T1078.002"], support, "medium"))
    for finding in by_category.get("ioc_match", []):
        paths.append(_path(f"AP-{finding['finding_id'][4:]}-ioc", f"Possible existing compromise involving {finding['asset_id']} (IOC match)", ["IOC match", "investigate asset"], ["T1071"], [finding], "low"))
    return paths


def correlate(scope: ScopePolicy, artifacts: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    impact = artifacts.get("impact") if isinstance(artifacts.get("impact"), dict) else {}
    criticality = {row.get("asset_id"): row.get("asset_criticality") for row in impact.get("findings", []) if isinstance(row, dict) and row.get("asset_criticality") not in (None, "UNKNOWN")}
    public_assets: set[str] = set()
    for host in (artifacts.get("nmap") or {}).get("hosts", []) if isinstance(artifacts.get("nmap"), dict) else []:
        if isinstance(host, dict) and host.get("address"):
            public_assets.add(host["address"])
            public_assets.update(host.get("hostnames", []))
    for row in (artifacts.get("http") or {}).get("records", []) if isinstance(artifacts.get("http"), dict) else []:
        if isinstance(row, dict) and row.get("status") == "success":
            public_assets.update(str(row.get(key)) for key in ("hostname", "url", "ip") if row.get(key))
    c2 = artifacts.get("c2")
    if isinstance(c2, dict):
        # IOC matches are leads; give them a category/severity for correlation without mutating the stored artifact.
        artifacts = {**artifacts, "c2": {**c2, "findings": [{"category": "ioc_match", "severity": "HIGH", **match} for match in c2.get("findings", []) if isinstance(match, dict)]}}
    findings = canonical_findings(artifacts, criticality, public_assets)
    base = build_attack_surface(scope, passive=artifacts.get("passive"), dns=artifacts.get("dns"), http=artifacts.get("http"), nmap=artifacts.get("nmap"), database=artifacts.get("database"), assets=artifacts.get("asset_inventory"))
    nodes = {node["id"]: node for node in base["nodes"]}
    relations = list(base["relations"])
    for tech in (artifacts.get("technology") or {}).get("technologies", []) if isinstance(artifacts.get("technology"), dict) else []:
        tid = f"technology:{tech['product'].lower()}"
        nodes.setdefault(tid, {"id": tid, "type": "technology", "label": tech["product"], "category": tech.get("category")})
        owner = tech["asset"]
        source = f"service:{owner.split(':')[0]}:tcp:{owner.split(':')[1]}" if owner.count(":") == 1 and owner.split(":")[1].isdigit() else f"host:{owner}"
        nodes.setdefault(source, {"id": source, "type": "service" if source.startswith("service:") else "host", "label": owner})
        relations.append({"type": "USES_TECHNOLOGY", "source": source, "target": tid, "evidence": ",".join(tech.get("sources", []))})
    for finding in findings:
        fid = f"finding:{finding['finding_id']}"
        nodes[fid] = {"id": fid, "type": "finding", "label": finding["title"], "severity": finding["severity"], "risk_score": finding["risk"]["score"]}
        asset = finding["asset_id"]
        target = f"host:{asset}" if f"host:{asset}" in nodes else f"ip:{asset.split(':')[0]}" if f"ip:{asset.split(':')[0]}" in nodes else f"asset:{asset}"
        nodes.setdefault(target, {"id": target, "type": "asset", "label": asset})
        relations.append({"type": "HAS_FINDING", "source": target, "target": fid, "evidence": ",".join(finding["sources"])})
        if finding.get("cve_id"):
            cid = f"cve:{finding['cve_id']}"
            nodes.setdefault(cid, {"id": cid, "type": "cve", "label": finding["cve_id"]})
            relations.append({"type": "AFFECTED_BY", "source": target, "target": cid, "evidence": finding.get("match_type") or "candidate"})
        crit = finding["risk"]["inputs"]["asset_criticality"]
        if crit != "UNKNOWN":
            iid = f"impact:{crit}"
            nodes.setdefault(iid, {"id": iid, "type": "business_impact", "label": f"Owner criticality {crit}"})
            relations.append({"type": "BUSINESS_IMPACT", "source": target, "target": iid, "evidence": "owner criticality configuration"})
    paths = attack_path_hypotheses(findings)
    priorities: dict[str, int] = {}
    for finding in findings:
        priorities[finding["priority"]] = priorities.get(finding["priority"], 0) + 1
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "root_domain": scope.root_domain, "generated_at": generated_at, "status": "success" if findings or nodes else "not_available",
            "canonical_findings": findings, "duplicates_merged": sum(len(f["source_finding_ids"]) - 1 for f in findings), "priority_counts": priorities,
            "graph": {"nodes": sorted(nodes.values(), key=lambda n: n["id"]), "relations": relations}, "attack_paths": paths,
            "attack_matrix": build_attack_matrix(findings)["matrix"], "findings": [],
            "limitations": ["Attack paths are hypotheses built from findings; none was tested or exploited.", "Risk scores combine severity, confidence, owner criticality and observed exposure; they are prioritization aids, not likelihood estimates.",
                            "Duplicate detection merges findings that share category, asset, and identifying key (CVE, certificate, IOC, rule)."]}
