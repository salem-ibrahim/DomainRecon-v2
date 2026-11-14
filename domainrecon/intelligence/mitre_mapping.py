"""Central MITRE ATT&CK (Enterprise) mapping for DomainRecon finding types.

Mappings describe which adversary technique a *defensive* finding relates to (the technique the
weakness could enable or that the evidence indicates). They are analyst aids, not detections.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

ATTACK_VERSION_NOTE = "ATT&CK Enterprise technique identifiers; verify against the ATT&CK release used by your organization."
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1078.002": ("Valid Accounts: Domain Accounts", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
    "T1558": ("Steal or Forge Kerberos Tickets", "Credential Access"),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", "Credential Access"),
    "T1558.004": ("Steal or Forge Kerberos Tickets: AS-REP Roasting", "Credential Access"),
    "T1649": ("Steal or Forge Authentication Certificates", "Credential Access"),
    "T1134": ("Access Token Manipulation", "Privilege Escalation"),
    "T1484.001": ("Domain or Tenant Policy Modification: Group Policy Modification", "Privilege Escalation"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1482": ("Domain Trust Discovery", "Discovery"),
    "T1087.002": ("Account Discovery: Domain Account", "Discovery"),
    "T1592": ("Gather Victim Host Information", "Reconnaissance"),
    "T1590": ("Gather Victim Network Information", "Reconnaissance"),
    "T1584.001": ("Compromise Infrastructure: Domains", "Resource Development"),
    "T1583.001": ("Acquire Infrastructure: Domains", "Resource Development"),
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder", "Persistence"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1543.002": ("Create or Modify System Process: Systemd Service", "Persistence"),
    "T1098.004": ("Account Manipulation: SSH Authorized Keys", "Persistence"),
}
# finding category -> techniques (most specific first)
CATEGORY_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "exposed_remote_service": ("T1133", "T1110"),
    "exposed_admin_interface": ("T1190", "T1133"),
    "exposed_database_service": ("T1190",),
    "vulnerable_software": ("T1190",),
    "weak_tls": ("T1557",),
    "certificate_issue": ("T1557",),
    "missing_security_header": ("T1190",),
    "information_disclosure": ("T1592",),
    "email_spoofing_risk": ("T1566",),
    "dns_misconfiguration": ("T1590",),
    "subdomain_takeover": ("T1584.001", "T1566"),
    "ioc_match": ("T1071",),
    "kerberoasting": ("T1558.003",),
    "asrep_roasting": ("T1558.004",),
    "kerberos_delegation": ("T1558", "T1134"),
    "adcs": ("T1649",),
    "privileged_account_exposure": ("T1078.002", "T1087.002"),
    "excessive_permissions": ("T1098", "T1484.001"),
    "weak_password_policy": ("T1110",),
    "gpo_security": ("T1484.001",),
    "domain_trust": ("T1482",),
}


def techniques_for(category: str) -> list[dict[str, str]]:
    return [{"technique_id": tid, "technique_name": TECHNIQUES[tid][0], "tactic": TECHNIQUES[tid][1]} for tid in CATEGORY_TECHNIQUES.get(category, ())]


def _finding_techniques(finding: dict[str, Any]) -> list[dict[str, str]]:
    collected: list[dict[str, str]] = []
    for key in ("mitre_attack", "attack_techniques"):
        value = finding.get(key)
        rows = value if isinstance(value, list) else [value] if isinstance(value, dict) else []
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("technique_id"), str):
                tid = row["technique_id"]
                name, tactic = TECHNIQUES.get(tid, (row.get("technique_name", tid), row.get("tactic_name", row.get("tactic", "Unknown"))))
                collected.append({"technique_id": tid, "technique_name": name, "tactic": tactic})
    if not collected and isinstance(finding.get("category"), str):
        collected = techniques_for(finding["category"])
    return collected


def build_attack_matrix(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate mapped findings into a tactic -> technique -> finding-id matrix."""
    matrix: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    unmapped = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        techniques = _finding_techniques(finding)
        if not techniques:
            unmapped += 1
            continue
        for technique in techniques:
            cell = matrix[technique["tactic"]].setdefault(technique["technique_id"], {"technique_name": technique["technique_name"], "finding_ids": []})
            identifier = str(finding.get("finding_id", "unidentified"))
            if identifier not in cell["finding_ids"]:
                cell["finding_ids"].append(identifier)
    return {
        "schema_id": "domainrecon.mitre_attack_matrix", "schema_version": 1, "status": "success",
        "matrix": {tactic: dict(sorted(cells.items())) for tactic, cells in sorted(matrix.items())},
        "mapped_technique_count": sum(len(cells) for cells in matrix.values()), "unmapped_findings": unmapped,
        "findings": [], "limitations": [ATTACK_VERSION_NOTE, "A mapping states which technique a weakness could enable or evidence relates to; it is not a detection of adversary activity."],
    }
