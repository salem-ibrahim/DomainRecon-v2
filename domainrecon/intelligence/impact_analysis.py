"""Offline impact scoring with owner-provided criticality and explicit evidence references."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SCHEMA_ID = "domainrecon.impact_analysis"
SCHEMA_VERSION = 1
_CRITICALITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": None}


def _owner_rows(config: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if config is None:
        return {}
    if not isinstance(config, dict) or config.get("schema_version", 1) != 1:
        raise ValueError("Criticality configuration must be a version 1 JSON object.")
    rows = config.get("assets", [])
    if not isinstance(rows, list):
        raise ValueError("Criticality config assets must be a list.")
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("asset_id"), str) or not row["asset_id"].strip():
            raise ValueError("Each entry requires a non-empty asset_id.")
        criticality = str(row.get("criticality", "UNKNOWN")).upper()
        if criticality not in _CRITICALITY:
            raise ValueError(f"Unsupported criticality for {row['asset_id']}.")
        if not isinstance(row.get("source"), str) or not row["source"].strip():
            raise ValueError("Each owner classification requires source provenance.")
        cia = row.get("cia", {})
        if not isinstance(cia, dict):
            raise ValueError("cia must be an object.")
        ratings: dict[str, int | None] = {}
        for dimension in ("confidentiality", "integrity", "availability"):
            value = cia.get(dimension)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 5):
                raise ValueError(f"{dimension} CIA rating must be an integer from 1 to 5.")
            ratings[dimension] = value
        result[row["asset_id"]] = {"criticality": criticality, "criticality_value": _CRITICALITY[criticality], "cia": ratings, "source": row["source"][:256], "provided_at": row.get("provided_at"), "rationale": str(row.get("rationale", ""))[:1000]}
    return result


def analyze_impact(artifacts: dict[str, Any], config: dict[str, Any] | None = None, *, run_id: str | None = None, generated_at: str | None = None) -> dict[str, Any]:
    """Score potential impact from owner ratings; no criticality is inferred from technical data."""
    if not isinstance(artifacts, dict):
        raise ValueError("artifacts must be an object.")
    owners = _owner_rows(config)
    findings: list[dict[str, Any]] = []
    for stage, payload in artifacts.items():
        if not isinstance(payload, dict):
            continue
        if payload.get("status") in {"failed", "invalid_input"}:
            continue
        for item in payload.get("findings", []) if isinstance(payload.get("findings"), list) else []:
            if not isinstance(item, dict):
                continue
            asset = next((item[key] for key in ("asset_id", "hostname", "matched_asset", "host", "ip_address") if isinstance(item.get(key), str) and item[key]), None)
            owner = owners.get(asset, {})
            criticality = owner.get("criticality", "UNKNOWN")
            cia = owner.get("cia", {"confidentiality": None, "integrity": None, "availability": None})
            dimensions = {key: owner.get("criticality_value") * value if owner.get("criticality_value") is not None and value is not None else None for key, value in cia.items()}
            scores = [score for score in dimensions.values() if isinstance(score, int)]
            overall = max(scores) if scores else None
            refs = item.get("evidence_references", item.get("evidence", []))
            source_severity = str(item.get("severity", {}).get("level") if isinstance(item.get("severity"), dict) else item.get("severity") or "").upper()
            priority = "review_owner_rating" if overall is None else "high" if overall >= 20 else "medium" if overall >= 12 else "low"
            # Owner impact estimates never raise a low-severity observation above its own evidence weight.
            cap = {"INFO": "low", "INFORMATIONAL": "low", "LOW": "medium"}.get(source_severity)
            if cap and priority in {"high", "medium"} and (cap == "low" or priority == "high"):
                priority = cap
            observed = {"stage": stage, "finding_id": item.get("finding_id"), "classification": item.get("classification", item.get("type")), "source_severity": item.get("severity"), "source": item.get("source")}
            findings.append({"asset_id": asset, "observed_finding": observed, "evidence_references": refs, "estimated_impact": {"status": "estimated_from_owner_input" if overall is not None else "not_assessed", "cia_dimension_scores": dimensions, "score": overall, "scale": "1-25 per CIA dimension", "formula": "owner criticality (1-5) × owner CIA rating (1-5); overall=max(known dimensions)", "assumptions": ["Owner-provided ratings are current and accurate."] if overall is not None else []}, "asset_criticality": criticality, "criticality_provenance": owner.get("source"), "confidence": "medium" if overall is not None and refs else "low" if overall is not None else "unknown", "priority": priority, "priority_inputs": {"owner_impact_score": overall, "source_severity": source_severity or None, "severity_cap": cap}})
    coverage = {key: {"status": payload.get("status", "available"), "artifact_available": True, "usable": payload.get("status") not in {"failed", "invalid_input"}} for key, payload in artifacts.items() if isinstance(payload, dict)}
    missing_stages = sorted(set(("passive", "dns", "http", "nmap", "database", "delivery", "vulnerability", "persistence", "c2")) - set(coverage))
    for stage in missing_stages:
        coverage[stage] = {"status": "not_run", "artifact_available": False, "usable": False}
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": generated_at or datetime.now(timezone.utc).isoformat(), "target": next((p.get("root_domain", p.get("target")) for p in artifacts.values() if isinstance(p, dict) and p.get("root_domain", p.get("target"))), None), "run_id": run_id, "status": "partial" if missing_stages or any(x["status"] != "success" for x in coverage.values()) else "success", "source": "stored_artifacts_and_owner_configuration", "rubric": {"version": "1.0", "criticality_scale": "CRITICAL=5,HIGH=4,MEDIUM=3,LOW=2,UNKNOWN=not assessed", "cia_scale": "owner-supplied integer 1-5", "formula": "criticality × CIA; no financial-loss estimate"}, "coverage": coverage, "findings": findings, "executive_summary": {"observed_findings": len(findings), "estimated_impact_findings": sum(1 for x in findings if x["estimated_impact"]["score"] is not None), "unknown_criticality": sum(1 for x in findings if x["asset_criticality"] == "UNKNOWN"), "highest_priority_findings": [x for x in findings if x["priority"] == "high"][:10], "exposed_critical_assets": [x["asset_id"] for x in findings if x["asset_criticality"] == "CRITICAL" and x["observed_finding"]["stage"] in {"delivery", "http", "nmap"}], "posture": "partial evidence summary; not a security certification", "recommended_next_actions": ["Validate high-priority estimates with asset owners.", "Collect missing stages and owner ratings where appropriate."]}, "limitations": ["Criticality/CIA are never inferred from hostnames or technical severity.", "Scores are owner-input-based impact estimates, not likelihood, financial loss, or confirmed business impact.", "Missing stages and evidence are unknown, not clean, safe, or zero.", "No financial loss is estimated."]}
