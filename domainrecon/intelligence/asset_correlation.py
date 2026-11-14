"""Deterministic offline correlation of reconnaissance artifacts into assets."""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from domainrecon.core.scope import ScopePolicy

SCHEMA_ID = "domainrecon.asset_inventory"
SCHEMA_VERSION = 1


def _asset_id(kind: str, root: str, identity: str) -> str:
    digest = hashlib.sha256(f"{kind}|{root}|{identity.casefold()}".encode("utf-8")).hexdigest()[:20]
    return f"{kind}-{digest}"


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def correlate_assets(
    scope: ScopePolicy,
    *,
    passive: dict[str, Any] | None = None,
    dns: dict[str, Any] | None = None,
    http: dict[str, Any] | None = None,
    nmap: dict[str, Any] | None = None,
    database: dict[str, Any] | None = None,
    previous_inventory: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> dict[str, Any]:
    """Correlate existing observations. IPs are infrastructure nodes, never host keys."""
    for label, payload in (("passive", passive), ("dns", dns), ("http", http), ("nmap", nmap), ("database", database), ("previous_inventory", previous_inventory)):
        if payload and payload.get("root_domain", payload.get("target", scope.root_domain)) != scope.root_domain:
            raise ValueError(f"{label} artifact belongs to a different root domain.")
    timestamp = observed_at or datetime.now(timezone.utc).isoformat()
    hosts: dict[str, dict[str, Any]] = {}

    def host_record(raw: str) -> dict[str, Any] | None:
        if not scope.permits_hostname(raw):
            return None
        name = scope.require_hostname(raw)
        return hosts.setdefault(name, {
            "asset_id": _asset_id("host", scope.root_domain, name), "asset_type": "hostname",
            "root_domain": scope.root_domain, "fqdn": name, "ip_addresses": [], "ip_families": {},
            "cname_chain": [], "dns_records": {}, "discovery_sources": [], "first_observed": timestamp,
            "last_observed": timestamp, "current_status": "discovered", "services": [], "technologies": [],
            "findings": [], "confidence": "medium", "evidence_references": [],
        })

    for row in _list((passive or {}).get("records")):
        if not isinstance(row, dict) or not isinstance(row.get("hostname"), str):
            continue
        asset = host_record(row["hostname"])
        if not asset:
            continue
        asset["discovery_sources"] = sorted(set(asset["discovery_sources"]) | {str(x) for x in _list(row.get("sources"))})
        asset["evidence_references"].append({"stage": "passive", "artifact": "passive.json", "hostname": asset["fqdn"]})
    for row in _list((dns or {}).get("records")):
        if not isinstance(row, dict) or not isinstance(row.get("hostname"), str):
            continue
        asset = host_record(row["hostname"])
        if not asset:
            continue
        records = row.get("records", {}) if isinstance(row.get("records"), dict) else {}
        for key in ("a", "aaaa"):
            values = records.get(key, [])
            values = [values] if isinstance(values, str) else values if isinstance(values, list) else []
            for value in values:
                if isinstance(value, str):
                    asset["ip_addresses"].append(value)
                    asset["ip_families"][value] = "IPv6" if ":" in value else "IPv4"
        cname = records.get("cname", [])
        asset["cname_chain"] = sorted(set(asset["cname_chain"]) | {str(x).rstrip(".").lower() for x in ([cname] if isinstance(cname, str) else cname if isinstance(cname, list) else [])})
        asset["dns_records"] = {**asset["dns_records"], **{k: v for k, v in records.items() if k in {"a", "aaaa", "cname", "mx", "ns", "txt", "soa", "caa"}}}
        if row.get("status") == "success":
            asset["current_status"] = "dns_resolved"
        asset["evidence_references"].append({"stage": "dns", "artifact": "dns.json", "status": row.get("status")})
    for row in _list((http or {}).get("records")):
        if not isinstance(row, dict) or not isinstance(row.get("hostname"), str):
            continue
        asset = host_record(row["hostname"])
        if not asset:
            continue
        service = {key: row.get(key) for key in ("url", "classification", "status_code", "ip", "final_url", "response_time", "tls") if key in row}
        asset["services"].append(service)
        technologies = row.get("technologies", [])
        if isinstance(technologies, list):
            asset["technologies"] = sorted(set(asset["technologies"]) | {str(x) for x in technologies})
        if row.get("status") == "success":
            asset["current_status"] = "http_responsive"
        asset["evidence_references"].append({"stage": "http", "artifact": "live_web_inventory.json", "classification": row.get("classification")})
    infrastructure: dict[str, dict[str, Any]] = {}
    ip_to_hosts: dict[str, set[str]] = defaultdict(set)
    for name, asset in hosts.items():
        asset["ip_addresses"] = sorted(set(asset["ip_addresses"]))
        for ip in asset["ip_addresses"]:
            ip_to_hosts[ip].add(name)
            infrastructure.setdefault(ip, {"asset_id": _asset_id("ip", scope.root_domain, ip), "asset_type": "ip_infrastructure", "root_domain": scope.root_domain, "ip_address": ip, "ip_family": asset["ip_families"].get(ip), "associated_hostnames": [], "infrastructure_classification": "shared_hosting_or_origin_unknown", "direct_origin_confirmed": False})["associated_hostnames"].append(name)
        asset.pop("ip_families", None)
    nmap_hosts = _list((nmap or {}).get("hosts"))
    for host_row in nmap_hosts:
        if not isinstance(host_row, dict) or not isinstance(host_row.get("address"), str):
            continue
        ip = host_row["address"]
        infra = infrastructure.setdefault(ip, {"asset_id": _asset_id("ip", scope.root_domain, ip), "asset_type": "ip_infrastructure", "root_domain": scope.root_domain, "ip_address": ip, "ip_family": "IPv6" if ":" in ip else "IPv4", "associated_hostnames": [], "infrastructure_classification": "shared_hosting_or_origin_unknown", "direct_origin_confirmed": False})
        services = host_row.get("ports", [])
        infra.setdefault("services", []).extend([{k: p.get(k) for k in ("port", "protocol", "state", "service", "product", "version", "cpes") if k in p} for p in services if isinstance(p, dict)])
        infra.setdefault("evidence_references", []).append({"stage": "nmap", "artifact": "nmap.json", "target": nmap.get("target")})
    for row in _list((database or {}).get("inventory")) + _list((database or {}).get("candidates")):
        if not isinstance(row, dict) or not isinstance(row.get("ip_address"), str):
            continue
        ip = row["ip_address"]
        infra = infrastructure.setdefault(ip, {"asset_id": _asset_id("ip", scope.root_domain, ip), "asset_type": "ip_infrastructure", "root_domain": scope.root_domain, "ip_address": ip, "ip_family": "IPv6" if ":" in ip else "IPv4", "associated_hostnames": [], "infrastructure_classification": "shared_hosting_or_origin_unknown", "direct_origin_confirmed": False})
        service = {key: row.get(key) for key in ("port", "transport", "nmap_service", "product", "version", "identity", "confidence") if key in row}
        infra.setdefault("services", []).append(service)
        finding = {key: row.get(key) for key in ("finding_id", "identity", "product", "version", "confidence", "assessment_status", "vulnerability_status") if key in row}
        infra.setdefault("findings", []).append(finding)
        infra.setdefault("evidence_references", []).append({"stage": "database", "artifact": "database_inventory.json", "finding_id": row.get("finding_id")})
    # Preserve shared hosting/CDN as explicit relations, without merging hostname assets.
    relations = []
    for ip, names in sorted(ip_to_hosts.items()):
        for name in sorted(names):
            relations.append({"type": "RESOLVES_TO", "source": hosts[name]["asset_id"], "target": infrastructure[ip]["asset_id"], "evidence": {"dns_ip": ip}})
        if len(names) > 1:
            for name in sorted(names):
                for other in sorted(names - {name}):
                    relations.append({"type": "SHARES_INFRASTRUCTURE_WITH", "source": hosts[name]["asset_id"], "target": hosts[other]["asset_id"], "evidence": {"shared_ip": ip, "direct_origin_confirmed": False}})
    previous_assets = _list((previous_inventory or {}).get("assets"))
    previous_by_id = {row.get("asset_id"): row for row in previous_assets if isinstance(row, dict) and isinstance(row.get("asset_id"), str)}
    for asset in hosts.values():
        old = previous_by_id.get(asset["asset_id"])
        if old:
            asset["first_observed"] = str(old.get("first_observed") or timestamp)
            asset["last_observed"] = timestamp
    for asset in hosts.values():
        asset["services"] = sorted(asset["services"], key=lambda x: (str(x.get("url", "")), str(x.get("classification", ""))))
        asset["evidence_references"] = sorted(asset["evidence_references"], key=lambda x: (x["stage"], x.get("artifact", "")))
    for asset in infrastructure.values():
        if "services" in asset:
            asset["services"] = sorted(asset["services"], key=lambda x: (x.get("port", 0), str(x.get("transport", x.get("protocol", "")))))
        if "findings" in asset:
            asset["findings"] = sorted(asset["findings"], key=lambda x: str(x.get("finding_id", "")))
        if "evidence_references" in asset:
            asset["evidence_references"] = sorted(asset["evidence_references"], key=lambda x: (x["stage"], x.get("artifact", "")))
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "root_domain": scope.root_domain, "generated_at": timestamp, "assets": sorted(list(hosts.values()) + list(infrastructure.values()), key=lambda x: x["asset_id"]), "relations": relations, "limitations": ["Shared IP addresses are represented as infrastructure; they do not merge hostname asset identities.", "Nmap IP-only observations are not assigned to a hostname unless stronger correlation is available."]}
