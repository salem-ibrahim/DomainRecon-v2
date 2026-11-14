"""Offline attack-surface graph assembled from existing V2 evidence."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from domainrecon.core.scope import ScopePolicy

SCHEMA_ID = "domainrecon.attack_surface"
SCHEMA_VERSION = 1


def build_attack_surface(scope: ScopePolicy, *, passive: dict[str, Any] | None = None, dns: dict[str, Any] | None = None, http: dict[str, Any] | None = None, nmap: dict[str, Any] | None = None, database: dict[str, Any] | None = None, assets: dict[str, Any] | None = None, findings: list[dict[str, Any]] | None = None, generated_at: str | None = None) -> dict[str, Any]:
    """Build nodes and typed relations without network access or inferred host/IP merges."""
    artifacts = (passive, dns, http, nmap, database, assets)
    for payload in artifacts:
        if payload and payload.get("root_domain", payload.get("target", scope.root_domain)) != scope.root_domain:
            raise ValueError("Attack-surface input belongs to a different root domain.")
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str, str]] = set()
    root_id = f"domain:{scope.root_domain}"
    nodes[root_id] = {"id": root_id, "type": "domain", "label": scope.root_domain}

    def node(identity: str, kind: str, label: str, **data: Any) -> None:
        nodes.setdefault(identity, {"id": identity, "type": kind, "label": label, **data})

    def edge(kind: str, source: str, target: str, evidence: str = "") -> None:
        edges.add((kind, source, target, evidence))

    passive_rows = (passive or {}).get("records", [])
    dns_rows = (dns or {}).get("records", [])
    http_rows = (http or {}).get("records", [])
    hosts_by_ip: dict[str, set[str]] = defaultdict(set)
    hosts_by_cname: dict[str, set[str]] = defaultdict(set)
    for row in passive_rows if isinstance(passive_rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("hostname"), str) or not scope.permits_hostname(row["hostname"]):
            continue
        host = scope.require_hostname(row["hostname"])
        hid = f"host:{host}"
        node(hid, "host", host, sources=sorted(row.get("sources", [])) if isinstance(row.get("sources"), list) else [])
        if host != scope.root_domain:
            edge("SUBDOMAIN_OF", hid, root_id, "passive.json")
    for row in dns_rows if isinstance(dns_rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("hostname"), str) or not scope.permits_hostname(row["hostname"]):
            continue
        host = scope.require_hostname(row["hostname"])
        hid = f"host:{host}"
        node(hid, "host", host)
        raw = row.get("records", {}) if isinstance(row.get("records"), dict) else {}
        for key in ("a", "aaaa"):
            vals = raw.get(key, [])
            for ip in ([vals] if isinstance(vals, str) else vals if isinstance(vals, list) else []):
                if isinstance(ip, str):
                    iid = f"ip:{ip}"
                    node(iid, "ip", ip, family="IPv6" if ":" in ip else "IPv4")
                    edge("RESOLVES_TO", hid, iid, f"dns.json:{key}")
                    hosts_by_ip[ip].add(hid)
        cnames = raw.get("cname", [])
        for cname in ([cnames] if isinstance(cnames, str) else cnames if isinstance(cnames, list) else []):
            target = str(cname).strip().rstrip(".").lower()
            if target:
                cid = f"host:{target}"
                node(cid, "host", target, external=not scope.permits_hostname(target))
                edge("CNAME_POINTS_TO", hid, cid, "dns.json:cname")
                hosts_by_cname[target].add(hid)
    for row in http_rows if isinstance(http_rows, list) else []:
        if not isinstance(row, dict) or not isinstance(row.get("hostname"), str) or not scope.permits_hostname(row["hostname"]):
            continue
        host = scope.require_hostname(row["hostname"])
        hid = f"host:{host}"
        node(hid, "host", host)
        url = row.get("url") if isinstance(row.get("url"), str) else f"{host}"
        sid = f"service:http:{url}"
        node(sid, "service", url, service_type="http", classification=row.get("classification"), status_code=row.get("status_code"))
        edge("HOSTS_SERVICE", hid, sid, "live_web_inventory.json")
        technologies = row.get("technologies", [])
        for tech in technologies if isinstance(technologies, list) else []:
            tid = f"technology:{str(tech).casefold()}"
            node(tid, "technology", str(tech))
            edge("USES_TECHNOLOGY", sid, tid, "live_web_inventory.json")
    for host in (nmap or {}).get("hosts", []) if isinstance((nmap or {}).get("hosts", []), list) else []:
        if not isinstance(host, dict) or not isinstance(host.get("address"), str):
            continue
        ip = host["address"]
        iid = f"ip:{ip}"
        node(iid, "ip", ip, family="IPv6" if ":" in ip else "IPv4")
        for port in host.get("ports", []) if isinstance(host.get("ports", []), list) else []:
            if not isinstance(port, dict) or port.get("state") != "open":
                continue
            port_no = port.get("port")
            sid = f"service:{ip}:{port.get('protocol', 'tcp')}:{port_no}"
            node(sid, "service", f"{ip}:{port_no}/{port.get('protocol', 'tcp')}", service_type=port.get("service"), product=port.get("product"), version=port.get("version"), authorized_nmap=True)
            edge("HOSTS_SERVICE", iid, sid, "nmap.json")
    db_inv = (database or {}).get("inventory", [])
    for row in db_inv if isinstance(db_inv, list) else []:
        if not isinstance(row, dict):
            continue
        finding_id = str(row.get("finding_id", f"db:{row.get('ip_address')}:{row.get('port')}"))
        fid = f"finding:{finding_id}"
        node(fid, "finding", f"Database service: {row.get('product', 'unknown')}", confidence=row.get("confidence"), evidence=row.get("evidence"))
        ip = row.get("ip_address")
        if isinstance(ip, str):
            iid = f"ip:{ip}"
            node(iid, "ip", ip, family="IPv6" if ":" in ip else "IPv4")
            edge("HAS_FINDING", iid, fid, str(row.get("source", {}).get("artifact", "database_inventory.json")))
    for index, finding in enumerate(findings or []):
        if not isinstance(finding, dict):
            continue
        fid = str(finding.get("finding_id", f"intel:{index}"))
        finding_node = f"finding:{fid}"
        node(finding_node, "finding", str(finding.get("title", finding.get("type", "Finding"))), confidence=finding.get("confidence", finding.get("match_confidence")), evidence=finding.get("evidence"))
        hostname = finding.get("hostname")
        if isinstance(hostname, str) and scope.permits_hostname(hostname):
            host = scope.require_hostname(hostname)
            hid = f"host:{host}"
            node(hid, "host", host)
            edge("HAS_FINDING", hid, finding_node, str(finding.get("source", "intelligence artifact")))
        address = finding.get("ip_address")
        if isinstance(address, str):
            iid = f"ip:{address}"
            node(iid, "ip", address, family="IPv6" if ":" in address else "IPv4")
            edge("HAS_FINDING", iid, finding_node, str(finding.get("source", "intelligence artifact")))
    for shared in (hosts_by_ip, hosts_by_cname):
        for indicator, related in sorted(shared.items()):
            if len(related) < 2:
                continue
            for source in sorted(related):
                for target in sorted(related - {source}):
                    edge("SHARES_INFRASTRUCTURE_WITH", source, target, f"shared:{indicator}")
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "root_domain": scope.root_domain, "generated_at": generated_at or datetime.now(timezone.utc).isoformat(), "nodes": sorted(nodes.values(), key=lambda x: x["id"]), "relations": [{"type": t, "source": s, "target": d, "evidence": e} for t, s, d, e in sorted(edges)], "source_artifacts": [name for name, artifact in (("passive", passive), ("dns", dns), ("http", http), ("nmap", nmap), ("database", database), ("assets", assets)) if artifact is not None]}
