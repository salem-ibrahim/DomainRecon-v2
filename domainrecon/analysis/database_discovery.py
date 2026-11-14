"""Pure offline Database Discovery over immutable Phase 1 Nmap JSON evidence."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domainrecon.core.scope import ScopePolicy

SCHEMA_ID = "domainrecon.database_inventory"
SCHEMA_VERSION = 1
_PORT_HINTS = {3306, 5432, 1433, 27017, 6379, 1521}
_IDENTITIES = {"mysql", "mariadb", "postgresql", "mssql", "mongodb", "redis", "oracle"}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _identity_from_explicit(value: str) -> str | None:
    normalized = value.lower().replace("_", " ").replace("-", " ")
    if "mariadb" in normalized:
        return "mariadb"
    if "postgresql" in normalized or normalized == "postgres":
        return "postgresql"
    if "microsoft sql server" in normalized or "mssql" in normalized or "ms sql" in normalized:
        return "mssql"
    if "mongodb" in normalized or "mongo db" in normalized:
        return "mongodb"
    if normalized == "redis" or normalized.startswith("redis "):
        return "redis"
    if "oracle" in normalized:
        return "oracle"
    if normalized == "mysql" or normalized.startswith("mysql "):
        return "mysql"
    return None


def _identity_from_service(service: str) -> str | None:
    normalized = service.lower()
    mapping = {"postgresql": "postgresql", "mariadb": "mariadb", "ms-sql-s": "mssql", "mssql": "mssql", "mongodb": "mongodb", "redis": "redis", "oracle-tns": "oracle", "oracle": "oracle"}
    return mapping.get(normalized)


def _product_label(identity: str) -> str:
    return {"mysql": "MySQL", "mariadb": "MariaDB", "postgresql": "PostgreSQL", "mssql": "Microsoft SQL Server", "mongodb": "MongoDB", "redis": "Redis", "oracle": "Oracle Database"}[identity]


def _cpe_entries(port: dict[str, Any]) -> list[dict[str, Any]]:
    entries = port.get("cpes", [])
    return [entry for entry in entries if isinstance(entry, dict) and isinstance(entry.get("original"), str)] if isinstance(entries, list) else []


def _find_identities(port: dict[str, Any]) -> tuple[set[str], list[str], list[dict[str, Any]]]:
    service, product = _text(port.get("service")), _text(port.get("product"))
    identities: set[str] = set()
    methods: list[str] = []
    service_identity = _identity_from_service(service)
    if service_identity:
        identities.add(service_identity)
        methods.append("nmap_service")
    product_identity = _identity_from_explicit(product)
    if product_identity:
        identities.add(product_identity)
        methods.append("nmap_product")
    cpes = _cpe_entries(port)
    for cpe in cpes:
        cpe_identity = _identity_from_explicit(" ".join(_text(cpe.get(key)) for key in ("vendor", "product")))
        if cpe_identity:
            identities.add(cpe_identity)
            methods.append("nmap_cpe")
    return identities, methods, cpes


def _confidence(identity: str, port: dict[str, Any], methods: list[str], cpes: list[dict[str, Any]]) -> str:
    if "nmap_cpe" in methods or "nmap_product" in methods:
        return "high"
    if "nmap_product" in methods or "nmap_service" in methods:
        return "medium"
    return "low"


def _version(identity: str, port: dict[str, Any], cpes: list[dict[str, Any]], methods: list[str]) -> str | None:
    if "nmap_product" in methods:
        value = _text(port.get("version"))
        if value:
            return value
    for cpe in cpes:
        if _identity_from_explicit(" ".join(_text(cpe.get(key)) for key in ("vendor", "product"))) == identity:
            value = _text(cpe.get("version"))
            if value and value not in {"*", "-"}:
                return value
    return None


def _finding_id(source_artifact: str, ip_address: str | None, port: int, transport: str, identity: str) -> str:
    value = "|".join((source_artifact, ip_address or "", str(port), transport, identity)).encode("utf-8")
    return "db-" + hashlib.sha256(value).hexdigest()[:12]


def _evidence(source_artifact: str, port: dict[str, Any], cpes: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "source_artifact": source_artifact,
        "nmap_state": port.get("state"),
        "nmap_port": port.get("port"),
        "nmap_protocol": port.get("protocol"),
        "nmap_service": port.get("service"),
        "nmap_product": port.get("product"),
        "nmap_version": port.get("version"),
        "nmap_extrainfo": port.get("extrainfo"),
        "nmap_cpes": cpes,
    }


def analyze_nmap_artifact(payload: dict[str, Any], scope: ScopePolicy, source_artifact: str = "nmap.json", *, detected_at: str | None = None) -> dict[str, Any]:
    """Classify database evidence without opening a socket or changing source data."""
    if not isinstance(payload, dict) or payload.get("schema_version") != 1 or payload.get("scanner") != "nmap":
        raise ValueError("Unsupported Nmap artifact schema.")
    if payload.get("status") not in {"success", "partial"}:
        raise ValueError("Database Discovery requires a successful (or partially successful multi-host) Nmap artifact.")
    target = payload.get("target")
    if not isinstance(target, str):
        raise ValueError("Nmap artifact target is missing.")
    scope.require_hostname(target)
    hosts = payload.get("hosts")
    if not isinstance(hosts, list):
        raise ValueError("Nmap artifact hosts must be a list.")
    timestamp = detected_at or _timestamp()
    inventory: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for host_index, host in enumerate(hosts):
        if not isinstance(host, dict):
            errors.append({"code": "invalid_host", "index": host_index})
            continue
        address = host.get("address") if isinstance(host.get("address"), str) else None
        ports = host.get("ports")
        if not isinstance(ports, list):
            errors.append({"code": "invalid_ports", "host_index": host_index})
            continue
        for port_index, port in enumerate(ports):
            if not isinstance(port, dict):
                errors.append({"code": "invalid_port", "host_index": host_index, "port_index": port_index})
                continue
            port_number, transport = port.get("port"), _text(port.get("protocol"))
            if not isinstance(port_number, int) or not 1 <= port_number <= 65535 or not transport:
                errors.append({"code": "invalid_endpoint", "host_index": host_index, "port_index": port_index})
                continue
            if port.get("state") != "open" or transport != "tcp":
                continue
            identities, methods, cpes = _find_identities(port)
            evidence = _evidence(source_artifact, port, cpes)
            associated = [name for name in host.get("hostnames", []) if isinstance(name, str) and scope.permits_hostname(name)] if isinstance(host.get("hostnames"), list) else []
            base = {"hostname": associated[0] if len(associated) == 1 else target, "associated_hostnames": associated, "ip_address": address, "port": port_number, "transport": transport, "nmap_service": port.get("service"), "detected_at": timestamp, "source": {"artifact": source_artifact, "schema_version": payload["schema_version"], "scanner": payload["scanner"]}, "evidence": evidence, "assessment_status": "service_observed", "vulnerability_status": "not_assessed"}
            if len(identities) == 1:
                identity = next(iter(identities))
                entry = {**base, "finding_id": _finding_id(source_artifact, address, port_number, transport, identity), "identity": identity, "product": _product_label(identity), "version": _version(identity, port, cpes, methods), "detection_method": "+".join(sorted(set(methods))), "confidence": _confidence(identity, port, methods, cpes)}
                inventory.append(entry)
            elif len(identities) > 1:
                candidates.append({**base, "identity": "unknown", "product": None, "version": None, "detection_method": "contradictory_nmap_evidence", "confidence": "low", "candidate_identities": sorted(identities), "classification_status": "contradictory"})
            elif port_number in _PORT_HINTS:
                candidates.append({**base, "identity": "unknown", "product": None, "version": None, "detection_method": "port_hint_only", "confidence": "low", "classification_status": "ambiguous"})
    inventory.sort(key=lambda item: (item.get("ip_address") or "", item["port"], item["identity"]))
    candidates.sort(key=lambda item: (item.get("ip_address") or "", item["port"]))
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "module": "database_discovery", "mode": "offline_nmap_analysis", "root_domain": scope.root_domain, "target": scope.root_domain, "source_artifact": source_artifact, "source_status": payload["status"], "generated_at": timestamp, "inventory": inventory, "candidates": candidates, "errors": errors}


def load_and_analyze_nmap(path: Path, scope: ScopePolicy) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return analyze_nmap_artifact(payload, scope, path.name)
