"""Engagement configuration: scope narrowing, operation gating, limits, and operation history.

An engagement file is configuration, not proof of authorization. It can only *narrow* what
DomainRecon may do (exclusions, authorized IP ranges, disabled operations, lower limits); every
network operation still requires its own typed acknowledgement and ScopePolicy enforcement.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ScopeViolation
from .ledger import HashChainLedger
from .scope import ScopePolicy, canonical_domain, canonical_hostname
from .simple_yaml import loads as yaml_loads

SCHEMA_ID = "domainrecon.engagement"
SCHEMA_VERSION = 1
OPERATIONS = ("passive_recon", "dns_assessment", "http_assessment", "tls_assessment", "port_scanning")
# Deprecated switches are accepted only as ``false`` so older files still load; ``true`` is refused because
# DomainRecon has no such capability and silently ignoring it would be misleading.
DEPRECATED_OPERATIONS = {
    "vulnerability_validation": "deprecated and unsupported: DomainRecon performs no vulnerability validation or exploitation "
                                "(Stage 04 is offline applicability assessment only). Remove the key or set it to false.",
}
HARD_LIMITS = {"max_concurrency": 4, "requests_per_second": 10}
PROFILES: dict[str, dict[str, bool]] = {
    "passive": {"passive_recon": True, "dns_assessment": True, "http_assessment": False, "tls_assessment": False, "port_scanning": False},
    "standard": {"passive_recon": True, "dns_assessment": True, "http_assessment": True, "tls_assessment": True, "port_scanning": False},
    "full": {"passive_recon": True, "dns_assessment": True, "http_assessment": True, "tls_assessment": True, "port_scanning": True},
}
# Interactive/legacy operation identifiers -> engagement operation switches.
OPERATION_MAP = {
    "passive_enumeration": "passive_recon", "dns_resolution": "dns_assessment", "dns_wildcard_probe": "dns_assessment",
    "dns_dnssec_query": "dns_assessment", "httpx_active_probe": "http_assessment", "tls_certificate_probe": "tls_assessment",
    "nmap_tcp_scan": "port_scanning", "nmap_host_scan": "port_scanning", "nmap_resume": "port_scanning",
}
_NAME = re.compile(r"^[\w .,:()/&+-]{1,120}$")


@dataclass(frozen=True)
class Engagement:
    name: str
    target: str
    profile: str
    domains: tuple[str, ...]
    ip_ranges: tuple[str, ...]
    excluded_hostnames: tuple[str, ...]
    excluded_networks: tuple[str, ...]
    operations: dict[str, bool]
    limits: dict[str, float]
    dkim_selectors: tuple[str, ...] = ()
    dns_resolvers: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = "interactive"
    sha256: str | None = None
    deprecations: tuple[str, ...] = ()

    @property
    def engagement_id(self) -> str:
        basis = json.dumps({"name": self.name, "target": self.target, "source_sha256": self.sha256, "created": self.metadata.get("created_at_utc")}, sort_keys=True)
        return "eng-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def scope_policy(self) -> ScopePolicy:
        return ScopePolicy(self.target, excluded_hostnames=frozenset(self.excluded_hostnames), excluded_networks=self.excluded_networks, authorized_networks=self.ip_ranges)

    def operation_allowed(self, operation: str) -> tuple[bool, str]:
        switch = OPERATION_MAP.get(operation, operation)
        if switch not in self.operations:
            return True, "operation not governed by the engagement file"
        if self.operations[switch]:
            return True, f"enabled by engagement '{self.name}' ({switch}); explicit authorization is still required"
        return False, f"disabled by engagement '{self.name}' ({switch}: false)"

    def limit(self, name: str) -> float:
        return self.limits[name]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "engagement_id": self.engagement_id, "name": self.name,
            "target": self.target, "profile": self.profile,
            "scope": {"domains": list(self.domains), "ip_ranges": list(self.ip_ranges), "excluded_assets": list(self.excluded_hostnames) + list(self.excluded_networks)},
            "operations": dict(self.operations), "limits": dict(self.limits),
            "deprecations": list(self.deprecations),
            "dns": {"dkim_selectors": list(self.dkim_selectors), "resolvers": list(self.dns_resolvers)},
            "metadata": dict(self.metadata), "source": self.source, "source_sha256": self.sha256,
            "note": "Configuration only; it is not proof of authorization. Active operations still require explicit acknowledgement.",
        }


def _as_list(value: Any, label: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list.")
    return value


def build_engagement(data: dict[str, Any], *, source: str = "interactive", sha256: str | None = None) -> Engagement:
    root = data.get("engagement", data)
    if not isinstance(root, dict):
        raise ValueError("Engagement configuration must be a mapping.")
    name = str(root.get("name") or "").strip()
    if not _NAME.fullmatch(name):
        raise ValueError("Engagement name is required (1-120 printable characters).")
    target = canonical_domain(str(root.get("target") or ""))
    ScopePolicy(target)  # rejects public suffixes and invalid roots
    scope = root.get("scope") or {}
    if not isinstance(scope, dict):
        raise ValueError("scope must be a mapping.")
    domains: list[str] = []
    for raw in _as_list(scope.get("domains"), "scope.domains") or [target]:
        domain = canonical_hostname(str(raw))
        if domain != target and not domain.endswith("." + target):
            raise ScopeViolation(f"scope.domains entry {domain} is outside the engagement target {target}; create one engagement per root domain.")
        domains.append(domain)
    ip_ranges = [str(ipaddress.ip_network(str(raw), strict=False)) for raw in _as_list(scope.get("ip_ranges"), "scope.ip_ranges")]
    for network in ip_ranges:
        net = ipaddress.ip_network(network)
        if not net.is_global or net.is_private:
            raise ScopeViolation(f"scope.ip_ranges entry {network} is not public address space.")
    excluded_hosts: list[str] = []
    excluded_nets: list[str] = []
    for raw in _as_list(scope.get("excluded_assets", root.get("excluded_assets")), "scope.excluded_assets"):
        text = str(raw).strip()
        try:
            excluded_nets.append(str(ipaddress.ip_network(text, strict=False)))
        except ValueError:
            excluded_hosts.append(canonical_hostname(text))
    profile = str(root.get("profile") or "standard").lower()
    if profile not in PROFILES:
        raise ValueError(f"Unknown profile {profile}; use one of {sorted(PROFILES)}.")
    operations = dict(PROFILES[profile])
    configured = root.get("operations") or {}
    if not isinstance(configured, dict):
        raise ValueError("operations must be a mapping.")
    deprecations: list[str] = []
    for key, value in configured.items():
        if key in DEPRECATED_OPERATIONS:
            if value is not False:
                raise ValueError(f"operations.{key} is {DEPRECATED_OPERATIONS[key]}")
            deprecations.append(f"operations.{key}: {DEPRECATED_OPERATIONS[key]}")
            continue
        if key not in OPERATIONS:
            raise ValueError(f"Unknown operation {key}; supported: {', '.join(OPERATIONS)}.")
        if not isinstance(value, bool):
            raise ValueError(f"operations.{key} must be true or false.")
        operations[key] = value
    limits_in = root.get("limits") or {}
    limits: dict[str, float] = {}
    for key, hard in HARD_LIMITS.items():
        value = limits_in.get(key, 2)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
            raise ValueError(f"limits.{key} must be a positive number.")
        limits[key] = min(value, hard)  # engagement files can lower, never raise, the hard caps
    dns_cfg = root.get("dns") or {}
    selectors = [str(value).lower() for value in _as_list(dns_cfg.get("dkim_selectors") if isinstance(dns_cfg, dict) else None, "dns.dkim_selectors")]
    policy = ScopePolicy(target)
    for selector in selectors:
        policy.require_dns_policy_name(f"{selector}._domainkey.{target}")
    resolvers = [ipaddress.ip_address(str(value)).compressed for value in _as_list(dns_cfg.get("resolvers") if isinstance(dns_cfg, dict) else None, "dns.resolvers")]
    metadata = {key: root.get(key) for key in ("client", "owner", "contact_reference", "authorization_reference", "start_date", "end_date") if root.get(key) is not None}
    metadata.setdefault("created_at_utc", datetime.now(timezone.utc).isoformat())
    return Engagement(name, target, profile, tuple(domains), tuple(ip_ranges), tuple(excluded_hosts), tuple(excluded_nets), operations, limits, tuple(selectors), tuple(resolvers), metadata, source, sha256, tuple(deprecations))


def load_engagement(path: Path) -> Engagement:
    """Load a .yaml/.yml (strict subset) or .json engagement file; max 256 KiB."""
    if not path.is_file():
        raise FileNotFoundError(f"Engagement file not found: {path}")
    if path.stat().st_size > 262_144:
        raise ValueError("Engagement file exceeds 256 KiB.")
    raw = path.read_bytes()
    text = raw.decode("utf-8-sig")
    data = json.loads(text) if path.suffix.lower() == ".json" else yaml_loads(text)
    if not isinstance(data, dict):
        raise ValueError("Engagement file must contain a mapping.")
    return build_engagement(data, source=str(path), sha256=hashlib.sha256(raw).hexdigest())


def operation_history(results_root: Path, engagement: Engagement) -> HashChainLedger:
    """Immutable, hash-chained history of every operation decision under an engagement."""
    return HashChainLedger(results_root / engagement.target / "engagements" / engagement.engagement_id / "operation_history.jsonl")
