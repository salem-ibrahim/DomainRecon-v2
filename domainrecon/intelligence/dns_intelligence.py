"""Offline DNS intelligence over existing passive and DNSx artifacts.

Wildcard probing is a separate, explicit DNSx action; this module never creates a
resolver or performs network I/O during artifact analysis.
"""
from __future__ import annotations

import re
import secrets
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from domainrecon.collectors.dns_intelligence import collect_dns
from domainrecon.core.scope import ScopePolicy

SCHEMA_ID = "domainrecon.dns_intelligence"
SCHEMA_VERSION = 1
_RECORD_KEYS = ("a", "aaaa", "cname", "mx", "ns", "txt", "soa", "caa")
_PROVIDER_SUFFIXES = {
    "amazonaws.com": "Amazon Web Services",
    "cloudfront.net": "Amazon CloudFront",
    "azureedge.net": "Microsoft Azure CDN",
    "trafficmanager.net": "Microsoft Azure Traffic Manager",
    "cloudflare.net": "Cloudflare",
    "cloudflare.com": "Cloudflare",
    "fastly.net": "Fastly",
    "akamaiedge.net": "Akamai",
    "edgesuite.net": "Akamai",
    "edgekey.net": "Akamai",
    "herokudns.com": "Heroku",
    "github.io": "GitHub Pages",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            if isinstance(item, str) and item.strip():
                result.append(item.strip())
            elif isinstance(item, dict):
                result.extend(f"{key}={val}" for key, val in sorted(item.items()) if isinstance(val, (str, int)))
        return result
    return []


def _dns_name(value: str) -> str | None:
    text = value.strip().rstrip(".").lower()
    if not text:
        return None
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _record_map(dns_payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = dns_payload.get("records", [])
    if not isinstance(rows, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("hostname"), str):
            continue
        host = _dns_name(row["hostname"])
        if host:
            result[host] = row
    return result


def _raw_records(row: dict[str, Any] | None) -> dict[str, list[str]]:
    raw = row.get("records", {}) if isinstance(row, dict) else {}
    if not isinstance(raw, dict):
        return {}
    return {key: _strings(raw.get(key)) for key in _RECORD_KEYS if _strings(raw.get(key))}


def _classify(row: dict[str, Any] | None, records: dict[str, list[str]]) -> str:
    if row is None:
        return "DNS_NOT_OBSERVED"
    status = str(row.get("status", "")).lower()
    error = str(row.get("error", "")).lower()
    if status in {"failed", "timeout"}:
        if "nxdomain" in error or "no such host" in error or "name error" in error:
            return "DNS_NXDOMAIN"
        if status == "timeout" or "timeout" in error or "timed out" in error:
            return "DNS_TIMEOUT"
        return "DNS_ERROR"
    if records.get("a") or records.get("aaaa"):
        return "DNS_RESOLVED_WITH_IP"
    if records.get("cname"):
        return "CNAME_ONLY"
    if status == "unresolved":
        return "DNS_NO_RECORD"
    if status == "success":
        return "DNS_NO_RECORD"
    return "DNS_ERROR"


def _provider_for(cname: str) -> str | None:
    canonical = _dns_name(cname)
    if not canonical:
        return None
    for suffix, provider in _PROVIDER_SUFFIXES.items():
        if canonical == suffix or canonical.endswith("." + suffix):
            return provider
    return None


_SPF_LOOKUP_TERMS = re.compile(r"(?i)(?:^|(?<=\s))[+?~-]?(include:|a(?=[:/\s]|$)|mx(?=[:/\s]|$)|ptr(?=[:\s]|$)|exists:|redirect=)")


def _advanced_dns_findings(scope: ScopePolicy, dns_by_host: dict[str, dict[str, Any]], hosts: list[dict[str, Any]], spf: list[str], dmarc: list[str], dnssec: dict[str, Any] | None) -> list[dict[str, Any]]:
    """SPF depth, DMARC tags, DKIM (operator-supplied selectors), DNSSEC indicators, dangling aliases."""
    findings: list[dict[str, Any]] = []
    if len(spf) == 1:
        lookups = len(_SPF_LOOKUP_TERMS.findall(" " + spf[0]))
        findings.append({"type": "spf_lookup_count", "classification": "exceeds_rfc7208_limit_indicator" if lookups > 10 else "within_limit_top_level", "confidence": "medium",
                         "evidence": {"queried_name": scope.root_domain, "top_level_lookup_terms": lookups, "note": "Top-level count only; included records are not expanded."}})
    elif len(spf) > 1:
        findings.append({"type": "spf_multiple_records", "classification": "invalid", "category": "dns_misconfiguration", "severity": "LOW", "confidence": "high", "evidence": {"records": spf}})
    if len(dmarc) == 1:
        tags = {key.strip().lower(): value.strip() for key, _, value in (part.partition("=") for part in dmarc[0].split(";")) if key.strip()}
        findings.append({"type": "dmarc_policy_detail", "classification": tags.get("p", "missing_policy").lower(), "confidence": "high",
                         "evidence": {"p": tags.get("p"), "sp": tags.get("sp"), "pct": tags.get("pct", "100"), "rua_present": "rua" in tags, "adkim": tags.get("adkim", "r"), "aspf": tags.get("aspf", "r")}})
    for name, row in sorted(dns_by_host.items()):
        if "._domainkey." not in name or not scope.permits_dns_policy_name(name):
            continue
        if str(row.get("status", "")).lower() != "success":
            findings.append({"type": "dkim_observation", "classification": "not_assessed", "confidence": "low", "evidence": {"queried_name": name}})
            continue
        records = [value for value in _raw_records(row).get("txt", []) if "p=" in value.replace(" ", "").lower() or "v=dkim1" in value.lower()]
        if not records:
            classification = "not_observed_for_selector"
        elif any(re.search(r"(?i)(?:^|;)\s*p\s*=\s*(?:;|$)", value) for value in records):
            classification = "revoked_key"
        else:
            classification = "present"
        findings.append({"type": "dkim_observation", "classification": classification, "confidence": "high" if records else "low",
                         "evidence": {"queried_name": name, "records": [value[:200] for value in records], "note": "Only operator-supplied selectors are queried; other selectors may exist."}})
    if dnssec is None:
        findings.append({"type": "dnssec_indicator", "classification": "not_assessed", "confidence": "low", "evidence": {"reason": "DNSSEC query not run (requires explicitly configured resolvers in the engagement)."}})
    else:
        signed = dnssec.get("dnskey_count", 0) > 0
        classification = "signed_and_validated" if signed and dnssec.get("ad_flag") else "signed_validation_not_confirmed" if signed else "unsigned_indicator" if dnssec.get("status") == "success" else "not_assessed"
        findings.append({"type": "dnssec_indicator", "classification": classification, "confidence": "medium" if dnssec.get("status") == "success" else "low",
                         "evidence": {key: dnssec.get(key) for key in ("resolver", "dnskey_count", "ds_count", "rrsig_present", "ad_flag", "status", "error")}})
    for item in hosts:
        if item.get("dangling_indicator"):
            findings.append({"type": "dangling_cname_indicator", "classification": "candidate", "category": "dns_misconfiguration", "severity": "INFO", "confidence": "medium",
                             "hostname": item["hostname"], "evidence": {"cname_chain": item["cname_chain"], "provider": item.get("external_provider"), "note": "No address observed for the alias; see takeover intelligence for provider correlation."}})
    return findings


def generate_wildcard_labels(scope: ScopePolicy, *, count: int = 2) -> list[str]:
    """Generate unique random in-scope labels; callers must explicitly resolve them."""
    if not 1 <= count <= 5:
        raise ValueError("Wildcard probe count must be between 1 and 5.")
    return [f"dr-wildcard-{secrets.token_hex(8)}.{scope.root_domain}" for _ in range(count)]


def probe_wildcard_dns(executable: Path, scope: ScopePolicy, *, count: int = 2) -> dict[str, Any]:
    """Explicitly query random labels through the existing DNSx integration."""
    labels = generate_wildcard_labels(scope, count=count)
    rows = collect_dns(executable, scope, labels)
    return {"labels": labels, "records": rows, "source": "dnsx", "probes": count}


def analyze_dns_artifacts(
    passive_payload: dict[str, Any] | None,
    dns_payload: dict[str, Any] | None,
    scope: ScopePolicy,
    *,
    wildcard_probe: dict[str, Any] | None = None,
    generated_at: str | None = None,
    dnssec: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Analyze immutable DNS/passive payloads without issuing network requests."""
    if passive_payload is not None and passive_payload.get("root_domain", scope.root_domain) != scope.root_domain:
        raise ValueError("Passive artifact root domain does not match the requested scope.")
    if dns_payload is not None and dns_payload.get("root_domain", scope.root_domain) != scope.root_domain:
        raise ValueError("DNS artifact root domain does not match the requested scope.")
    discovered: dict[str, dict[str, Any]] = {}
    raw_passive = passive_payload.get("records", []) if isinstance(passive_payload, dict) else []
    if isinstance(raw_passive, list):
        for item in raw_passive:
            if not isinstance(item, dict) or not isinstance(item.get("hostname"), str) or not scope.permits_hostname(item["hostname"]):
                continue
            host = scope.require_hostname(item["hostname"])
            sources = item.get("sources", [])
            discovered[host] = {"hostname": host, "sources": sorted({str(s) for s in sources if isinstance(s, str)}) if isinstance(sources, list) else []}
    dns_by_host = _record_map(dns_payload or {})
    all_hosts = sorted(set(discovered) | {h for h in dns_by_host if scope.permits_hostname(h)})
    cname_map: dict[str, str] = {}
    full_chains: dict[str, list[str]] = {}
    dns_hosts: list[dict[str, Any]] = []
    ip_hosts: dict[str, list[str]] = defaultdict(list)
    cname_hosts: dict[str, list[str]] = defaultdict(list)
    for host in all_hosts:
        row = dns_by_host.get(host)
        records = _raw_records(row)
        safe_ips: list[str] = []
        for key in ("a", "aaaa"):
            safe_ips.extend(records.get(key, []))
        cnames = [_dns_name(x.split()[0]) for x in records.get("cname", []) if x.split()]
        cnames = [x for x in cnames if x]
        if cnames:
            cname_map[host] = cnames[0]
            cname_hosts[cnames[0]].append(host)
            full_chains[host] = list(dict.fromkeys(cnames))  # DNSx reports the whole chain in order
        for address in safe_ips:
            ip_hosts[address].append(host)
        dns_hosts.append({
            "hostname": host,
            "sources": discovered.get(host, {}).get("sources", []),
            "category": _classify(row, records),
            "records": records,
            "cname_chain": [],
            "cname_chain_status": "not_present",
            "external_provider": None,
            "wildcard_status": "not_assessed",
            "evidence": [{"source": "dnsx" if row else "passive_enumeration", "hostname": host}],
        })
    by_host = {item["hostname"]: item for item in dns_hosts}
    for host, item in by_host.items():
        current = host
        seen = {current}
        chain: list[str] = []
        provider = None
        while current in cname_map:
            target = cname_map[current]
            chain.append(target)
            provider = provider or _provider_for(target)
            if target in seen:
                item["cname_chain_status"] = "broken_loop"
                break
            seen.add(target)
            if target not in cname_map:
                target_row = dns_by_host.get(target)
                if target_row is None:
                    item["cname_chain_status"] = "unresolved_terminal"
                elif str(target_row.get("status", "")).lower() in {"failed", "timeout"}:
                    item["cname_chain_status"] = "broken_terminal"
                else:
                    item["cname_chain_status"] = "complete"
                break
            current = target
        if len(full_chains.get(host, [])) > len(chain):
            chain = full_chains[host]
            provider = next((p for p in (_provider_for(hop) for hop in chain) if p), provider)
            item["cname_chain_status"] = "unresolved_terminal"
        if chain and item["cname_chain_status"] == "not_present":
            item["cname_chain_status"] = "complete"
        addresses_observed = bool(item["records"].get("a") or item["records"].get("aaaa"))
        if chain and addresses_observed:
            item["cname_chain_status"] = "complete"  # DNSx resolved the chain to addresses
        item["cname_chain"] = chain
        item["external_provider"] = provider
        item["terminal_addresses_observed"] = addresses_observed
        row = dns_by_host.get(host) or {}
        # Dangling indicator: an alias whose chain produced no address in a successful query. Not proof of takeover.
        item["dangling_indicator"] = bool(chain) and not addresses_observed and str(row.get("status", "")).lower() == "success"
        item["evidence"][0]["source"] = row.get("query_purpose") and "dnsx_policy" or item["evidence"][0]["source"]

    wildcard_source = wildcard_probe or {}
    wildcard_rows = {
        hostname: row for hostname, row in _record_map(wildcard_source).items()
        if scope.permits_hostname(hostname)
    }
    wildcard_signatures: list[tuple[str, ...]] = []
    for row in wildcard_rows.values():
        raw = _raw_records(row)
        signature = tuple(sorted(raw.get("a", []) + raw.get("aaaa", []) + [_dns_name(c.split()[0]) or c for c in raw.get("cname", []) if c.split()]))
        if signature:
            wildcard_signatures.append(signature)
    discovered_signatures: dict[tuple[str, ...], list[str]] = defaultdict(list)
    for item in dns_hosts:
        raw = item["records"]
        sig = tuple(sorted(raw.get("a", []) + raw.get("aaaa", []) + [_dns_name(c.split()[0]) or c for c in raw.get("cname", []) if c.split()]))
        if sig:
            discovered_signatures[sig].append(item["hostname"])
    matching_signatures = [sig for sig in wildcard_signatures if sig in discovered_signatures]
    wildcard_level = "confirmed" if len(wildcard_signatures) >= 2 and len(set(wildcard_signatures)) == 1 else "suspected" if wildcard_signatures else "not_detected" if wildcard_probe else "not_assessed"
    wildcard_findings: list[dict[str, Any]] = []
    if wildcard_level in {"confirmed", "suspected"}:
        for sig in sorted(set(matching_signatures)):
            for host in discovered_signatures[sig]:
                by_host[host]["wildcard_status"] = wildcard_level
        wildcard_findings.append({
            "type": "wildcard_dns", "classification": "confirmed" if wildcard_level == "confirmed" else "suspected",
            "confidence": "high" if wildcard_level == "confirmed" else "medium",
            "evidence": {"probe_labels": wildcard_probe.get("labels", []), "probe_signatures": [list(x) for x in wildcard_signatures], "matching_discovered_hosts": sorted({h for sig in matching_signatures for h in discovered_signatures[sig]})},
        })

    shared_ips = [{"ip": ip, "hostnames": sorted(set(hosts)), "evidence": {"record_type": "A_or_AAAA"}} for ip, hosts in sorted(ip_hosts.items()) if len(set(hosts)) > 1]
    shared_cnames = [{"cname_target": target, "hostnames": sorted(set(hosts)), "evidence": {"record_type": "CNAME"}} for target, hosts in sorted(cname_hosts.items()) if len(set(hosts)) > 1]
    findings: list[dict[str, Any]] = list(wildcard_findings)
    root_row = dns_by_host.get(scope.root_domain)
    root_observed = isinstance(root_row, dict) and str(root_row.get("status", "")).lower() == "success"
    records_at_root = _raw_records(root_row)
    if root_observed:
        findings.append({"type": "caa_observation", "classification": "present" if records_at_root.get("caa") else "not_observed", "confidence": "high" if records_at_root.get("caa") else "low", "evidence": {"queried_name": scope.root_domain, "records": records_at_root.get("caa", []), "note": "Absence is an observation, not by itself a vulnerability."}})
    txt_values = records_at_root.get("txt", [])
    spf = [x for x in txt_values if x.lower().startswith("v=spf1")]
    dmarc_host = f"_dmarc.{scope.root_domain}"
    dmarc_row = dns_by_host.get(dmarc_host)
    dmarc_values = _raw_records(dmarc_row).get("txt", [])
    dmarc = [x for x in dmarc_values if x.lower().startswith("v=dmarc1")]
    if root_observed:
        findings.append({"type": "spf_observation", "classification": "present" if spf else "not_observed", "confidence": "high" if spf else "low", "evidence": {"queried_name": scope.root_domain, "txt": spf, "note": "No SPF record is not by itself a vulnerability."}})
    if isinstance(dmarc_row, dict) and str(dmarc_row.get("status", "")).lower() == "success":
        findings.append({"type": "dmarc_observation", "classification": "present" if dmarc else "not_observed", "confidence": "high" if dmarc else "low", "evidence": {"queried_name": dmarc_host, "txt": dmarc, "note": "No DMARC record is not by itself a vulnerability."}})
    if not isinstance(dmarc_row, dict) or str(dmarc_row.get("status", "")).lower() != "success":
        findings.append({"type": "dmarc_observation", "classification": "not_assessed", "confidence": "low", "evidence": {"queried_name": dmarc_host, "record": "TXT", "note": "DMARC was not successfully queried; absence is not inferred."}})
    if not root_observed:
        findings.append({"type": "spf_observation", "classification": "not_assessed", "confidence": "low", "evidence": {"queried_name": scope.root_domain, "record": "TXT", "note": "SPF was not successfully queried; absence is not inferred."}})
        findings.append({"type": "caa_observation", "classification": "not_assessed", "confidence": "low", "evidence": {"queried_name": scope.root_domain, "record": "CAA", "note": "CAA was not successfully queried; absence is not inferred."}})
    findings.extend(_advanced_dns_findings(scope, dns_by_host, dns_hosts, spf, dmarc, dnssec))
    dns_rows_status = [str(row.get("status", "")).lower() for row in _record_map(dns_payload or {}).values()]
    if not isinstance(dns_payload, dict):
        dns_status = "not_available"
    elif dns_rows_status and all(value in {"failed", "timeout"} for value in dns_rows_status):
        dns_status = "failed"
    elif any(value in {"failed", "timeout"} for value in dns_rows_status):
        dns_status = "partial"
    else:
        dns_status = "success"
    return {
        "schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": generated_at or _now(),
        "root_domain": scope.root_domain,
        "source_status": {"passive": passive_payload.get("status") if isinstance(passive_payload, dict) else "not_available", "dns": dns_status, "wildcard": "available" if wildcard_probe is not None else "not_run"},
        "hosts": dns_hosts, "shared_infrastructure": {"shared_ips": shared_ips, "shared_cname_targets": shared_cnames},
        "findings": findings,
    }
