"""Passive subdomain-takeover indicator analysis over stored DNS and HTTP evidence.

Architecture (extensible without code changes):

* **Provider signatures** live in ``domainrecon/data/takeover_signatures.json`` (bundled) and may be
  extended by an operator-supplied JSON file with the same schema. Each signature names CNAME
  suffixes/substrings, whether a dangling alias is claimable, and evidence rules.
* **Evidence rules** are evaluated by the ``EVIDENCE_MATCHERS`` registry keyed by rule ``type``
  (``http_text_contains``, ``http_title_contains``, ``http_body_contains``, ``http_status_in``,
  ``http_header_contains``). New evidence types are added by registering one matcher function.
  Rules of unknown type are reported as ``unsupported_rules``, never silently treated as matches.
* **Classification** is unchanged and conservative:
  ``strong_indicator`` (provider + unclaimed-resource evidence, or a dangling alias on a provider
  whose names are claimable), ``potentially_vulnerable`` (dangling alias without a provider signal),
  ``informational`` (provider alias resolving normally), ``insufficient_evidence`` (DNS not observed).

Signatures are curated and marked ``unverified``; a match is an indicator to investigate, not proof.
No resource registration, account creation, claiming, or takeover attempt is ever made. Response
bodies are matched only if present in stored evidence (``body_excerpt``); HTTPX does not keep them.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from domainrecon.intelligence.mitre_mapping import techniques_for

SCHEMA_ID = "domainrecon.takeover_intelligence"
SCHEMA_VERSION = 2
BUNDLED_SIGNATURES = Path(__file__).resolve().parent.parent / "data" / "takeover_signatures.json"
_SEVERITY = {"strong_indicator": "HIGH", "potentially_vulnerable": "MEDIUM", "informational": "INFO", "insufficient_evidence": "INFO"}
_CONFIDENCE = {"strong_indicator": "medium", "potentially_vulnerable": "low", "informational": "high", "insufficient_evidence": "low"}
_SIGNALS = {"unclaimed_resource", "supporting"}


def _titles(ctx: dict[str, Any]) -> list[str]:
    return [str(row.get("title") or "").lower() for row in ctx["http"]]


def _bodies(ctx: dict[str, Any]) -> list[str]:
    return [str(row.get("body_excerpt") or "").lower() for row in ctx["http"]]


EVIDENCE_MATCHERS: dict[str, Callable[[dict[str, Any], dict[str, Any]], bool]] = {
    "http_text_contains": lambda rule, ctx: any(str(rule["value"]).lower() in text for text in _titles(ctx) + _bodies(ctx)),
    "http_title_contains": lambda rule, ctx: any(str(rule["value"]).lower() in text for text in _titles(ctx)),
    "http_body_contains": lambda rule, ctx: any(str(rule["value"]).lower() in text for text in _bodies(ctx)),
    "http_status_in": lambda rule, ctx: any(row.get("status_code") in set(rule["value"]) for row in ctx["http"]),
    "http_header_contains": lambda rule, ctx: any(str(rule["value"].get("contains", "")).lower() in str((row.get("headers") or {}).get(str(rule["value"].get("header", "")).lower(), "")).lower()
                                                  for row in ctx["http"] if isinstance(row.get("headers"), dict)),
}


def _validate_signatures(data: Any, source: str) -> list[dict[str, Any]]:
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("providers"), list):
        raise ValueError(f"{source}: not a version 1 takeover signature file.")
    providers = []
    for entry in data["providers"]:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not isinstance(entry.get("provider"), str):
            raise ValueError(f"{source}: every provider needs string 'id' and 'provider'.")
        suffixes = entry.get("cname_suffixes", [])
        contains = entry.get("cname_contains", [])
        if not isinstance(suffixes, list) or not isinstance(contains, list) or not (suffixes or contains):
            raise ValueError(f"{source}: provider {entry['id']} needs cname_suffixes or cname_contains.")
        rules = entry.get("evidence_rules", [])
        if not isinstance(rules, list) or any(not isinstance(rule, dict) or "type" not in rule or "value" not in rule or rule.get("signal", "unclaimed_resource") not in _SIGNALS for rule in rules):
            raise ValueError(f"{source}: provider {entry['id']} has malformed evidence_rules.")
        providers.append({**entry, "cname_suffixes": [s.lower().strip(".") for s in suffixes], "cname_contains": [c.lower() for c in contains],
                          "claimable_when_dangling": entry.get("claimable_when_dangling") is True, "verification_status": str(entry.get("verification_status", "unverified")),
                          "signature_source": source})
    return providers


def load_signatures(extra_path: Path | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Bundled signatures plus an optional operator file (adds providers or rules; cannot remove bundled ones)."""
    raw = BUNDLED_SIGNATURES.read_bytes()
    providers = {entry["id"]: entry for entry in _validate_signatures(json.loads(raw), "bundled")}
    provenance: dict[str, Any] = {"bundled_sha256": hashlib.sha256(raw).hexdigest(), "operator_file": None}
    if extra_path is not None:
        extra_raw = extra_path.read_bytes()
        if len(extra_raw) > 2_000_000:
            raise ValueError("Takeover signature file exceeds 2 MB.")
        for entry in _validate_signatures(json.loads(extra_raw), f"operator:{extra_path.name}"):
            if entry["id"] in providers:
                merged = providers[entry["id"]]
                merged["evidence_rules"] = merged.get("evidence_rules", []) + entry.get("evidence_rules", [])
                merged["cname_suffixes"] = sorted(set(merged["cname_suffixes"]) | set(entry["cname_suffixes"]))
                merged["cname_contains"] = sorted(set(merged["cname_contains"]) | set(entry["cname_contains"]))
            else:
                providers[entry["id"]] = entry
        provenance["operator_file"] = {"name": extra_path.name, "sha256": hashlib.sha256(extra_raw).hexdigest()}
    provenance["provider_count"] = len(providers)
    return list(providers.values()), provenance


def provider_for_chain(chain: list[str], providers: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    for hop in chain:
        name = hop.lower().rstrip(".")
        for provider in providers if providers is not None else load_signatures()[0]:
            if any(name == suffix or name.endswith("." + suffix) for suffix in provider["cname_suffixes"]) or any(fragment in name for fragment in provider["cname_contains"]):
                return provider
    return None


def _evaluate_rules(provider: dict[str, Any], ctx: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    matched, unsupported = [], []
    for rule in provider.get("evidence_rules", []):
        matcher = EVIDENCE_MATCHERS.get(rule["type"])
        if matcher is None:
            unsupported.append({"provider": provider["id"], "type": rule["type"]})
            continue
        try:
            if matcher(rule, ctx):
                matched.append({"type": rule["type"], "value": rule["value"], "signal": rule.get("signal", "unclaimed_resource"), "reference": rule.get("reference"), "verification_status": provider["verification_status"], "signature_source": provider["signature_source"]})
        except (AttributeError, TypeError, KeyError):
            unsupported.append({"provider": provider["id"], "type": rule["type"], "error": "malformed rule value"})
    return matched, unsupported


def analyze_takeover(dns_intelligence: dict[str, Any] | None, http: dict[str, Any] | None = None, *, root_domain: str | None = None, generated_at: str | None = None, signatures_path: Path | None = None) -> dict[str, Any]:
    providers, signature_provenance = load_signatures(signatures_path)
    hosts = dns_intelligence.get("hosts", []) if isinstance(dns_intelligence, dict) else []
    http_rows: dict[str, list[dict[str, Any]]] = {}
    for row in (http or {}).get("records", []) if isinstance(http, dict) else []:
        if isinstance(row, dict) and isinstance(row.get("hostname"), str):
            http_rows.setdefault(row["hostname"], []).append(row)
    findings: list[dict[str, Any]] = []
    assessed: list[dict[str, Any]] = []
    unsupported_rules: list[dict[str, Any]] = []
    for host in hosts if isinstance(hosts, list) else []:
        if not isinstance(host, dict) or not host.get("cname_chain"):
            continue
        name, chain = host["hostname"], list(host["cname_chain"])
        provider = provider_for_chain(chain, providers)
        observations = http_rows.get(name, [])
        matched, unsupported = _evaluate_rules(provider, {"http": observations, "chain": chain}) if provider else ([], [])
        unsupported_rules += unsupported
        unclaimed = [rule for rule in matched if rule["signal"] == "unclaimed_resource"]
        dns_status = str(host.get("category", ""))
        dangling = bool(host.get("dangling_indicator"))
        evidence = {"cname_chain": chain, "dns_category": dns_status, "dangling_indicator": dangling, "provider": (provider or {}).get("provider"), "provider_signature_id": (provider or {}).get("id"),
                    "http_observations": [{key: row.get(key) for key in ("url", "status_code", "title")} for row in observations][:4], "matched_rules": matched,
                    "matched_fingerprint": unclaimed[0]["value"] if unclaimed else None, "body_evidence_available": any(row.get("body_excerpt") for row in observations)}
        if dns_status in {"DNS_ERROR", "DNS_TIMEOUT", "DNS_NOT_OBSERVED"}:
            classification, reason = "insufficient_evidence", "DNS for this alias was not successfully observed."
        elif provider and unclaimed:
            classification, reason = "strong_indicator", f"Alias points to {provider['provider']} and stored HTTP evidence matches a curated (unverified) unclaimed-resource signature."
        elif provider and dangling and provider["claimable_when_dangling"]:
            classification, reason = "strong_indicator", f"Alias points to a {provider['provider']} name that returned no address; the signature marks such names as re-creatable by another tenant."
        elif dangling:
            classification, reason = "potentially_vulnerable", "Alias chain returned no address; verify whether the target resource or domain is still owned by the organization."
        else:
            classification, reason = "informational", "Alias to an external service resolves normally; no unclaimed-resource signal was observed."
        assessed.append({"hostname": name, "classification": classification, "provider": (provider or {}).get("provider")})
        if classification == "informational" and not provider:
            continue
        digest = hashlib.sha256(f"takeover|{name}|{'>'.join(chain)}".encode()).hexdigest()[:16]
        findings.append({
            "finding_id": f"takeover-{digest}", "type": "subdomain_takeover_indicator", "category": "subdomain_takeover", "classification": classification,
            "asset_id": name, "hostname": name, "severity": _SEVERITY[classification], "confidence": _CONFIDENCE[classification], "reason": reason, "evidence": evidence,
            "detection_basis": "curated signature, not independently verified" if provider else "DNS evidence only",
            "recommended_remediation": "Remove or update the DNS record if the provider resource is no longer used; otherwise confirm the resource is claimed by the organization's own account. Do not attempt to claim it from an unapproved account.",
            "mitre_attack": techniques_for("subdomain_takeover") if classification in {"strong_indicator", "potentially_vulnerable"} else [],
            "source": "takeover_intelligence",
        })
    counts = {key: sum(1 for row in assessed if row["classification"] == key) for key in _SEVERITY}
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": generated_at, "root_domain": root_domain, "status": "success" if isinstance(dns_intelligence, dict) else "not_available",
            "signature_set": signature_provenance, "supported_evidence_types": sorted(EVIDENCE_MATCHERS), "unsupported_rules": unsupported_rules,
            "assessed_aliases": assessed, "classification_counts": counts, "findings": findings,
            "limitations": ["Passive evidence only; no resource is registered, claimed, or modified.", "Signatures are curated and marked unverified; a match is an indicator to investigate, not proof of takeover.",
                            "HTTP rules match stored titles (and body excerpts only when present); HTTPX in DomainRecon does not retain response bodies.", "Provider behavior changes over time; confirm indicators with the provider's documentation before acting."]}
