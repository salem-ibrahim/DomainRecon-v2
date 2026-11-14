"""Cloud infrastructure attribution from DNS, HTTP, certificate, IP-range, and ASN evidence.

``confirmed_by_published_range`` is used only when an address falls inside a provider-published
range file the operator imported (AWS ip-ranges.json, Azure Service Tags JSON, Google cloud.json,
Cloudflare text lists, or a generic CSV). Everything else is an *inferred* attribution with
confidence derived from the number and strength of independent signals. No lookups are made.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
from pathlib import Path
from typing import Any

SCHEMA_ID = "domainrecon.cloud_intelligence"
SCHEMA_VERSION = 1
CNAME_PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("cloudfront.net", "AWS", "CloudFront"), ("elb.amazonaws.com", "AWS", "Elastic Load Balancing"), ("s3.amazonaws.com", "AWS", "S3"),
    ("elasticbeanstalk.com", "AWS", "Elastic Beanstalk"), ("awsglobalaccelerator.com", "AWS", "Global Accelerator"), ("amazonaws.com", "AWS", "AWS service"),
    ("azurewebsites.net", "Microsoft Azure", "App Service"), ("azurefd.net", "Microsoft Azure", "Front Door"), ("azureedge.net", "Microsoft Azure", "Azure CDN"),
    ("trafficmanager.net", "Microsoft Azure", "Traffic Manager"), ("blob.core.windows.net", "Microsoft Azure", "Blob Storage"), ("cloudapp.azure.com", "Microsoft Azure", "Cloud Services/VM"),
    ("cloudapp.net", "Microsoft Azure", "Cloud Services"), ("azure-api.net", "Microsoft Azure", "API Management"), ("azurestaticapps.net", "Microsoft Azure", "Static Web Apps"),
    ("appspot.com", "Google Cloud", "App Engine"), ("run.app", "Google Cloud", "Cloud Run"), ("storage.googleapis.com", "Google Cloud", "Cloud Storage"),
    ("ghs.googlehosted.com", "Google Cloud", "Google-hosted service"), ("googleusercontent.com", "Google Cloud", "Google user content"),
    ("cdn.cloudflare.net", "Cloudflare", "CDN"), ("cloudflare.net", "Cloudflare", "CDN"), ("digitaloceanspaces.com", "DigitalOcean", "Spaces"),
    ("ondigitalocean.app", "DigitalOcean", "App Platform"), ("fastly.net", "Fastly", "CDN"), ("akamaiedge.net", "Akamai", "CDN"), ("edgekey.net", "Akamai", "CDN"),
    ("edgesuite.net", "Akamai", "CDN"), ("herokuapp.com", "Heroku", "Apps"), ("herokudns.com", "Heroku", "Apps"), ("vercel-dns.com", "Vercel", "Hosting"),
    ("netlify.app", "Netlify", "Hosting"), ("github.io", "GitHub", "Pages"), ("oraclecloud.com", "Oracle Cloud", "OCI"),
)
HEADER_HINTS: tuple[tuple[str, str, str, str], ...] = (
    ("server", "cloudflare", "Cloudflare", "CDN/proxy"), ("cf-ray", "", "Cloudflare", "CDN/proxy"), ("x-amz-cf-id", "", "AWS", "CloudFront"),
    ("via", "cloudfront", "AWS", "CloudFront"), ("server", "amazons3", "AWS", "S3"), ("x-amz-request-id", "", "AWS", "AWS service"),
    ("x-azure-ref", "", "Microsoft Azure", "Front Door/CDN"), ("x-msedge-ref", "", "Microsoft Azure", "Edge"), ("server", "microsoft-azure-application-gateway", "Microsoft Azure", "Application Gateway"),
    ("server", "google frontend", "Google Cloud", "Google Front End"), ("server", "gws", "Google Cloud", "Google Web Server"), ("x-goog-generation", "", "Google Cloud", "Cloud Storage"),
    ("x-served-by", "cache-", "Fastly", "CDN"), ("server", "akamaighost", "Akamai", "CDN"), ("x-vercel-id", "", "Vercel", "Hosting"), ("x-nf-request-id", "", "Netlify", "Hosting"),
)
ISSUER_HINTS = (("O=Amazon", "AWS", "AWS Certificate Manager", "medium"), ("Microsoft Azure", "Microsoft Azure", "Azure-issued certificate", "medium"),
                ("Cloudflare", "Cloudflare", "Cloudflare-issued certificate", "medium"), ("Google Trust Services", "Google Cloud", "Google Trust Services certificate (widely used outside Google Cloud)", "low"))


def load_provider_ranges(path: Path, provider: str | None = None) -> list[dict[str, str]]:
    """Parse an operator-supplied published range file into ``[{"network", "provider", "service", "region"}]``."""
    if path.stat().st_size > 50_000_000:
        raise ValueError("Provider range file exceeds 50 MB.")
    text = path.read_text(encoding="utf-8-sig")
    rows: list[dict[str, str]] = []
    if path.suffix.lower() == ".json":
        data = json.loads(text)
        if isinstance(data, dict) and "prefixes" in data and "syncToken" in data:  # AWS ip-ranges.json
            for item in data.get("prefixes", []) + data.get("ipv6_prefixes", []):
                rows.append({"network": item.get("ip_prefix") or item.get("ipv6_prefix"), "provider": "AWS", "service": item.get("service", ""), "region": item.get("region", "")})
        elif isinstance(data, dict) and isinstance(data.get("values"), list):  # Azure Service Tags
            for value in data["values"]:
                for prefix in (value.get("properties") or {}).get("addressPrefixes", []):
                    rows.append({"network": prefix, "provider": "Microsoft Azure", "service": value.get("name", ""), "region": (value.get("properties") or {}).get("region", "")})
        elif isinstance(data, dict) and isinstance(data.get("prefixes"), list):  # Google cloud.json
            for item in data["prefixes"]:
                rows.append({"network": item.get("ipv4Prefix") or item.get("ipv6Prefix"), "provider": "Google Cloud", "service": item.get("service", ""), "region": item.get("scope", "")})
        else:
            raise ValueError("Unrecognized JSON range format (expected AWS, Azure Service Tags, or Google cloud.json).")
    elif path.suffix.lower() == ".csv":
        for item in csv.DictReader(io.StringIO(text)):
            rows.append({"network": item.get("network") or item.get("cidr"), "provider": item.get("provider") or provider or "", "service": item.get("service", ""), "region": item.get("region", "")})
    else:  # plain list of CIDRs (e.g. Cloudflare ips-v4 / ips-v6)
        if not provider:
            raise ValueError("A provider name is required for plain-text CIDR lists.")
        rows = [{"network": line.strip(), "provider": provider, "service": "", "region": ""} for line in text.splitlines() if line.strip() and not line.startswith("#")]
    valid = []
    for row in rows:
        try:
            row["network"] = str(ipaddress.ip_network(str(row["network"]), strict=False))
            if row["provider"]:
                valid.append(row)
        except ValueError:
            continue
    return valid


def load_asn_map(path: Path) -> list[dict[str, str]]:
    """CSV ``network,asn,organization`` exported by the operator (e.g. from RDAP/whois tooling)."""
    rows = []
    for item in csv.DictReader(io.StringIO(path.read_text(encoding="utf-8-sig"))):
        try:
            rows.append({"network": str(ipaddress.ip_network(item.get("network") or item.get("prefix") or "", strict=False)), "asn": str(item.get("asn", "")).upper().removeprefix("AS"), "organization": item.get("organization") or item.get("org") or ""})
        except ValueError:
            continue
    return rows


def _addresses(dns_hosts: list[dict[str, Any]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for host in dns_hosts:
        records = host.get("records", {}) if isinstance(host.get("records"), dict) else {}
        result[host["hostname"]] = list(records.get("a", [])) + list(records.get("aaaa", []))
    return result


def analyze_cloud(dns_intelligence: dict[str, Any] | None, *, http: dict[str, Any] | None = None, certificates: dict[str, Any] | None = None,
                  provider_ranges: list[dict[str, str]] | None = None, asn_map: list[dict[str, str]] | None = None, range_sources: list[str] | None = None) -> dict[str, Any]:
    hosts = [h for h in (dns_intelligence or {}).get("hosts", []) if isinstance(h, dict) and isinstance(h.get("hostname"), str)]
    signals: dict[str, list[dict[str, Any]]] = {}

    def add(asset: str, provider: str, service: str, kind: str, evidence: dict[str, Any], strength: str) -> None:
        signals.setdefault(asset, []).append({"provider": provider, "service": service, "evidence_type": kind, "evidence": evidence, "strength": strength})

    networks = [(ipaddress.ip_network(row["network"]), row) for row in provider_ranges or []]
    asns = [(ipaddress.ip_network(row["network"]), row) for row in asn_map or []]
    ip_facts: dict[str, dict[str, Any]] = {}
    for host, addresses in _addresses(hosts).items():
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                continue
            for network, row in networks:
                if ip.version == network.version and ip in network:
                    add(host, row["provider"], row["service"] or "published range", "published_ip_range", {"ip": address, "network": row["network"], "region": row["region"]}, "confirmed")
                    break
            asn = next((row for network, row in asns if ip.version == network.version and ip in network), None)
            if asn:
                ip_facts[address] = {"asn": asn["asn"], "organization": asn["organization"], "network": asn["network"]}
    for host in hosts:
        for hop in host.get("cname_chain", []):
            match = next((entry for entry in CNAME_PROVIDERS if hop == entry[0] or hop.endswith("." + entry[0])), None)
            if match:
                add(host["hostname"], match[1], match[2], "dns_cname", {"cname": hop}, "medium")
                break
    for row in (http or {}).get("records", []) if isinstance(http, dict) else []:
        headers = row.get("headers") if isinstance(row.get("headers"), dict) else {}
        headers = {str(k).lower(): str(v).lower() for k, v in headers.items()}
        if row.get("web_server"):
            headers.setdefault("server", str(row["web_server"]).lower())
        for header, needle, provider, service in HEADER_HINTS:
            if header in headers and needle in headers[header]:
                add(str(row.get("hostname")), provider, service, "http_header", {"header": header, "url": row.get("url")}, "medium")
    for cert in (certificates or {}).get("certificates", []) if isinstance(certificates, dict) else []:
        issuer = str(cert.get("issuer_dn") or "")
        for needle, provider, service, strength in ISSUER_HINTS:
            if needle.lower() in issuer.lower():
                for association in cert.get("observed_on", []):
                    if association.get("hostname"):
                        add(association["hostname"], provider, service, "certificate_issuer", {"issuer_dn": issuer, "certificate_id": cert.get("certificate_id")}, strength)
    attributions = []
    for asset, rows in sorted(signals.items()):
        by_provider: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            by_provider.setdefault(row["provider"], []).append(row)
        for provider, evidence in sorted(by_provider.items()):
            kinds = {row["evidence_type"] for row in evidence}
            if "published_ip_range" in kinds:
                attribution, confidence = "confirmed_by_published_range", "high"
            elif len(kinds) >= 2:
                attribution, confidence = "inferred", "high"
            elif any(row["strength"] == "medium" for row in evidence):
                attribution, confidence = "inferred", "medium"
            else:
                attribution, confidence = "inferred", "low"
            attributions.append({"asset": asset, "provider": provider, "services": sorted({row["service"] for row in evidence}), "attribution": attribution, "confidence": confidence,
                                 "evidence": evidence, "conflicting_providers": sorted(set(by_provider) - {provider})})
    providers: dict[str, int] = {}
    for row in attributions:
        providers[row["provider"]] = providers.get(row["provider"], 0) + 1
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "status": "success" if hosts or http or certificates else "not_available",
            "attributions": attributions, "provider_asset_counts": providers, "ip_ownership": ip_facts, "range_sources": range_sources or [], "findings": [],
            "limitations": ["Attribution without an imported published range is inferred, not confirmed ownership.", "CDN/proxy attribution describes the edge in front of a service, not necessarily the origin.",
                            "ASN data comes only from operator-imported maps; no WHOIS/RDAP lookup is performed by this module."]}


def range_file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
