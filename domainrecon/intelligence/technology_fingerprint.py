"""Multi-source technology fingerprinting over stored HTTPX, Nmap, database, and TLS evidence.

Every fingerprint carries product, category, version (only when explicitly stated by a source),
version_source, evidence, sources, confidence, and the related asset. Versions are taken only
from explicit ``product/version`` banners, HTTPX ``Name:version`` technology entries, or Nmap
service-version fields; they are never inferred from generic banners. Self-reported banner
versions are labelled as such (servers can lie or be masked).
"""
from __future__ import annotations

import re
from typing import Any

SCHEMA_ID = "domainrecon.technology_inventory"
SCHEMA_VERSION = 1
CATEGORIES: dict[str, str] = {
    "nginx": "web_server", "apache httpd": "web_server", "apache": "web_server", "microsoft-iis": "web_server", "iis": "web_server", "litespeed": "web_server",
    "caddy": "web_server", "openresty": "web_server", "lighttpd": "web_server", "apache tomcat": "application_server", "tomcat": "application_server", "jetty": "application_server",
    "cloudflare": "cdn_security", "akamai": "cdn", "akamaighost": "cdn", "fastly": "cdn", "amazon cloudfront": "cdn", "cloudfront": "cdn", "varnish": "reverse_proxy", "envoy": "reverse_proxy",
    "haproxy": "reverse_proxy", "traefik": "reverse_proxy", "squid": "reverse_proxy", "wordpress": "cms", "drupal": "cms", "joomla": "cms", "magento": "ecommerce", "shopify": "ecommerce",
    "asp.net": "framework", "express": "framework", "django": "framework", "laravel": "framework", "ruby on rails": "framework", "spring": "framework", "next.js": "framework",
    "react": "javascript_library", "jquery": "javascript_library", "angular": "javascript_library", "vue.js": "javascript_library", "php": "programming_language",
    "java": "programming_language", "python": "programming_language", "node.js": "programming_language", "ruby": "programming_language",
    "mysql": "database", "mariadb": "database", "postgresql": "database", "microsoft sql server": "database", "mongodb": "database", "redis": "database", "oracle database": "database",
    "imperva": "security_waf", "incapsula": "security_waf", "sucuri": "security_waf", "f5 big-ip": "load_balancer_security", "aws waf": "security_waf", "akamai kona": "security_waf",
    "openssh": "remote_access", "microsoft terminal services": "remote_access", "windows": "operating_system", "linux": "operating_system", "ubuntu": "operating_system",
    "debian": "operating_system", "centos": "operating_system", "red hat": "operating_system", "freebsd": "operating_system",
}
_ALIASES = {"microsoft-httpapi": "microsoft-httpapi", "apache httpd": "apache httpd", "apache": "apache httpd", "iis": "microsoft-iis", "akamaighost": "akamai", "incapsula": "imperva", "cloudfront": "amazon cloudfront", "node": "node.js", "nodejs": "node.js"}
_BANNER = re.compile(r"([A-Za-z][A-Za-z0-9 ._+-]{1,40}?)/(\d+(?:\.\d+){0,3}[a-z0-9.-]*)")
_OS_HINTS = (("ubuntu", "Ubuntu"), ("debian", "Debian"), ("centos", "CentOS"), ("red hat", "Red Hat"), ("win32", "Windows"), ("win64", "Windows"), ("freebsd", "FreeBSD"))
_HEADER_PRODUCTS = (
    ("cf-ray", "", "Cloudflare"), ("x-sucuri-id", "", "Sucuri"), ("x-iinfo", "", "Imperva"), ("x-cdn", "incapsula", "Imperva"), ("x-drupal-cache", "", "Drupal"),
    ("x-generator", "drupal", "Drupal"), ("x-generator", "wordpress", "WordPress"), ("x-generator", "joomla", "Joomla"), ("x-powered-by", "express", "Express"),
    ("x-powered-by", "next.js", "Next.js"), ("x-aspnet-version", "", "ASP.NET"), ("x-aspnetmvc-version", "", "ASP.NET"), ("x-amz-cf-id", "", "Amazon CloudFront"), ("x-varnish", "", "Varnish"),
)
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


def _key(product: str) -> str:
    name = product.strip().lower()
    return _ALIASES.get(name, name)


def _category(product: str) -> str:
    key = _key(product)
    return CATEGORIES.get(key) or next((value for name, value in CATEGORIES.items() if name in key), "unknown")


class _Inventory:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, Any]] = {}

    def add(self, asset: str, product: str, *, source: str, evidence: dict[str, Any], confidence: str, version: str | None = None, version_source: str | None = None) -> None:
        product = product.strip()
        if not product or not asset:
            return
        key = (asset, _key(product))
        row = self.rows.setdefault(key, {"asset": asset, "product": product, "category": _category(product), "version": None, "version_source": None, "confidence": confidence, "sources": [], "evidence": []})
        if source not in row["sources"]:
            row["sources"].append(source)
        row["evidence"].append({"source": source, **evidence})
        if version and (row["version"] is None or version_source == "nmap_service_version"):
            row["version"], row["version_source"] = version, version_source
        if _CONFIDENCE_ORDER[confidence] > _CONFIDENCE_ORDER[row["confidence"]]:
            row["confidence"] = confidence
        if len(row["sources"]) >= 2 and row["confidence"] == "low":
            row["confidence"] = "medium"  # independent corroboration

    def items(self) -> list[dict[str, Any]]:
        return sorted(self.rows.values(), key=lambda row: (row["asset"], row["category"], row["product"].lower()))


def _banner(inventory: _Inventory, asset: str, value: str, source: str, header: str) -> None:
    matches = _BANNER.findall(value)
    for product, version in matches:
        inventory.add(asset, product.strip(), source=source, evidence={"header": header, "value": value[:200]}, confidence="medium", version=version, version_source="self_reported_banner")
    if not matches and value.strip():
        inventory.add(asset, value.split("(")[0].split(",")[0].strip()[:60], source=source, evidence={"header": header, "value": value[:200]}, confidence="medium")
    lowered = value.lower()
    for needle, os_name in _OS_HINTS:
        if needle in lowered:
            inventory.add(asset, os_name, source=source, evidence={"header": header, "value": value[:200], "note": "OS hint from banner comment"}, confidence="low")


def fingerprint_technologies(*, http: dict[str, Any] | None = None, nmap: dict[str, Any] | None = None, database: dict[str, Any] | None = None, generated_at: str | None = None) -> dict[str, Any]:
    inventory = _Inventory()
    for row in (http or {}).get("records", []) if isinstance(http, dict) else []:
        if not isinstance(row, dict) or row.get("status") not in (None, "success"):
            continue
        asset = str(row.get("hostname") or row.get("url") or "")
        for tech in row.get("technologies", []) if isinstance(row.get("technologies"), list) else []:
            name, _, version = str(tech).partition(":")
            inventory.add(asset, name, source="httpx_tech_detect", evidence={"value": str(tech)}, confidence="medium", version=version.strip() or None, version_source="httpx_tech_detect" if version.strip() else None)
        headers = {str(k).lower(): str(v) for k, v in row.get("headers", {}).items()} if isinstance(row.get("headers"), dict) else {}
        server = headers.get("server") or row.get("web_server")
        if isinstance(server, str) and server:
            _banner(inventory, asset, server, "http_server_header", "server")
        for header in ("x-powered-by", "x-aspnet-version", "x-generator"):
            if headers.get(header):
                if header == "x-aspnet-version":
                    inventory.add(asset, "ASP.NET", source="http_header", evidence={"header": header, "value": headers[header][:200]}, confidence="medium", version=headers[header].strip()[:40], version_source="self_reported_banner")
                else:
                    _banner(inventory, asset, headers[header], "http_header", header)
        for header, needle, product in _HEADER_PRODUCTS:
            if header in headers and needle in headers[header].lower():
                inventory.add(asset, product, source="http_header", evidence={"header": header}, confidence="medium")
    for host in (nmap or {}).get("hosts", []) if isinstance(nmap, dict) else []:
        if not isinstance(host, dict):
            continue
        asset = str(host.get("address"))
        for port in host.get("ports", []) if isinstance(host.get("ports"), list) else []:
            if not isinstance(port, dict) or port.get("state") != "open" or not port.get("product"):
                continue
            has_cpe = bool(port.get("cpes"))
            evidence = {"port": port.get("port"), "service": port.get("service"), "extrainfo": port.get("extrainfo"), "cpes": [c.get("original") if isinstance(c, dict) else c for c in port.get("cpes", [])]}
            inventory.add(f"{asset}:{port.get('port')}", str(port["product"]), source="nmap_service_detection", evidence=evidence, confidence="high" if has_cpe else "medium",
                          version=port.get("version") or None, version_source="nmap_service_version" if port.get("version") else None)
            if port.get("ostype"):
                inventory.add(asset, str(port["ostype"]), source="nmap_service_detection", evidence={"port": port.get("port"), "ostype": port.get("ostype")}, confidence="medium")
    for row in (database or {}).get("inventory", []) if isinstance(database, dict) else []:
        if isinstance(row, dict) and row.get("product"):
            inventory.add(f"{row.get('ip_address')}:{row.get('port')}", str(row["product"]), source="database_discovery", evidence={"finding_id": row.get("finding_id"), "detection_method": row.get("detection_method")}, confidence=str(row.get("confidence", "medium")), version=row.get("version"), version_source="nmap_service_version" if row.get("version") else None)
    items = inventory.items()
    by_category: dict[str, int] = {}
    for row in items:
        by_category[row["category"]] = by_category.get(row["category"], 0) + 1
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": generated_at, "status": "success" if (http or nmap or database) else "not_available",
            "technologies": items, "category_counts": by_category, "findings": [],
            "limitations": ["Banner versions are self-reported by the service and may be masked or false.", "Operating systems are reported only from explicit Nmap ostype fields or banner comments (low confidence).",
                            "Client-side libraries are reported only when HTTPX technology detection observed them; no crawling is performed."]}
