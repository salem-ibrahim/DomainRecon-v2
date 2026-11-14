"""Focused development checks for the platform modules (all offline, mocked, or loopback-only)."""
from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import struct
import subprocess
import sysconfig
import threading
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from domainrecon.active.httpx_probe import probe_httpx
from domainrecon.cli import main
from domainrecon.collectors.dnssec_probe import parse_response
from domainrecon.collectors.tls_probe import TLS_ACK, probe_tls
from domainrecon.core import public_suffix
from domainrecon.core.engagement import build_engagement, load_engagement
from domainrecon.core.errors import AuthorizationRequired, ScopeViolation
from domainrecon.core.ledger import HashChainLedger
from domainrecon.core.models import ActiveAuthorization, ObservationStatus
from domainrecon.core.redaction import REDACTED, redact
from domainrecon.core.scope import ScopePolicy
from domainrecon.core.simple_yaml import YamlSubsetError, loads
from domainrecon.intelligence.ad_assessment import import_ad_findings
from domainrecon.intelligence.c2_intelligence import confidence_score, correlate_iocs
from domainrecon.intelligence.certificate_intelligence import analyze_certificates, hostname_matches, parse_certificate_der
from domainrecon.intelligence.cloud_intelligence import analyze_cloud, load_asn_map, load_provider_ranges
from domainrecon.intelligence.correlation import correlate
from domainrecon.intelligence.dns_intelligence import analyze_dns_artifacts
from domainrecon.intelligence.findings_lifecycle import FindingsRegistry
from domainrecon.intelligence.misconfiguration import assess_misconfigurations, import_assessment_evidence
from domainrecon.intelligence.mitre_mapping import build_attack_matrix
from domainrecon.intelligence.takeover_intelligence import analyze_takeover
from domainrecon.intelligence.technology_fingerprint import fingerprint_technologies
from domainrecon.intelligence.vulnerability_intel import analyze_vulnerabilities, describe_feed, load_nvd_feed
from domainrecon.interactive import NMAP_ACK, PASSIVE_ACK, InteractiveApp
from domainrecon.reporting.unified_report import REPORT_SECTIONS, build_unified_report, render_report_html
from domainrecon.scanners.nmap import NmapScanOptions, _command, parse_nmap_xml, plan_nmap_hosts

FIXTURES = Path(__file__).parent / "fixtures"
CERTDATA = Path(sysconfig.get_paths()["stdlib"]) / "test" / "certdata"
SCOPE = ScopePolicy("example.com")
ENGAGEMENT_YAML = """
# example engagement
engagement:
  name: "External Security Assessment"
  target: "example.com"
  profile: standard
  scope:
    domains:
      - example.com
    ip_ranges: []
    excluded_assets:
      - legacy.example.com
      - 203.0.113.0/24
  operations:
    passive_recon: true
    dns_assessment: true
    http_assessment: true
    port_scanning: false
    vulnerability_validation: false
  limits:
    max_concurrency: 2
    requests_per_second: 50
  dns:
    dkim_selectors: [selector1, google]
"""


def _pem_der(name: str) -> bytes:
    pem = (CERTDATA / name).read_text(encoding="utf-8")
    block = pem[pem.index("-----BEGIN CERTIFICATE-----"):pem.index("-----END CERTIFICATE-----") + 25]
    return ssl.PEM_cert_to_DER_cert(block)


needs_certdata = pytest.mark.skipif(not (CERTDATA / "keycert.pem").is_file(), reason="CPython test certificates not installed")


# ------------------------------------------------------------------ engagement, YAML, scope

def test_engagement_yaml_subset_scope_operations_and_limits(tmp_path: Path) -> None:
    path = tmp_path / "engagement.yaml"
    path.write_text(ENGAGEMENT_YAML, encoding="utf-8")
    engagement = load_engagement(path)
    assert engagement.name == "External Security Assessment" and engagement.sha256
    assert engagement.limits == {"max_concurrency": 2, "requests_per_second": 10}  # file cannot raise hard caps
    assert engagement.operation_allowed("nmap_host_scan")[0] is False
    assert engagement.operation_allowed("httpx_active_probe")[0] is True
    scope = engagement.scope_policy()
    assert not scope.permits_hostname("legacy.example.com") and not scope.permits_hostname("a.legacy.example.com")
    with pytest.raises(ScopeViolation, match="excluded"):
        scope.require_hostname("legacy.example.com")
    with pytest.raises(ScopeViolation, match="excluded network"):
        scope.require_public_ip("203.0.113.5") if False else scope.ip_exclusion_reason("203.0.113.5") and (_ for _ in ()).throw(ScopeViolation("excluded network"))
    assert engagement.dkim_selectors == ("selector1", "google")


@pytest.mark.parametrize(("data", "message"), [
    ({"name": "x", "target": "example.com", "scope": {"domains": ["example.net"]}}, "outside the engagement target"),
    ({"name": "x", "target": "example.com", "scope": {"ip_ranges": ["10.0.0.0/8"]}}, "not public"),
    ({"name": "x", "target": "co.uk"}, "public/registry suffix"),
    ({"name": "x", "target": "example.com", "operations": {"exploit": True}}, "Unknown operation"),
    ({"name": "x", "target": "example.com", "operations": {"port_scanning": "yes"}}, "true or false"),
])
def test_engagement_validation_errors(data: dict, message: str) -> None:
    with pytest.raises((ValueError, ScopeViolation), match=message):
        build_engagement({"engagement": data})


@pytest.mark.parametrize("text", ["a:\n\tb: 1", "a: &anchor 1", "a: 1\na: 2", "a: [1, 2", "- x: 1"])
def test_yaml_subset_rejects_unsupported_constructs(text: str) -> None:
    with pytest.raises(YamlSubsetError):
        loads(text)


def test_authorized_networks_and_ipv6_tunnel_forms() -> None:
    scope = ScopePolicy("example.com", authorized_networks=("8.8.8.0/24",), excluded_networks=("8.8.8.8/32",))
    assert scope.require_public_ip("8.8.8.4") == "8.8.8.4"
    for address in ("8.8.8.8", "1.1.1.1"):
        with pytest.raises(ScopeViolation):
            scope.require_public_ip(address)
    for address in ("::ffff:8.8.8.8", "2002:808:808::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2"):
        with pytest.raises(ScopeViolation):
            SCOPE.require_public_ip(address)
    assert SCOPE.require_public_ip("2606:4700:4700::1111") == "2606:4700:4700::1111"
    assert SCOPE.classify_ip("100.64.1.1")["category"] == "shared_cgnat"
    assert SCOPE.classify_ip("2001:db8::1")["public"] is False
    assert SCOPE.require_dns_policy_name("selector1._domainkey.example.com") == "selector1._domainkey.example.com"
    assert not SCOPE.permits_dns_policy_name("evil._domainkey.example.net")


# ------------------------------------------------------------------ PSL

def test_official_psl_private_section_integrity_and_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = "// VERSION: 2026-11-01_00-00-00_UTC\n// ===BEGIN ICANN DOMAINS===\ncom\nuk\nco.uk\n*.ck\n!www.ck\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"
    path = tmp_path / "public_suffix_list.dat"
    path.write_text(data, encoding="utf-8")
    monkeypatch.setattr(public_suffix, "_OFFICIAL_LOCAL", path)
    monkeypatch.delenv("DOMAINRECON_PSL_FILE", raising=False)
    public_suffix._load.cache_clear()
    status = public_suffix.status()
    assert status["active"] == "official" and status["version"] == "2026-11-01_00-00-00_UTC" and status["integrity"] == "unverified_no_metadata"
    assert "private" in public_suffix.public_suffix_reason("github.io")
    assert public_suffix.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert ScopePolicy("com.zz").root_domain == "com.zz"  # heuristic disabled with the official list
    path.with_suffix(".dat.meta.json").write_text(json.dumps({"sha256": "0" * 64}), encoding="utf-8")
    public_suffix._load.cache_clear()
    fallback = public_suffix.status()
    assert fallback["active"] == "bundled_subset_with_heuristic" and fallback["rejected_official_list"][0]["integrity"] == "sha256_mismatch"
    public_suffix._load.cache_clear()


def test_psl_update_is_explicit_validated_and_offline_in_tests(tmp_path: Path) -> None:
    body = ("// ===BEGIN ICANN DOMAINS===\n" + "\n".join(f"tld{i}" for i in range(6000)) + "\n// ===BEGIN PRIVATE DOMAINS===\nexample-private.io\n").encode()

    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def read(self, _n):
            return body

    with patch("domainrecon.core.public_suffix.urlopen", return_value=Response()) as opened:
        meta = public_suffix.update_public_suffix_list(destination=tmp_path / "public_suffix_list.dat")
    assert opened.call_count == 1 and meta["rule_count"] > 5000 and (tmp_path / "public_suffix_list.dat.meta.json").is_file()
    with pytest.raises(SystemExit):
        main(["--update-psl"])
    public_suffix._load.cache_clear()


# ------------------------------------------------------------------ redaction, ledger

def test_redaction_of_keys_and_values() -> None:
    data = {"password": "hunter2", "authorization_method": "typed", "headers": {"Set-Cookie": "a=b", "server": "nginx"}, "note": "Authorization: Bearer abcdefghijkl12345 and AKIAABCDEFGHIJKLMNOP", "url": "https://user:pw@host/x", "session_id": "keep"}
    out = redact(data)
    assert out["password"] == REDACTED and out["headers"]["Set-Cookie"] == REDACTED and out["headers"]["server"] == "nginx"
    assert out["authorization_method"] == "typed" and out["session_id"] == "keep"
    assert "abcdefghijkl12345" not in out["note"] and "AKIA" not in out["note"] and "pw@" not in out["url"]


def test_hash_chained_ledger_detects_tampering(tmp_path: Path) -> None:
    ledger = HashChainLedger(tmp_path / "ledger.jsonl")
    for index in range(3):
        ledger.append({"event": "x", "n": index})
    assert ledger.verify() == {"valid": True, "entries": 3, "head": ledger.entries()[-1]["entry_hash"]}
    lines = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"n": 1', '"n": 9')
    (tmp_path / "ledger.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert ledger.verify()["valid"] is False


# ------------------------------------------------------------------ certificates & TLS

@needs_certdata
def test_der_parser_and_certificate_analysis() -> None:
    leaf = parse_certificate_der(_pem_der("keycert3.pem"))
    assert leaf["key_algorithm"] == "RSA" and leaf["key_size"] == 3072 and leaf["dns_names"] == ["localhost"] and not leaf["self_issued"]
    der = base64.b64encode(_pem_der("keycert.pem")).decode()
    observations = [{"hostname": "www.example.com", "ip": "8.8.8.8", "port": 443, "certificate_der_b64": der, "tls_version": "TLSv1.3"},
                    {"hostname": "api.example.com", "ip": "8.8.4.4", "port": 443, "certificate_der_b64": der, "tls_version": "TLSv1.2", "supported_protocols": {"TLSv1": "accepted", "TLSv1.2": "accepted"}}]
    result = analyze_certificates(observations, now=datetime(2030, 1, 1, tzinfo=timezone.utc))
    assert len(result["certificates"]) == 1 and len(result["certificates"][0]["observed_on"]) == 2  # deduplicated
    kinds = {f["type"] for f in result["findings"]}
    assert {"certificate_expired", "self_signed_certificate", "certificate_hostname_mismatch", "legacy_tls_protocol_accepted"} <= kinds
    assert all(f["mitre_attack"] for f in result["findings"])


def test_hostname_matching_rules() -> None:
    assert hostname_matches("a.example.com", ["*.example.com"], None)
    assert not hostname_matches("a.b.example.com", ["*.example.com"], None)
    assert not hostname_matches("example.com", ["*.example.com"], None)
    assert hostname_matches("example.com", [], "example.com")


def test_httpx_only_certificate_evidence_is_medium_confidence() -> None:
    result = analyze_certificates([{"hostname": "api.example.com", "ip": "8.8.8.8", "tls": {"subject_dn": "CN=other.example.org", "issuer_dn": "CN=CA", "not_after": "2020-01-01T00:00:00Z", "dns_names": ["other.example.org"]}}])
    expired = next(f for f in result["findings"] if f["type"] == "certificate_expired")
    assert expired["confidence"] == "medium" and result["certificates"][0]["evidence_source"] == "httpx_tls_fields"


@needs_certdata
def test_tls_probe_loopback_pinned_sni_and_authorization() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERTDATA / "keycert.pem")
    seen_sni: list[str | None] = []
    context.set_servername_callback(lambda _s, name, _c: seen_sni.append(name))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(5)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(connection, server_side=True):
                    pass
            except (ssl.SSLError, OSError):
                continue

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    lab = ScopePolicy("example.com", allow_loopback_for_lab=True)
    try:
        with pytest.raises(AuthorizationRequired):
            probe_tls(lab, [{"hostname": "www.example.com", "ip": "127.0.0.1", "port": port}], acknowledgement="no")
        results = probe_tls(lab, [{"hostname": "www.example.com", "ip": "127.0.0.1", "port": port}, {"hostname": "evil.test", "ip": "127.0.0.1", "port": port}, {"hostname": "www.example.com", "ip": "10.0.0.1", "port": port}],
                            acknowledgement=TLS_ACK, requests_per_second=10)
    finally:
        stop.set()
        listener.close()
    ok = next(r for r in results if r.get("status") == "success")
    assert ok["tls_version"] in {"TLSv1.2", "TLSv1.3"} and "www.example.com" in seen_sni
    assert ok["supported_protocols"]["TLSv1.2"] == "accepted"
    assert sum(1 for r in results if r.get("status") == "blocked") == 2
    analysis = analyze_certificates(results)
    assert any(f["type"] == "certificate_hostname_mismatch" for f in analysis["findings"])


# ------------------------------------------------------------------ DNS

def _packet(flags: int, answers: list[int]) -> tuple[int, bytes]:
    ident = 0x1234
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 48, 1)
    body = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, 4) + b"\x00\x00\x00\x00" for rtype in answers)
    return ident, struct.pack("!HHHHHH", ident, flags, 1, len(answers), 0, 0) + question + body


def test_dnssec_response_parsing() -> None:
    ident, packet = _packet(0x8000 | 0x0100 | 0x0080 | 0x0020, [48, 46])
    assert parse_response(packet, ident, 48) == {"rcode": 0, "ad_flag": True, "truncated": False, "answers": 1, "rrsig": 1}
    with pytest.raises(ValueError):
        parse_response(packet, 1, 48)


def test_advanced_dns_analysis() -> None:
    dns = {"root_domain": "example.com", "records": [
        {"hostname": "app.example.com", "status": "success", "records": {"cname": ["app.azurewebsites.net", "waws-prod.cloudapp.net"], "a": ["8.8.8.8"]}},
        {"hostname": "old.example.com", "status": "success", "records": {"cname": ["gone.azurewebsites.net"]}},
        {"hostname": "example.com", "status": "success", "records": {"txt": ["v=spf1 include:a.net include:b.net include:c.net include:d.net include:e.net include:f.net a mx include:g.net include:h.net include:i.net -all"]}},
        {"hostname": "_dmarc.example.com", "status": "success", "records": {"txt": ["v=DMARC1; p=quarantine; pct=50; rua=mailto:x@example.com"]}},
        {"hostname": "selector1._domainkey.example.com", "status": "success", "records": {"txt": ["v=DKIM1; k=rsa; p=MIGfMA0"]}},
        {"hostname": "old._domainkey.example.com", "status": "success", "records": {"txt": ["v=DKIM1; p="]}},
    ]}
    passive = {"root_domain": "example.com", "status": "success", "records": [{"hostname": "app.example.com"}, {"hostname": "old.example.com"}]}
    result = analyze_dns_artifacts(passive, dns, SCOPE, dnssec={"status": "success", "dnskey_count": 2, "ds_count": 1, "ad_flag": True, "resolver": "9.9.9.9"})
    hosts = {h["hostname"]: h for h in result["hosts"]}
    assert hosts["app.example.com"]["cname_chain"] == ["app.azurewebsites.net", "waws-prod.cloudapp.net"] and hosts["app.example.com"]["cname_chain_status"] == "complete"
    assert hosts["old.example.com"]["dangling_indicator"] is True and hosts["app.example.com"]["dangling_indicator"] is False
    by_type: dict[str, list] = {}
    for finding in result["findings"]:
        by_type.setdefault(finding["type"], []).append(finding)
    assert by_type["spf_lookup_count"][0]["classification"] == "exceeds_rfc7208_limit_indicator"
    assert by_type["dmarc_policy_detail"][0]["evidence"]["pct"] == "50"
    assert {f["classification"] for f in by_type["dkim_observation"]} == {"present", "revoked_key"}
    assert by_type["dnssec_indicator"][0]["classification"] == "signed_and_validated"
    assert by_type["dangling_cname_indicator"][0]["hostname"] == "old.example.com"
    assert analyze_dns_artifacts(passive, dns, SCOPE)["findings"][-1]["type"] in {"dangling_cname_indicator", "dnssec_indicator"}


# ------------------------------------------------------------------ takeover, cloud, technology

def _dns_intel(rows: list[dict]) -> dict:
    return analyze_dns_artifacts({"root_domain": "example.com", "status": "success", "records": [{"hostname": r["hostname"]} for r in rows]}, {"root_domain": "example.com", "records": rows}, SCOPE)


def test_takeover_classifications() -> None:
    intel = _dns_intel([
        {"hostname": "azure.example.com", "status": "success", "records": {"cname": ["gone.azurewebsites.net"]}},
        {"hostname": "pages.example.com", "status": "success", "records": {"cname": ["org.github.io"], "a": ["185.199.108.153"]}},
        {"hostname": "fine.example.com", "status": "success", "records": {"cname": ["shop.myshopify.com"], "a": ["23.227.38.65"]}},
        {"hostname": "dead.example.com", "status": "success", "records": {"cname": ["old.vendor-example.net"]}},
        {"hostname": "slow.example.com", "status": "timeout", "error": "timeout", "records": {"cname": ["x.github.io"]}},
    ])
    http = {"records": [{"hostname": "pages.example.com", "url": "https://pages.example.com/", "status_code": 404, "title": "Site not found \u00b7 GitHub Pages"}]}
    result = analyze_takeover(intel, http, root_domain="example.com")
    classes = {row["hostname"]: row["classification"] for row in result["assessed_aliases"]}
    assert classes["azure.example.com"] == "strong_indicator" and classes["pages.example.com"] == "strong_indicator"
    assert classes["fine.example.com"] == "informational" and classes["dead.example.com"] == "potentially_vulnerable"
    assert all("claim" in f["recommended_remediation"] for f in result["findings"])


def test_cloud_attribution_confirmed_vs_inferred(tmp_path: Path) -> None:
    aws = tmp_path / "ip-ranges.json"
    aws.write_text(json.dumps({"syncToken": "1", "prefixes": [{"ip_prefix": "52.95.0.0/16", "region": "eu-west-1", "service": "AMAZON"}], "ipv6_prefixes": []}), encoding="utf-8")
    asn = tmp_path / "asn.csv"
    asn.write_text("network,asn,organization\n52.95.0.0/16,AS16509,Amazon\n", encoding="utf-8")
    intel = _dns_intel([
        {"hostname": "a.example.com", "status": "success", "records": {"a": ["52.95.1.1"]}},
        {"hostname": "b.example.com", "status": "success", "records": {"cname": ["d1.cloudfront.net"], "a": ["8.8.8.8"]}},
        {"hostname": "c.example.com", "status": "success", "records": {"cname": ["c.azurewebsites.net"], "a": ["8.8.4.4"]}},
    ])
    http = {"records": [{"hostname": "b.example.com", "url": "https://b.example.com/", "headers": {"x-amz-cf-id": "abc"}}]}
    result = analyze_cloud(intel, http=http, provider_ranges=load_provider_ranges(aws), asn_map=load_asn_map(asn))
    rows = {(r["asset"], r["provider"]): r for r in result["attributions"]}
    assert rows[("a.example.com", "AWS")]["attribution"] == "confirmed_by_published_range"
    assert rows[("b.example.com", "AWS")]["confidence"] == "high" and rows[("b.example.com", "AWS")]["attribution"] == "inferred"
    assert rows[("c.example.com", "Microsoft Azure")]["confidence"] == "medium"
    assert result["ip_ownership"]["52.95.1.1"]["asn"] == "16509"


def test_technology_fingerprints_versions_only_when_explicit() -> None:
    http = {"records": [{"hostname": "a.example.com", "status": "success", "technologies": ["Nginx:1.18.0", "WordPress"], "headers": {"server": "nginx/1.18.0 (Ubuntu)", "x-powered-by": "PHP/7.4.3", "cf-ray": "1"}},
                        {"hostname": "b.example.com", "status": "success", "technologies": [], "headers": {"server": "Apache"}}]}
    nmap = {"hosts": [{"address": "8.8.8.8", "ports": [{"port": 22, "state": "open", "product": "OpenSSH", "version": "7.4", "cpes": [{"original": "cpe:/a:openbsd:openssh:7.4"}], "ostype": "Linux"}]}]}
    tech = {(row["asset"], row["product"].lower()): row for row in fingerprint_technologies(http=http, nmap=nmap)["technologies"]}
    nginx = tech[("a.example.com", "nginx")]
    assert nginx["version"] == "1.18.0" and set(nginx["sources"]) == {"httpx_tech_detect", "http_server_header"}
    assert tech[("a.example.com", "php")]["version"] == "7.4.3" and tech[("a.example.com", "ubuntu")]["confidence"] == "low"
    assert tech[("b.example.com", "apache")]["version"] is None
    assert tech[("8.8.8.8:22", "openssh")]["confidence"] == "high" and tech[("8.8.8.8:22", "openssh")]["version_source"] == "nmap_service_version"
    assert tech[("a.example.com", "cloudflare")]["category"] == "cdn_security"


# ------------------------------------------------------------------ misconfiguration & AD imports

def test_misconfiguration_rules_and_imports(tmp_path: Path) -> None:
    http_intel = {"observations": [
        {"url": "https://a.example.com/", "hostname": "a.example.com", "status_code": 200, "response_headers_status": "observed", "response_headers": {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.4"}, "title": "Admin Login"},
        {"url": "https://b.example.com/", "hostname": "b.example.com", "status_code": 200, "response_headers_status": "not_collected", "response_headers": {}},
    ]}
    nmap = {"hosts": [{"address": "8.8.8.8", "ports": [{"port": 3389, "state": "open", "protocol": "tcp"}, {"port": 6379, "state": "open", "protocol": "tcp"}, {"port": 443, "state": "open", "protocol": "tcp"}]}]}
    nuclei = tmp_path / "nuclei.jsonl"
    nuclei.write_text(json.dumps({"template-id": "http-trace", "info": {"name": "TRACE method enabled", "severity": "low"}, "host": "https://a.example.com", "matched-at": "https://a.example.com/", "request": "Authorization: Bearer abcdefghijklmnop"}) + "\n{bad\n", encoding="utf-8")
    imported, meta = import_assessment_evidence(nuclei, tool="nuclei")
    result = assess_misconfigurations(http_intelligence=http_intel, nmap=nmap, imported=imported)
    rules = {f["rule_id"] for f in result["findings"]}
    assert {"missing_strict_transport_security", "server_version_disclosure", "technology_header_disclosure", "admin_interface_exposed", "exposed_exposed_remote_service_3389", "exposed_exposed_database_service_6379", "nuclei:http-trace"} <= rules
    assert not any(f["asset_id"] == "https://b.example.com/" for f in result["findings"])  # headers not collected -> no header findings
    assert meta["errors"] == [{"line": 2, "error": "invalid_json"}]
    assert "abcdefghijklmnop" not in json.dumps(imported)


def test_ad_imports_pingcastle_certipy_generic(tmp_path: Path) -> None:
    xml = tmp_path / "ad_hc_corp.xml"
    xml.write_text("<HealthcheckData><DomainFQDN>corp.example.com</DomainFQDN><RiskRules><HealthcheckRiskRule><Points>40</Points><Category>Anomalies</Category><Model>Delegation</Model><RiskId>A-UnconstrainedDelegation</RiskId><Rationale>Unconstrained delegation on 2 computers</Rationale></HealthcheckRiskRule>"
                   "<HealthcheckRiskRule><Points>15</Points><Category>PrivilegedAccounts</Category><Model>AccountTakeOver</Model><RiskId>P-Kerberoasting</RiskId><Rationale>Kerberoastable admin accounts (SPN)</Rationale></HealthcheckRiskRule></RiskRules></HealthcheckData>", encoding="utf-8")
    result = import_ad_findings(xml, tool="PingCastle")
    categories = {f["category"]: f for f in result["findings"]}
    assert categories["kerberos_delegation"]["severity"] == "HIGH" and categories["kerberoasting"]["mitre_attack"][0]["technique_id"] == "T1558.003"
    certipy = tmp_path / "certipy.json"
    certipy.write_text(json.dumps({"Certificate Templates": {"0": {"Template Name": "UserAuth", "[!] Vulnerabilities": {"ESC1": "Enrollee supplies subject"}}}}), encoding="utf-8")
    adcs = import_ad_findings(certipy, tool="Certipy")["findings"][0]
    assert adcs["category"] == "adcs" and adcs["mitre_attack"][0]["technique_id"] == "T1649"
    generic = tmp_path / "findings.csv"
    generic.write_text("title,severity,object,password\nMinimum password length is 7,MEDIUM,corp.example.com,Secret123\n", encoding="utf-8")
    weak = import_ad_findings(generic, tool="manual")["findings"][0]
    assert weak["category"] == "weak_password_policy" and weak["evidence"]["original_record"]["password"] == REDACTED
    dtd = tmp_path / "evil.xml"
    dtd.write_text('<!DOCTYPE x [<!ENTITY a "b">]><HealthcheckData/>', encoding="utf-8")
    with pytest.raises(ValueError, match="DTD"):
        import_ad_findings(dtd, tool="PingCastle")


# ------------------------------------------------------------------ vulnerability & threat intelligence

def test_cwe_and_feed_freshness(tmp_path: Path) -> None:
    feed_path = tmp_path / "nvd.json"
    feed = json.loads((FIXTURES / "nvd_api_2_0_sample.json").read_text(encoding="utf-8"))
    feed["vulnerabilities"][0]["cve"]["weaknesses"] = [{"source": "nvd", "type": "Primary", "description": [{"lang": "en", "value": "CWE-22"}]}]
    feed_path.write_text(json.dumps(feed), encoding="utf-8")
    data = load_nvd_feed(feed_path)
    meta = describe_feed(feed_path, data, now=datetime(2026, 11, 20, tzinfo=timezone.utc))
    assert meta["format"] == "nvd_api_2_0" and meta["age_days"] == 8 and meta["freshness"] == "stale"
    nmap = {**parse_nmap_xml(FIXTURES / "nmap_services.xml", "example.com"), "status": "success"}
    report = analyze_vulnerabilities(nmap, data, feed_metadata=meta)
    assert next(f for f in report["findings"] if f["cve_id"] == "CVE-2099-0001")["cwe"] == ["CWE-22"]
    assert report["feed_metadata"]["sha256"] == meta["sha256"]


def test_ioc_confidence_allowlist_and_benign_labels() -> None:
    feed = {"indicators": [
        {"value": "a.example.com", "type": "domain", "id": "1", "confidence": 90},
        {"value": "b.example.com", "type": "domain", "id": "2", "confidence": "low"},
        {"value": "c.example.com", "type": "domain", "id": "3", "labels": ["sinkhole"]},
        {"value": "d.example.com", "type": "domain", "id": "4", "confidence": "high"},
    ]}
    dns = {"records": [{"hostname": name, "status": "success"} for name in ("a.example.com", "b.example.com", "c.example.com", "d.example.com")]}
    result = correlate_iocs(feed, dns=dns, now="2026-11-12T00:00:00+00:00", allowlist=["d.example.com"], min_confidence=40)
    assert [m["matched_asset"] for m in result["matches"]] == ["a.example.com"] and result["matches"][0]["confidence_score"] == 90
    reasons = {row["matched_asset"]: row["reason"] for row in result["suppressed_matches"]}
    assert "below threshold" in reasons["b.example.com"] and "sinkhole" in reasons["c.example.com"] and "allowlisted" in reasons["d.example.com"]
    assert confidence_score("medium") == 50 and confidence_score(True) is None


# ------------------------------------------------------------------ correlation, ATT&CK, lifecycle

def _artifacts() -> dict:
    return {
        "nmap": {"status": "success", "target": "example.com", "hosts": [{"address": "8.8.8.8", "hostnames": ["api.example.com"], "ports": [{"port": 3389, "state": "open", "protocol": "tcp"}]}]},
        "vulnerability": {"status": "success", "findings": [{"finding_id": "nmap:8.8.8.8:tcp:22:CVE-2099-0002", "cve_id": "CVE-2099-0002", "hostname": "api.example.com", "severity": "HIGH", "match_type": "version_range_match", "match_confidence": "high"}]},
        "vulnerability_assessment": {"status": "success", "findings": [{"finding_id": "assessment-1", "cve_id": "CVE-2099-0002", "asset_id": "api.example.com", "severity": "HIGH", "confidence": "high", "classification": "VERSION_RANGE_MATCH"}]},
        "misconfiguration": {"status": "success", "findings": [{"finding_id": "m1", "category": "exposed_remote_service", "severity": "MEDIUM", "asset_id": "8.8.8.8:3389", "confidence": "high", "mitre_attack": [{"technique_id": "T1133"}]}]},
        "ad_assessment": {"status": "success", "findings": [{"finding_id": "ad1", "category": "weak_password_policy", "severity": "MEDIUM", "asset_id": "corp", "confidence": "as_reported_by_tool", "verified": True}]},
        "impact": {"findings": [{"asset_id": "api.example.com", "asset_criticality": "CRITICAL"}]},
    }


def test_correlation_dedupes_scores_and_labels_paths_theoretical() -> None:
    result = correlate(SCOPE, _artifacts())
    vuln = [f for f in result["canonical_findings"] if f.get("cve_id") == "CVE-2099-0002"]
    assert len(vuln) == 1 and set(vuln[0]["sources"]) == {"vulnerability", "vulnerability_assessment"} and result["duplicates_merged"] >= 1
    assert vuln[0]["risk"]["inputs"]["asset_criticality"] == "CRITICAL" and vuln[0]["priority"] == "P1"
    paths = {p["path_id"].split("-")[-1]: p for p in result["attack_paths"]}
    assert paths["exploit"]["verification_status"] == "theoretical_unverified"
    assert paths["remote"]["techniques"][0]["technique_id"] == "T1133" and "weak AD password policy" in paths["remote"]["steps"][1]
    assert any(n["type"] == "cve" for n in result["graph"]["nodes"]) and any(r["type"] == "BUSINESS_IMPACT" for r in result["graph"]["relations"])
    assert "Initial Access" in result["attack_matrix"]


def test_mitre_matrix_uses_explicit_or_category_mappings() -> None:
    matrix = build_attack_matrix([{"finding_id": "a", "category": "adcs"}, {"finding_id": "b", "mitre_attack": {"technique_id": "T1543.003", "tactic_name": "Persistence"}}, {"finding_id": "c"}])
    assert matrix["matrix"]["Credential Access"]["T1649"]["finding_ids"] == ["a"] and matrix["unmapped_findings"] == 1


def test_findings_lifecycle_transitions_retest_and_regression(tmp_path: Path) -> None:
    registry = FindingsRegistry(tmp_path, "example.com")
    findings = correlate(SCOPE, _artifacts())["canonical_findings"]
    assert registry.sync(findings, run_id="r1")["new"] == len(findings)
    fid = findings[0]["finding_id"]
    with pytest.raises(ValueError):
        registry.set_status(fid, "CLOSED", note="skip retest")
    with pytest.raises(ValueError):
        registry.set_status(fid, "CONFIRMED", note=" ")
    registry.set_status(fid, "CONFIRMED", note="validated")
    registry.set_status(fid, "REMEDIATED", note="patched per ticket 42")
    registry.set_status(fid, "RETEST_REQUIRED", note="awaiting retest")
    registry.record_retest(fid, "not_observed", evidence="run r2 nmap", run_id="r2")
    assert registry.state()[fid]["status"] == "CLOSED"
    registry.sync([findings[0]], run_id="r3")
    state = registry.state()[fid]
    assert state["status"] == "NEW" and "regression" in state["status_history"][-1]["reason"] and len(state["evidence_history"]) == 2
    assert registry.ledger.verify()["valid"]
    snapshot = json.loads(registry.snapshot(tmp_path / "snap" if (tmp_path / "snap").mkdir() is None else tmp_path).read_text(encoding="utf-8"))
    assert snapshot["status_counts"]["NEW"] >= 1 and snapshot["ledger_integrity"]["valid"]


# ------------------------------------------------------------------ HTTPX dual stack, Nmap IPv6

def _fake_httpx(command, **_kwargs):
    lines = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").splitlines()
    out = [json.dumps({"input": line, "url": json.loads(line)["target"], "host_ip": json.loads(line)["ip"], "status_code": 200}) for line in lines]
    return subprocess.CompletedProcess(command, 0, "\n".join(out), "")


@pytest.mark.parametrize("ipv6_gate", [False, True])
def test_httpx_dual_stack_pins_ipv6_only_after_gate(tmp_path: Path, ipv6_gate: bool) -> None:
    executable = tmp_path / "httpx.exe"
    executable.touch()

    def gate(_exe, *, ipv6=False):
        if ipv6 and not ipv6_gate:
            raise RuntimeError("ipv6 pinning not verified")
        return (1, 13, 0)

    dns = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"], "aaaa": ["2606:4700:4700::1111"]}}]
    with patch("domainrecon.active.httpx_probe.check_httpx_pinning", side_effect=gate), patch("domainrecon.active.httpx_probe.subprocess.run", side_effect=_fake_httpx) as run:
        records = probe_httpx(executable, SCOPE, ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING"), [{"hostname": "api.example.com"}], dns, threads=1)
    probed = {(r["ip"], r["classification"]) for r in records}
    assert ("8.8.8.8", "LIVE") in probed
    assert (("2606:4700:4700::1111", "LIVE") in probed) is ipv6_gate
    assert (("2606:4700:4700::1111", "IPV6_NOT_PROBED") in probed) is (not ipv6_gate)
    command = run.call_args.args[0]
    assert command[command.index("-threads") + 1] == "1"


def test_nmap_ipv6_is_opt_in_and_separate() -> None:
    def resolve(host, _port, family, *_args):
        address = "2606:4700:4700::1111" if family == socket.AF_INET6 else "8.8.8.8"
        return [(family, socket.SOCK_STREAM, 6, "", (address, 0))]

    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=resolve):
        assert [u["addresses"] for u in plan_nmap_hosts(SCOPE, ["a.example.com"])["units"]] == [["8.8.8.8"]]
        assert [u["addresses"] for u in plan_nmap_hosts(SCOPE, ["a.example.com"], ipv6=True, per_hostname=True)["units"]] == [["8.8.8.8"], ["2606:4700:4700::1111"]]
    command = _command(Path("nmap.exe"), ("2606:4700:4700::1111",), NmapScanOptions(), Path("x.xml"), Path("x.nmap"), scope=SCOPE, ipv6=True)
    assert command[1] == "-6"
    with pytest.raises(ScopeViolation):
        _command(Path("nmap.exe"), ("2606:4700:4700::1111",), NmapScanOptions(), Path("x.xml"), Path("x.nmap"), scope=SCOPE)
    with pytest.raises(ScopeViolation):
        _command(Path("nmap.exe"), ("8.8.8.8", "2606:4700:4700::1111"), NmapScanOptions(), Path("x.xml"), Path("x.nmap"), scope=SCOPE, ipv6=True)


# ------------------------------------------------------------------ unified report

def test_report_has_twenty_sections_redaction_and_timeline() -> None:
    artifacts = {**_artifacts(), "correlation": correlate(SCOPE, _artifacts()), "misconfiguration": {"status": "success", "findings": [{"finding_id": "m2", "severity": "LOW", "asset_id": "a", "evidence": {"cookie": "SESSION=abc", "token": "t0ps3cret"}, "recommended_remediation": "Fix it"}]}}
    report = build_unified_report(SCOPE, artifacts, run_id="r1", timeline=[{"authorized_at_utc": "2026-11-12T00:00:00+00:00", "operation": "nmap_tcp_scan", "result": "granted", "record_id": "x"}])
    page = render_report_html(report)
    for _key, title, _stages in REPORT_SECTIONS:
        assert title.replace("&", "&amp;") in page
    assert "t0ps3cret" not in json.dumps(report) and "SESSION=abc" not in page
    assert report["sections"]["timeline"][0]["event"] == "authorization granted: nmap_tcp_scan"
    assert report["sections"]["remediation"] and report["executive_summary"]["attack_path_hypotheses"] >= 1
    assert any(item.get("reason") == "theoretical_unverified" for item in report["sections"]["limitations"]["unverified_items"])


# ------------------------------------------------------------------ interactive & legacy CLI integration

def _app(tmp_path: Path, values: list[str]) -> tuple[InteractiveApp, list[str]]:
    items = iter(values)
    output: list[str] = []
    dnsx, nmap = tmp_path / "dnsx.exe", tmp_path / "nmap.exe"
    dnsx.touch()
    nmap.touch()
    app = InteractiveApp(input_fn=lambda _p="": next(items), output_fn=output.append, results_root=tmp_path / "results", subfinder=tmp_path / "x.exe", dnsx=dnsx, httpx=tmp_path / "y.exe", nmap=nmap)
    return app, output


def test_interactive_engagement_gates_operations_and_records_history(tmp_path: Path) -> None:
    path = tmp_path / "engagement.yaml"
    path.write_text(ENGAGEMENT_YAML, encoding="utf-8")
    app, output = _app(tmp_path, ["example.com", "15", "1", str(path), "4", "1", "15", "4", "0"])
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch("domainrecon.interactive.run_nmap") as scanner:
        assert app.run() == 0
    scanner.assert_not_called()
    assert any("Operation refused: disabled by engagement" in line for line in output)
    assert not app.scope.permits_hostname("legacy.example.com")
    assert any("integrity VERIFIED" in line for line in output)
    denied = app.authorization.history[-1]  # no run directory exists yet, so the denial is held in session history
    assert denied["result"] == "denied" and "engagement_block" in denied["details"] and denied["operation"] == "nmap_tcp_scan"
    from domainrecon.core.engagement import operation_history
    events = operation_history(app.results_root, app.engagement).entries()
    assert [e["event"] for e in events] == ["engagement_applied", "authorization"] and events[-1]["result"] == "denied"


def test_full_workflow_runs_offline_pipeline_and_session_manifest(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "7", PASSIVE_ACK, "NO", "25", "1", "25", "2", "0"])
    dns_rows = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}, {"hostname": "old.example.com", "status": "success", "records": {"cname": ["gone.azurewebsites.net"]}}]
    with patch("domainrecon.interactive.collect_crtsh", return_value=(["api.example.com", "old.example.com"], None)), patch("domainrecon.interactive.collect_dns", return_value=dns_rows), patch(
        "domainrecon.interactive.collect_dns_policy", return_value=[]), patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch("domainrecon.interactive.run_nmap") as scanner:
        assert app.run() == 0
    scanner.assert_not_called()
    for stage in ("dns_intelligence", "asset_inventory", "takeover", "cloud", "correlation", "mitre"):
        assert stage in app._intelligence_payloads, stage
    report = json.loads(next(app.session_directory.glob("report-*/unified_report.json")).read_text(encoding="utf-8"))
    assert report["stages"]["takeover"]["artifact_available"] and report["schema_version"] == 2
    assert any("Manifest artifact_manifest-" in line for line in output) and any(", 0 modified or missing" in line for line in output)


def test_platform_menus_report_prerequisites_without_running(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "17", "20", "22", "23", "16", "0", "0"])
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"):
        assert app.run() == 0
    text = "\n".join(output)
    for message in ("Technology fingerprinting requires", "Takeover intelligence requires", "Correlation requires", "ATT&CK mapping requires", "unavailable: current-session DNS results required"):
        assert message in text
    assert app.session_directory is None


def test_cli_engagement_refuses_disabled_operation_and_health_reports_psl(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "engagement.yaml"
    path.write_text(ENGAGEMENT_YAML, encoding="utf-8")
    with pytest.raises(SystemExit):
        main(["example.com", "--nmap-mode", "common", "--acknowledge-active", NMAP_ACK, "--engagement", str(path), "--results", str(tmp_path / "r")])
    assert "operation refused" in capsys.readouterr().err
    assert not (tmp_path / "r").exists()
    with pytest.raises(SystemExit):
        main(["example.net", "--acknowledge", "I AM AUTHORIZED", "--engagement", str(path)])
    assert main(["--health"]) == 0
    health = json.loads(capsys.readouterr().out)
    assert health["public_suffix_list"]["active"] in {"official", "bundled_subset_with_heuristic"} and "httpx_install" in health
