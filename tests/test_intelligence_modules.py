from __future__ import annotations

import csv
import io
import json

from domainrecon.core.scope import ScopePolicy
from domainrecon.intelligence.asset_correlation import correlate_assets
from domainrecon.intelligence.attack_surface import build_attack_surface
from domainrecon.intelligence.change_detection import compare_runs
from domainrecon.intelligence.dns_intelligence import analyze_dns_artifacts, generate_wildcard_labels
from domainrecon.intelligence.http_intelligence import analyze_http_inventory
from domainrecon.intelligence.vulnerability_intel import analyze_vulnerabilities
from domainrecon.reporting.unified_report import (
    build_unified_report,
    render_report_csv,
    render_report_html,
    render_report_json,
)


def test_dns_engine_classifies_records_chains_shared_infrastructure_and_security_observations() -> None:
    scope = ScopePolicy("example.com")
    passive = {"root_domain": "example.com", "status": "success", "records": [
        {"hostname": "one.example.com", "sources": ["subfinder"]},
        {"hostname": "two.example.com", "sources": ["crtsh"]},
        {"hostname": "alias.example.com", "sources": ["crtsh"]},
        {"hostname": "empty.example.com", "sources": ["subfinder"]},
        {"hostname": "lost.example.com", "sources": ["crtsh"]},
        {"hostname": "slow.example.com", "sources": ["subfinder"]},
        {"hostname": "broken.example.com", "sources": ["crtsh"]},
        {"hostname": "_dmarc.example.com", "sources": ["manual"]},
    ]}
    dns = {"root_domain": "example.com", "records": [
        {"hostname": "one.example.com", "status": "success", "records": {"a": ["8.8.8.8"], "aaaa": ["2001:4860:4860::8888"]}},
        {"hostname": "two.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}},
        {"hostname": "alias.example.com", "status": "success", "records": {"cname": ["edge.cloudfront.net"]}},
        {"hostname": "empty.example.com", "status": "success", "records": {}},
        {"hostname": "lost.example.com", "status": "failed", "error": "NXDOMAIN: no such host"},
        {"hostname": "slow.example.com", "status": "timeout", "error": "DNS timeout"},
        {"hostname": "broken.example.com", "status": "success", "records": {"cname": ["terminal.example.net"]}},
        {"hostname": "example.com", "status": "success", "records": {"txt": ["v=spf1 -all"], "caa": ["issue \"ca.example\""]}},
        {"hostname": "_dmarc.example.com", "status": "success", "records": {"txt": ["v=DMARC1; p=reject"]}},
    ]}
    result = analyze_dns_artifacts(passive, dns, scope, generated_at="fixed")
    hosts = {row["hostname"]: row for row in result["hosts"]}
    assert hosts["one.example.com"]["category"] == "DNS_RESOLVED_WITH_IP"
    assert hosts["empty.example.com"]["category"] == "DNS_NO_RECORD"
    assert hosts["lost.example.com"]["category"] == "DNS_NXDOMAIN"
    assert hosts["slow.example.com"]["category"] == "DNS_TIMEOUT"
    assert hosts["alias.example.com"]["category"] == "CNAME_ONLY"
    assert hosts["alias.example.com"]["cname_chain"] == ["edge.cloudfront.net"]
    assert hosts["alias.example.com"]["cname_chain_status"] == "unresolved_terminal"
    assert hosts["alias.example.com"]["external_provider"] == "Amazon CloudFront"
    assert hosts["broken.example.com"]["cname_chain_status"] == "unresolved_terminal"
    assert result["shared_infrastructure"]["shared_ips"][0]["hostnames"] == ["one.example.com", "two.example.com"]
    finding_types = {f["type"] for f in result["findings"]}
    assert {"spf_observation", "dmarc_observation"} <= finding_types
    caa = next(f for f in result["findings"] if f["type"] == "caa_observation")
    assert caa["classification"] == "present"


def test_dns_wildcard_detection_compares_random_answers_without_discarding_hosts() -> None:
    scope = ScopePolicy("example.com")
    passive = {"root_domain": "example.com", "status": "success", "records": [{"hostname": "app.example.com", "sources": ["crtsh"]}]}
    dns = {"root_domain": "example.com", "records": [{"hostname": "app.example.com", "status": "success", "records": {"a": ["203.0.113.8"]}}]}
    probe = {"labels": ["random1.example.com", "random2.example.com"], "records": [
        {"hostname": "random1.example.com", "status": "success", "records": {"a": ["203.0.113.8"]}},
        {"hostname": "random2.example.com", "status": "success", "records": {"a": ["203.0.113.8"]}},
    ]}
    result = analyze_dns_artifacts(passive, dns, scope, wildcard_probe=probe, generated_at="fixed")
    assert result["hosts"][0]["wildcard_status"] == "confirmed"
    assert result["findings"][0]["classification"] == "confirmed"
    assert result["hosts"][0]["hostname"] == "app.example.com"
    labels = generate_wildcard_labels(scope, count=2)
    assert len(set(labels)) == 2 and all(label.endswith(".example.com") for label in labels)


def test_dns_successful_empty_is_not_dns_failure_and_scope_mismatch_rejected() -> None:
    scope = ScopePolicy("example.com")
    result = analyze_dns_artifacts({"root_domain": "example.com", "status": "success", "records": []}, {"root_domain": "example.com", "records": [{"hostname": "x.example.com", "status": "success", "records": {}}]}, scope)
    assert result["hosts"][0]["category"] == "DNS_NO_RECORD"
    assert result["source_status"]["dns"] == "success"
    try:
        analyze_dns_artifacts(None, {"root_domain": "other.test", "records": []}, scope)
    except ValueError:
        pass
    else:
        raise AssertionError("Cross-scope DNS artifact must be rejected")


def test_dns_missing_rows_and_failed_root_do_not_claim_optional_records_absent() -> None:
    scope = ScopePolicy("example.com")
    passive = {"root_domain": "example.com", "status": "success", "records": [{"hostname": "api.example.com", "sources": ["crtsh"]}]}
    dns = {"root_domain": "example.com", "records": [
        {"hostname": "api.example.com", "status": "success", "records": {}},
        {"hostname": "example.com", "status": "failed", "error": "timeout"},
    ]}
    result = analyze_dns_artifacts(passive, dns, scope)
    assert result["hosts"][0]["category"] == "DNS_NO_RECORD"
    assert result["source_status"]["dns"] == "partial"
    assert all(row["classification"] == "not_assessed" for row in result["findings"] if row["type"] in {"spf_observation", "dmarc_observation", "caa_observation"})
    missing = analyze_dns_artifacts(passive, {"root_domain": "example.com", "records": []}, scope)
    assert missing["hosts"][0]["category"] == "DNS_NOT_OBSERVED"


def test_asset_correlation_uses_stable_fqdn_identity_and_does_not_merge_shared_cdn_ips() -> None:
    scope = ScopePolicy("example.com")
    passive = {"root_domain": "example.com", "status": "success", "records": [
        {"hostname": "api.example.com", "sources": ["subfinder", "crtsh"]},
        {"hostname": "cdn.example.com", "sources": ["crtsh"]},
    ]}
    dns = {"root_domain": "example.com", "records": [
        {"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}},
        {"hostname": "cdn.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}},
    ]}
    http = {"root_domain": "example.com", "records": [{"hostname": "api.example.com", "url": "https://api.example.com/", "status": "success", "classification": "LIVE", "technologies": ["HTML"]}]}
    nmap = {"target": "example.com", "status": "success", "hosts": [{"address": "8.8.8.8", "ports": [{"port": 443, "protocol": "tcp", "state": "open", "service": "https"}]}]}
    first = correlate_assets(scope, passive=passive, dns=dns, http=http, nmap=nmap, observed_at="fixed")
    second = correlate_assets(scope, passive=passive, dns=dns, http=http, nmap=nmap, previous_inventory=first, observed_at="later")
    hosts = [a for a in first["assets"] if a["asset_type"] == "hostname"]
    assert len(hosts) == 2
    assert len({a["asset_id"] for a in hosts}) == 2
    assert {a["asset_id"] for a in hosts} == {a["asset_id"] for a in second["assets"] if a["asset_type"] == "hostname"}
    assert hosts[0]["asset_id"] != hosts[1]["asset_id"]
    assert {"subfinder", "crtsh"} <= set(next(a for a in hosts if a["fqdn"] == "api.example.com")["discovery_sources"])
    infrastructure = next(a for a in first["assets"] if a["asset_type"] == "ip_infrastructure")
    assert infrastructure["ip_address"] == "8.8.8.8"
    assert infrastructure["services"][0]["port"] == 443
    prior_host = next(a for a in first["assets"] if a.get("fqdn") == "api.example.com")
    current_host = next(a for a in second["assets"] if a.get("fqdn") == "api.example.com")
    assert current_host["first_observed"] == prior_host["first_observed"]
    assert current_host["last_observed"] == "later"
    assert any(r["type"] == "SHARES_INFRASTRUCTURE_WITH" for r in first["relations"])


def test_attack_surface_generates_offline_provenance_edges_and_external_cname() -> None:
    scope = ScopePolicy("example.com")
    surface = build_attack_surface(scope,
        passive={"root_domain": "example.com", "records": [{"hostname": "api.example.com", "sources": ["subfinder"]}, {"hostname": "www.example.com", "sources": ["crtsh"]}]},
        dns={"root_domain": "example.com", "records": [{"hostname": "api.example.com", "records": {"a": ["8.8.8.8"], "cname": ["edge.cdn.invalid"]}}, {"hostname": "www.example.com", "records": {"a": ["8.8.8.8"]}}]},
        http={"root_domain": "example.com", "records": [{"hostname": "api.example.com", "url": "https://api.example.com/", "status_code": 200, "technologies": ["nginx"]}]},
        nmap={"target": "example.com", "hosts": [{"address": "8.8.8.8", "ports": [{"port": 443, "protocol": "tcp", "state": "open", "service": "https"}]}]},
        findings=[{"finding_id": "f1", "hostname": "api.example.com", "type": "header_observation", "confidence": "high", "evidence": {"header": "HSTS"}}],
    )
    types = {relation["type"] for relation in surface["relations"]}
    assert {"SUBDOMAIN_OF", "RESOLVES_TO", "CNAME_POINTS_TO", "HOSTS_SERVICE", "USES_TECHNOLOGY", "SHARES_INFRASTRUCTURE_WITH", "HAS_FINDING"} <= types
    external = next(node for node in surface["nodes"] if node["label"] == "edge.cdn.invalid")
    assert external["external"] is True
    assert any(node.get("authorized_nmap") for node in surface["nodes"] if node["type"] == "service")


def test_change_detection_tracks_dns_ips_http_nmap_and_cve_observation_changes() -> None:
    previous = {"root_domain": "example.com", "run_id": "r1",
        "passive": {"status": "success", "records": [{"hostname": "api.example.com"}]},
        "dns": {"status": "success", "records": [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}]},
        "http": {"status": "success", "records": [{"url": "https://api.example.com/", "status_code": 200, "classification": "LIVE"}]},
        "database": {"inventory": [{"finding_id": "db-1", "ip_address": "8.8.8.8", "port": 5432, "identity": "postgresql", "version": "14"}]},
        "vulnerability": {"status": "success", "findings": [{"finding_id": "f1", "cve_id": "CVE-2026-11111", "severity": "MEDIUM"}]},
        "nmap": {"status": "success", "hosts": [{"address": "8.8.8.8", "ports": [{"port": 443, "protocol": "tcp", "state": "open", "service": "https"}, {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "1"}]}]},
    }
    current = {"root_domain": "example.com", "run_id": "r2",
        "passive": {"status": "success", "records": [{"hostname": "api.example.com"}, {"hostname": "new.example.com"}]},
        "dns": {"status": "success", "records": [{"hostname": "api.example.com", "status": "success", "records": {"a": ["1.1.1.1"]}}]},
        "http": {"status": "success", "records": [{"url": "https://api.example.com/", "status_code": 403, "classification": "ACCESS_RESTRICTED"}]},
        "database": {"inventory": [{"finding_id": "db-1", "ip_address": "8.8.8.8", "port": 5432, "identity": "postgresql", "version": "15"}]},
        "vulnerability": {"status": "success", "findings": [{"finding_id": "f1", "cve_id": "CVE-2026-11111", "severity": "HIGH"}]},
        "nmap": {"status": "success", "hosts": [{"address": "8.8.8.8", "ports": [{"port": 8443, "protocol": "tcp", "state": "open", "service": "https-alt"}, {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "2"}]}]},
    }
    result = compare_runs(previous, current)
    kinds = {change["change_type"] for change in result["changes"]}
    assert {"subdomain_added", "ip_association_added", "ip_association_removed", "nmap_observation_added", "nmap_observation_removed", "nmap_observation_changed", "database_observation_changed", "http_observation_changed", "vulnerability_observation_changed"} <= kinds
    assert not any(row["stage"] == "http" for row in result["unknown_comparisons"])
    assert all(row["previous_run_id"] == "r1" and row["current_run_id"] == "r2" for row in result["changes"])


def test_change_detection_never_infers_removals_from_partial_http_stage() -> None:
    previous = {"root_domain": "example.com", "run_id": "r1", "http": {"status": "success", "records": [{"url": "https://api.example.com/", "status_code": 200}]}}
    current = {"root_domain": "example.com", "run_id": "r2", "http": {"status": "partial", "records": []}}
    result = compare_runs(previous, current)
    assert not any(change["change_type"] == "http_observation_removed" for change in result["changes"])
    assert any(item["stage"] == "http" for item in result["unknown_comparisons"])


def test_vulnerability_intelligence_matches_only_exact_cpe_and_keeps_exploit_metadata_passive() -> None:
    cpe = "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"
    services = {"inventory": [{
        "finding_id": "db-1", "hostname": "api.example.com", "ip_address": "8.8.8.8", "port": 443,
        "product": "Widget", "version": "1.2", "source": {"artifact": "nmap.json"},
        "evidence": {"nmap_cpes": [{"original": cpe}]},
    }]}
    feed = {"vulnerabilities": [{"cve": {
        "id": "CVE-2026-12345", "published": "2026-01-01", "lastModified": "2026-02-01",
        "descriptions": [{"lang": "en", "value": "Example issue."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 8.2}, "baseSeverity": "HIGH"}]},
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"}],
        "configurations": {"nodes": [{"cpeMatch": [{"criteria": cpe, "vulnerable": True}]}]},
    }}]}
    report = analyze_vulnerabilities(services, feed, generated_at="fixed")
    assert len(report["findings"]) == 1
    finding = report["findings"][0]
    assert finding["match_confidence"] == "high"
    assert finding["cvss_score"] == 8.2 and finding["severity"] == "HIGH"
    assert finding["exploit_availability"]["status"] == "not_listed_in_nvd_reference_tags"
    assert finding["assessment"] == "candidate_match_not_confirmed_exploitability"
    assert finding["business_impact"] == "not_assessed"
    assert finding["exploitability_assessment"] == "unknown"
    assert finding["patch_status"] == "not_assessed"
    assert analyze_vulnerabilities(services, None)["status"] == "offline_no_feed"
    mismatch = dict(feed["vulnerabilities"][0])
    mismatch["cve"] = dict(mismatch["cve"], configurations={"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:other:thing:9:*:*:*:*:*:*:*"}]}]})
    assert analyze_vulnerabilities(services, {"vulnerabilities": [mismatch]})["findings"] == []


def test_vulnerability_intel_records_nvd_exploit_tag_as_reference_only() -> None:
    cpe = "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"
    service = {"inventory": [{"finding_id": "db-1", "nmap_state": "open", "evidence": {"nmap_cpes": [{"original": cpe}]}}]}
    feed = {"vulnerabilities": [{"cve": {
        "id": "CVE-2026-22222", "cisaExploitAdd": "2026-02-01", "references": [{"url": "https://example.invalid/reference", "tags": ["Exploit"]}],
        "configurations": {"nodes": [{"cpeMatch": [{"criteria": cpe, "vulnerable": True}]}]},
    }}]}
    finding = analyze_vulnerabilities(service, feed)["findings"][0]
    assert finding["exploit_availability"] == {"status": "referenced_by_nvd_metadata", "references": ["https://example.invalid/reference"]}
    assert finding["service_exposure"] == "network_service_observed_open"
    assert finding["priority_inputs"]["asset_criticality"] == "unknown"
    assert finding["known_exploitation_status"] == "listed_in_nvd_cisa_kev_fields"


def test_http_intelligence_distinguishes_observed_and_missing_headers_and_http_statuses() -> None:
    inventory = {"root_domain": "example.com", "records": [
        {"hostname": "api.example.com", "url": "https://api.example.com/", "final_url": None, "status_code": 403, "headers": {"strict-transport-security": "max-age=31536000"}},
        {"hostname": "timeout.example.com", "url": "https://timeout.example.com/", "final_url": None, "classification": "TIMEOUT"},
    ]}
    report = analyze_http_inventory(inventory, generated_at="fixed")
    api, timeout = report["observations"]
    assert api["classification"] == "ACCESS_FORBIDDEN"
    assert api["response_headers_status"] == "observed"
    assert "HSTS" in api["security_headers"]
    assert api["final_url"] is None and api["final_url_observed"] is False
    assert timeout["classification"] == "CONNECTION_TIMEOUT"
    assert timeout["response_headers_status"] == "not_collected"


def test_unified_report_is_partial_valid_and_escapes_untrusted_content() -> None:
    scope = ScopePolicy("example.com")
    assets = {"root_domain": "example.com", "assets": [{"asset_id": "host-1", "asset_type": "hostname", "fqdn": "<script>api.example.com</script>", "ip_addresses": ["8.8.8.8"]}]}
    report = build_unified_report(scope, {"asset_inventory": assets, "http": {"root_domain": "example.com", "records": []}, "vulnerability": {"root_domain": "example.com", "status": "success", "findings": [{"finding_id": "f1", "cve_id": "CVE-2026-11111", "title": "=HYPERLINK(\"https://evil.invalid\")", "evidence": {"cpe": "exact"}}]}}, run_id="run-1", generated_at="fixed")
    assert report["status"] == "partial"
    assert report["stages"]["nmap"]["status"] == "not_run"
    decoded = json.loads(render_report_json(report))
    assert decoded["run_id"] == "run-1"
    rows = list(csv.DictReader(io.StringIO(render_report_csv(report))))
    assert rows[0]["asset_id"] == "host-1"
    assert rows[0]["record_type"] == "asset"
    finding_row = next(row for row in rows if row["record_type"] == "finding")
    assert finding_row["title"].startswith("'=")
    page = render_report_html(report)
    assert "<script>api.example.com</script>" not in page
    assert "&lt;script&gt;api.example.com&lt;/script&gt;" in page
    assert "Content-Security-Policy" in page
