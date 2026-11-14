"""Phase 2 regression tests: Stage 02 CPE/CVE matching and change-detection reliability."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from domainrecon.core.scope import ScopePolicy
from domainrecon.intelligence.change_detection import compare_runs
from domainrecon.intelligence.vulnerability_assessment import assess_vulnerabilities
from domainrecon.intelligence.vulnerability_intel import analyze_vulnerabilities, compare_versions, load_nvd_feed, normalize_cpe
from domainrecon.interactive import InteractiveApp
from domainrecon.scanners.nmap import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"


def _nmap_payload() -> dict:
    parsed = parse_nmap_xml(FIXTURES / "nmap_services.xml", "example.com")
    return {**parsed, "status": "success"}


# ---------------------------------------------------------------- CPE normalization

@pytest.mark.parametrize(("value", "expected"), [
    ("cpe:/a:openbsd:openssh:7.4", "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"),
    ("cpe:/a:Apache:HTTP_Server:2.4.49", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
    ("cpe:/o:linux:linux_kernel", "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"),
    ("cpe:/a:vendor:prod%21uct:1.0", "cpe:2.3:a:vendor:prod!uct:1.0:*:*:*:*:*:*:*"),
    ("cpe:/a:vendor:product:1.0:sp1:~~pro~win~x64~", "cpe:2.3:a:vendor:product:1.0:sp1:*:*:pro:win:x64:*"),
    ("cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*", "cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*"),
    ("cpe:2.3:a:vendor:prod\\:uct:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:prod\\:uct:1.0:*:*:*:*:*:*:*"),
    ({"original": "cpe:/a:openbsd:openssh:7.4", "parse_status": "parsed"}, "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*"),
])
def test_cpe_22_and_23_normalize_to_cpe_23(value, expected: str) -> None:
    assert normalize_cpe(value)["cpe23"] == expected


@pytest.mark.parametrize("value", ["openssh 7.4", "cpe:/x:vendor:product", "cpe:2.3:a:vendor:product:1.0", "cpe:/a:a:b:c:d:e:f:g:h", None, 42])
def test_invalid_cpes_are_rejected(value) -> None:
    assert normalize_cpe(value) is None


@pytest.mark.parametrize(("left", "right", "expected"), [
    ("2.4.49", "2.4.50", -1), ("1.10", "1.9", 1), ("7.4", "7.4.0", 0), ("8.0", "7.4p1", 1), ("7.4p1", "7.4", None), ("1.0-beta", "1.0.1", None), ("", "1.0", None),
])
def test_version_comparison_is_conservative(left: str, right: str, expected) -> None:
    assert compare_versions(left, right) == expected


# ---------------------------------------------------------------- end-to-end Nmap XML -> NVD 2.0

def test_real_nmap_cpe_format_matches_nvd_2_0_with_correct_boundaries() -> None:
    report = analyze_vulnerabilities(_nmap_payload(), load_nvd_feed(FIXTURES / "nvd_api_2_0_sample.json"), generated_at="fixed")
    got = {(row["port"], row["cve_id"], row["match_type"]) for row in report["findings"]}
    assert got == {
        (22, "CVE-2099-0002", "version_range_match"),
        (22, "CVE-2099-0004", "version_range_match"),
        (80, "CVE-2099-0001", "exact_cpe_match"),
        (80, "CVE-2099-0006", "candidate_match"),
        (80, "CVE-2099-0007", "candidate_match"),
    }
    excluded = {"CVE-2099-0003", "CVE-2099-0005", "CVE-2099-0008", "CVE-2099-0009"}
    assert not excluded & {row["cve_id"] for row in report["findings"]}
    exact = next(row for row in report["findings"] if row["cve_id"] == "CVE-2099-0001")
    assert exact["service_cpe_original"] == "cpe:/a:apache:http_server:2.4.49" and exact["service_cpe_format"] == "2.2"
    assert exact["cvss_score"] == 7.5 and exact["severity"] == "HIGH" and exact["match_confidence"] == "high"
    ranged = next(row for row in report["findings"] if row["cve_id"] == "CVE-2099-0002")
    assert ranged["version_range"] == {"versionStartIncluding": "6.0", "versionEndExcluding": "8.0"}
    and_config = next(row for row in report["findings"] if row["cve_id"] == "CVE-2099-0006")
    assert "platform" in and_config["match_reason"] and and_config["match_confidence"] == "medium"
    statuses = {row["service_id"].rsplit(":", 1)[-1]: row["status"] for row in report["service_assessments"]}
    assert statuses == {"22": "matched", "80": "matched", "8080": "no_match"}
    assert report["match_type_counts"] == {"exact_cpe_match": 1, "version_range_match": 2, "candidate_match": 2}


def test_legacy_nvd_1_1_feed_ranges_and_and_nodes() -> None:
    report = analyze_vulnerabilities(_nmap_payload(), load_nvd_feed(FIXTURES / "nvd_legacy_1_1_sample.json"))
    got = {(row["cve_id"], row["match_type"]) for row in report["findings"]}
    assert got == {("CVE-2099-1001", "version_range_match"), ("CVE-2099-1002", "candidate_match")}
    legacy = next(row for row in report["findings"] if row["cve_id"] == "CVE-2099-1001")
    assert legacy["severity"] == "MEDIUM" and legacy["cvss_score"] == 5.3 and legacy["published"] == "2099-02-01T00:00Z"


def _single_service(cpe: str, version: str | None = None) -> dict:
    return {"scanner": "nmap", "status": "success", "target": "example.com", "hosts": [{"address": "203.0.113.10", "ports": [
        {"port": 22, "protocol": "tcp", "state": "open", "product": "OpenSSH", "version": version, "cpes": [{"original": cpe}]}]}]}


def _feed(item: dict) -> dict:
    return {"vulnerabilities": [{"cve": {"id": "CVE-2099-5000", "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, **item}]}]}]}}]}


def test_version_missing_is_insufficient_evidence_not_a_match() -> None:
    report = analyze_vulnerabilities(_single_service("cpe:/a:openbsd:openssh"), _feed({"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "8.0"}))
    assert report["findings"] == []
    assert report["service_assessments"][0]["status"] == "insufficient_evidence"


def test_banner_version_fallback_is_only_a_candidate() -> None:
    report = analyze_vulnerabilities(_single_service("cpe:/a:openbsd:openssh", "7.4p1 Debian 10+deb9u7"), _feed({"criteria": "cpe:2.3:a:openbsd:openssh:7.4p1:*:*:*:*:*:*:*"}))
    finding = report["findings"][0]
    assert finding["match_type"] == "candidate_match" and finding["version_source"] == "nmap_service_version"


def test_unorderable_versions_become_candidates_not_matches_or_misses() -> None:
    report = analyze_vulnerabilities(_single_service("cpe:/a:openbsd:openssh:7.4p1"), _feed({"criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "versionEndExcluding": "7.4"}))
    assert report["findings"][0]["match_type"] == "candidate_match"


def test_version_mismatch_and_similar_names_never_match() -> None:
    assert analyze_vulnerabilities(_single_service("cpe:/a:openbsd:openssh:7.4"), _feed({"criteria": "cpe:2.3:a:openbsd:openssh:7.5:*:*:*:*:*:*:*"}))["findings"] == []
    assert analyze_vulnerabilities(_single_service("cpe:/a:openbsd:openssh:7.4"), _feed({"criteria": "cpe:2.3:a:openbsd:open_ssh:7.4:*:*:*:*:*:*:*"}))["findings"] == []
    assert analyze_vulnerabilities(_single_service("cpe:/a:openbsd:openssh:7.4"), _feed({"criteria": "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*", "vulnerable": False}))["findings"] == []
    report = analyze_vulnerabilities(_single_service("cpe:/a:openbsd:openssh:7.4"), _feed({"criteria": "cpe:2.3:a:openbsd:openssh:7.4:sp1:*:*:*:*:*:*"}))
    assert report["findings"][0]["match_type"] == "candidate_match"


def test_stage_04_distinguishes_exact_range_and_candidate_matches() -> None:
    intel = analyze_vulnerabilities(_nmap_payload(), load_nvd_feed(FIXTURES / "nvd_api_2_0_sample.json"))
    classes = {row["cve_id"]: row["classification"] for row in assess_vulnerabilities(intel)["findings"]}
    assert classes["CVE-2099-0001"] == "CONFIRMED_VERSION_MATCH"
    assert classes["CVE-2099-0002"] == "VERSION_RANGE_MATCH"
    assert classes["CVE-2099-0007"] == "POSSIBLE_VERSION_MATCH"


def test_feed_size_limit(tmp_path: Path) -> None:
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="limit"):
        load_nvd_feed(feed, max_bytes=5)


def test_interactive_stage_two_matches_nmap_formatted_cpes(tmp_path: Path) -> None:
    artifact = tmp_path / "nmap.json"
    artifact.write_text(json.dumps(_nmap_payload()), encoding="utf-8")
    app = InteractiveApp(input_fn=lambda _prompt="": str(FIXTURES / "nvd_api_2_0_sample.json"), output_fn=lambda _line: None, results_root=tmp_path / "results")
    app._set_target("example.com")
    app.last_nmap_artifact = artifact
    app._run_vulnerability_intelligence()
    saved = json.loads((app.session_directory / "vulnerability-01" / "vulnerability_intelligence.json").read_text(encoding="utf-8"))
    assert len(saved["findings"]) == 5


# ---------------------------------------------------------------- change detection reliability

PREV = {"root_domain": "example.com", "run_id": "r1", "passive": {"status": "success", "errors": [], "records": [
    {"hostname": "both.example.com", "sources": ["crtsh", "subfinder"]},
    {"hostname": "sf.example.com", "sources": ["subfinder"]},
    {"hostname": "ct.example.com", "sources": ["crtsh"]},
]}}


def _status(result: dict) -> dict[str, str]:
    return {row["hostname"]: row["status"] for row in result["asset_status"]}


def test_failed_source_never_establishes_removal() -> None:
    current = {"root_domain": "example.com", "run_id": "r2", "passive_sources": {"subfinder": {"status": "failed"}, "crt.sh": {"status": "success"}},
               "passive": {"status": "success", "errors": ["subfinder exit 1"], "records": [{"hostname": "both.example.com", "sources": ["crtsh"]}]}}
    result = compare_runs(PREV, current)
    assert _status(result) == {"both.example.com": "STILL_PRESENT", "sf.example.com": "SOURCE_FAILED", "ct.example.com": "NOT_OBSERVED"}
    assert not any(change["change_type"] == "subdomain_removed" for change in result["changes"])


def test_unqueried_source_is_insufficient_data() -> None:
    current = {"root_domain": "example.com", "run_id": "r2", "passive_sources": {"crt.sh": {"status": "success"}},
               "passive": {"status": "success", "errors": [], "records": [{"hostname": "ct.example.com", "sources": ["crtsh"]}]}}
    assert _status(compare_runs(PREV, current))["sf.example.com"] == "INSUFFICIENT_DATA"


def test_missing_or_failed_current_passive_stage() -> None:
    assert set(_status(compare_runs(PREV, {"root_domain": "example.com", "run_id": "r2"})).values()) == {"INSUFFICIENT_DATA"}
    failed = {"root_domain": "example.com", "run_id": "r2", "passive": {"status": "failed", "errors": ["crt.sh HTTP 503", "subfinder failed"], "records": []}}
    assert set(_status(compare_runs(PREV, failed)).values()) == {"SOURCE_FAILED"}


def test_legacy_runs_without_source_summary_use_errors_and_observed_sources() -> None:
    current = {"root_domain": "example.com", "run_id": "r2", "passive": {"status": "success", "errors": [], "records": [{"hostname": "both.example.com", "sources": ["crtsh", "subfinder"]}]}}
    assert _status(compare_runs(PREV, current)) == {"both.example.com": "STILL_PRESENT", "sf.example.com": "NOT_OBSERVED", "ct.example.com": "NOT_OBSERVED"}


def test_confirmed_removal_requires_dns_evidence_and_preserves_history() -> None:
    previous = {**PREV, "dns": {"status": "success", "records": [{"hostname": "sf.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}]}}
    current = {"root_domain": "example.com", "run_id": "r2", "passive_sources": {"subfinder": {"status": "success"}, "crt.sh": {"status": "success"}},
               "passive": {"status": "success", "errors": [], "records": [{"hostname": "both.example.com", "sources": ["crtsh", "subfinder"]}]},
               "dns": {"status": "success", "records": [{"hostname": "sf.example.com", "status": "unresolved"}]}}
    result = compare_runs(previous, current)
    rows = {row["hostname"]: row for row in result["asset_status"]}
    assert rows["sf.example.com"]["status"] == "CONFIRMED_REMOVED"
    assert rows["sf.example.com"]["previous_observation"] == PREV["passive"]["records"][1]
    assert rows["ct.example.com"]["status"] == "NOT_OBSERVED"
    removed = [change for change in result["changes"] if change["change_type"] == "subdomain_removed"]
    assert [change["asset_identifier"] for change in removed] == ["sf.example.com"]
    assert result["asset_status_counts"]["CONFIRMED_REMOVED"] == 1


def test_interactive_history_uses_saved_source_summary(tmp_path: Path) -> None:
    run = tmp_path / "results" / "example.com" / "20261101T000000Z" / "passive-01"
    run.mkdir(parents=True)
    (run / "passive.json").write_text(json.dumps(PREV["passive"] | {"root_domain": "example.com"}), encoding="utf-8")
    (run / "enumeration_summary.json").write_text(json.dumps({"root_domain": "example.com", "passive": {"sources": {"subfinder": {"status": "success"}, "crt.sh": {"status": "failed"}}}}), encoding="utf-8")
    app = InteractiveApp(input_fn=lambda _prompt="": "", output_fn=lambda _line: None, results_root=tmp_path / "results")
    app._set_target("example.com")
    loaded = app._load_saved_run_artifacts(run.parent)
    assert loaded["passive_sources"]["crt.sh"]["status"] == "failed"
    assert ScopePolicy("example.com").root_domain == "example.com"
