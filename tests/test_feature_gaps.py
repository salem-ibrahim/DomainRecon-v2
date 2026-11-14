"""Focused checks for the feature-gap closure: integration, IPv6 Nmap, HTTPX discovery/validation, takeover signatures, PSL install."""
from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from domainrecon.active import httpx_probe
from domainrecon.active.httpx_probe import ActiveAuthorization, check_httpx_ready, discover_httpx, inspect_httpx, probe_httpx
from domainrecon.cli import main
from domainrecon.core import public_suffix
from domainrecon.core.engagement import build_engagement
from domainrecon.core.scope import ScopePolicy
from domainrecon.intelligence.dns_intelligence import analyze_dns_artifacts
from domainrecon.intelligence.takeover_intelligence import analyze_takeover, load_signatures
from domainrecon.interactive import NMAP_ACK, PASSIVE_ACK, InteractiveApp
from domainrecon.reporting.unified_report import REPORT_SECTIONS

SCOPE = ScopePolicy("example.com")


def _app(tmp_path: Path, values: list[str], **kwargs) -> tuple[InteractiveApp, list[str]]:
    items = iter(values)
    output: list[str] = []
    dnsx, nmap = tmp_path / "dnsx.exe", tmp_path / "nmap.exe"
    dnsx.touch()
    nmap.touch()
    app = InteractiveApp(input_fn=lambda _p="": next(items), output_fn=output.append, results_root=tmp_path / "results", subfinder=tmp_path / "x.exe", dnsx=dnsx,
                         httpx=kwargs.get("httpx", tmp_path / "missing-httpx.exe"), nmap=nmap)
    return app, output


# ------------------------------------------------------------------ integration / menus

def test_platform_menu_entries_show_availability_and_none_are_decorative(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "0"])
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"):
        assert app.run() == 0
    lines = [line for line in output if line.startswith(("[15]", "[16]", "[17]", "[18]", "[19]", "[20]", "[21]", "[22]", "[23]", "[24]", "[25]"))]
    assert len(lines) == 11 and all(" - " in line for line in lines)
    assert any(line.startswith("[20] Subdomain Takeover Intelligence - needs current-session DNS results") for line in lines)
    assert any(line.startswith("[21] Active Directory Assessment Imports - available") for line in lines)


def test_impact_consumes_every_findings_stage_and_changes_have_a_report_section(tmp_path: Path) -> None:
    app, output = _app(tmp_path, [""])
    app._set_target("example.com")
    app._intelligence_payloads["takeover"] = {"status": "success", "findings": [{"finding_id": "t1", "asset_id": "old.example.com", "severity": "HIGH", "category": "subdomain_takeover"}]}
    assert app._defensive_prerequisites()["impact"] is None
    app._run_impact_analysis()
    impact = app._intelligence_payloads["impact"]
    assert [f["observed_finding"]["stage"] for f in impact["findings"]] == ["takeover"]
    assert any("changes" in stages for _key, _title, stages in REPORT_SECTIONS)


def test_vulnerability_validation_is_explicitly_deprecated() -> None:
    with pytest.raises(ValueError, match="deprecated and unsupported"):
        build_engagement({"engagement": {"name": "x", "target": "example.com", "operations": {"vulnerability_validation": True}}})
    engagement = build_engagement({"engagement": {"name": "x", "target": "example.com", "operations": {"vulnerability_validation": False}}})
    assert "vulnerability_validation" not in engagement.operations
    assert engagement.to_dict()["deprecations"][0].startswith("operations.vulnerability_validation: deprecated")


# ------------------------------------------------------------------ Nmap IPv6 in both CLIs

def _dns_success(app: InteractiveApp) -> None:
    app._set_target("example.com")
    run = app._ensure_session_directory()
    app.passive_payload, app.passive_records, app.source_stats, app.passive_session_directory = {"status": "success"}, [{"hostname": "api.example.com"}], {"sources": {}}, run
    app.dns_records, app.dns_session_directory = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}], run


@pytest.mark.parametrize(("choices", "hostnames", "per_hostname", "operation"), [
    (["6", "1", NMAP_ACK], ["example.com"], False, "nmap_tcp_scan"),
    (["5", "1", "3", NMAP_ACK], ["api.example.com"], False, "nmap_host_scan"),
    (["5", "1", "4", NMAP_ACK], ["api.example.com"], True, "nmap_host_scan"),
])
def test_interactive_nmap_ipv6_options(tmp_path: Path, choices: list[str], hostnames: list[str], per_hostname: bool, operation: str) -> None:
    app, _ = _app(tmp_path, choices)
    _dns_success(app)
    result = {"schema_version": 1, "scanner": "nmap", "target": "example.com", "status": "success", "hosts": []}
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch("domainrecon.interactive.run_nmap_hosts", return_value=result) as scanner:
        app._nmap_menu()
    assert scanner.call_args.args[2] == hostnames and scanner.call_args.kwargs["ipv6"] is True and scanner.call_args.kwargs["per_hostname"] is per_hostname
    record = [json.loads(p.read_text(encoding="utf-8")) for p in app.session_directory.glob("authorization-*.json")][-1]
    assert record["operation"] == operation and record["details"]["ipv6"] is True


def test_legacy_cli_nmap_ipv6(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    with patch("domainrecon.cli.run_nmap_hosts", return_value={"status": "success", "hosts": []}) as scanner, patch("domainrecon.cli.run_nmap") as apex:
        assert main(["example.com", "--nmap-mode", "common", "--acknowledge-active", NMAP_ACK, "--nmap-ipv6", "--results", str(tmp_path / "r")]) == 0
    apex.assert_not_called()
    assert scanner.call_args.args[2] == ["example.com"] and scanner.call_args.kwargs["ipv6"] is True
    with pytest.raises(SystemExit):
        main(["example.com", "--acknowledge", "I AM AUTHORIZED", "--nmap-ipv6"])


# ------------------------------------------------------------------ HTTPX discovery, validation, safe failure

def _version_run(output: str, code: int = 0):
    return lambda command, **_k: subprocess.CompletedProcess(command, code, "", output)


@pytest.mark.parametrize(("output", "code", "status"), [
    ("projectdiscovery.io\n[INF] Current httpx version v1.13.2", 0, "compatible_pending_loopback_gate"),
    ("[INF] Current httpx version v1.12.0", 0, "incompatible_version"),
    ("Usage: httpx [OPTIONS] URL\nError: No such option: -version", 2, "not_projectdiscovery_or_unparseable"),
])
def test_inspect_httpx_classifies_binaries(tmp_path: Path, output: str, code: int, status: str) -> None:
    executable = tmp_path / "httpx.exe"
    executable.touch()
    with patch("domainrecon.active.httpx_probe.subprocess.run", side_effect=_version_run(output, code)) as run:
        assert inspect_httpx(executable)["status"] == status
    assert run.call_args.args[0][1:] == ["-version", "-duc"]
    assert inspect_httpx(tmp_path / "absent.exe")["status"] == "not_found"


def test_discover_httpx_selects_first_compatible_candidate_and_guides(tmp_path: Path) -> None:
    old, good = tmp_path / "old.exe", tmp_path / "good.exe"
    old.touch()
    good.touch()

    def run(command, **_k):
        return subprocess.CompletedProcess(command, 0, "", "Current httpx version v1.11.0" if command[0] == str(old) else "Current httpx version v1.13.0")

    with patch.object(httpx_probe, "httpx_candidates", return_value=[tmp_path / "none.exe", old, good]), patch("domainrecon.active.httpx_probe.subprocess.run", side_effect=run):
        found = discover_httpx()
    assert found["selected"] == str(good) and found["guidance"] is None
    assert [c["status"] for c in found["candidates"]] == ["not_found", "incompatible_version", "compatible_pending_loopback_gate"]
    with patch.object(httpx_probe, "httpx_candidates", return_value=[tmp_path / "none.exe"]):
        assert "setup.ps1 -InstallTools" in discover_httpx()["guidance"]


def test_check_httpx_ready_requires_loopback_gates(tmp_path: Path) -> None:
    executable = tmp_path / "httpx.exe"
    executable.touch()

    def gate(_exe, *, ipv6=False):
        if ipv6:
            raise RuntimeError("no ipv6 pinning")
        return (1, 13, 0)

    with patch("domainrecon.active.httpx_probe.subprocess.run", side_effect=_version_run("Current httpx version v1.13.0")), patch("domainrecon.active.httpx_probe.check_httpx_pinning", side_effect=gate):
        ready = check_httpx_ready(executable)
    assert ready["ready"] is True and ready["ipv4_pinning_gate"] == "passed" and ready["ipv6_pinning_gate"].startswith("failed")
    with patch("domainrecon.active.httpx_probe.subprocess.run", side_effect=_version_run("Current httpx version v1.13.0")), patch("domainrecon.active.httpx_probe.check_httpx_pinning", side_effect=RuntimeError("pinning not honoured")):
        assert check_httpx_ready(executable)["ready"] is False


def test_missing_httpx_fails_safely_everywhere(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    dns = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}]
    with patch("domainrecon.active.httpx_probe.subprocess.run") as run:
        with pytest.raises(FileNotFoundError, match="setup.ps1"):
            probe_httpx(tmp_path / "missing.exe", SCOPE, ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING"), [{"hostname": "api.example.com"}], dns)
    run.assert_not_called()
    with patch("domainrecon.cli.discover_httpx", return_value={"selected": None, "candidates": [], "guidance": "x"}):
        assert main(["--check-httpx", "--httpx", str(tmp_path / "missing.exe")]) == 1
    assert '"ready": false' in capsys.readouterr().out
    httpx = tmp_path / "httpx.exe"
    httpx.touch()
    app, output = _app(tmp_path, ["I AUTHORIZE ACTIVE PROBING"], httpx=httpx)
    _dns_success(app)
    with patch("domainrecon.interactive.probe_httpx", side_effect=RuntimeError("HTTPX failed its loopback pinning check")):
        app._run_httpx()
    assert app.httpx_records is None and not list(app.session_directory.glob("httpx-*"))
    assert any("failed safely; no target was probed" in line for line in output) and any("--check-httpx" in line for line in output)


def test_cli_uses_discovered_httpx_without_treating_it_as_custom_path(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    discovered = tmp_path / "go" / "httpx.exe"
    with patch("domainrecon.cli.discover_httpx", return_value={"selected": str(discovered), "candidates": [{"path": str(discovered), "status": "compatible_pending_loopback_gate"}], "guidance": None}), \
         patch("domainrecon.cli.enumerate_passive_detailed", return_value=({"root_domain": "example.com", "status": "success", "errors": [], "records": []}, {"elapsed_seconds": 0, "unique_subdomains": 0, "sources": {}})):
        assert main(["example.com", "--acknowledge", "I AM AUTHORIZED", "--results", str(tmp_path / "r")]) == 0
        assert main(["--health"]) == 0
    health = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert health["httpx"].endswith("httpx.exe") and health["httpx_discovery"]["selected"] == str(discovered)


# ------------------------------------------------------------------ takeover signature architecture

def _intel(rows: list[dict]) -> dict:
    return analyze_dns_artifacts({"root_domain": "example.com", "status": "success", "records": [{"hostname": r["hostname"]} for r in rows]}, {"root_domain": "example.com", "records": rows}, SCOPE)


def test_operator_signatures_extend_providers_and_rules_without_code_changes(tmp_path: Path) -> None:
    extra = tmp_path / "signatures.json"
    extra.write_text(json.dumps({"schema_version": 1, "providers": [
        {"id": "examplecdn", "provider": "ExampleCDN", "cname_suffixes": ["examplecdn.net"], "verification_status": "operator_validated", "evidence_rules": [
            {"type": "http_status_in", "value": [404], "signal": "supporting"},
            {"type": "http_header_contains", "value": {"header": "x-examplecdn", "contains": "no-such-site"}, "signal": "unclaimed_resource", "reference": "internal-runbook-7"},
            {"type": "tls_cert_subject_contains", "value": "x"}]},
        {"id": "heroku", "provider": "Heroku", "cname_suffixes": ["herokuapp.com"], "evidence_rules": [{"type": "http_title_contains", "value": "custom heroku placeholder"}]},
    ]}), encoding="utf-8")
    intel = _intel([{"hostname": "cdn.example.com", "status": "success", "records": {"cname": ["site.examplecdn.net"], "a": ["8.8.8.8"]}},
                    {"hostname": "app.example.com", "status": "success", "records": {"cname": ["x.herokuapp.com"], "a": ["8.8.4.4"]}}])
    http = {"records": [{"hostname": "cdn.example.com", "status_code": 404, "headers": {"x-examplecdn": "no-such-site"}}, {"hostname": "app.example.com", "status_code": 200, "title": "Custom Heroku Placeholder"}]}
    bundled_only = analyze_takeover(intel, http)
    assert {row["hostname"]: row["classification"] for row in bundled_only["assessed_aliases"]} == {"cdn.example.com": "informational", "app.example.com": "informational"}
    result = analyze_takeover(intel, http, signatures_path=extra)
    classes = {row["hostname"]: row["classification"] for row in result["assessed_aliases"]}
    assert classes == {"cdn.example.com": "strong_indicator", "app.example.com": "strong_indicator"}
    cdn = next(f for f in result["findings"] if f["hostname"] == "cdn.example.com")
    assert {rule["type"] for rule in cdn["evidence"]["matched_rules"]} == {"http_status_in", "http_header_contains"} and cdn["detection_basis"].startswith("curated signature")
    assert result["unsupported_rules"] == [{"provider": "examplecdn", "type": "tls_cert_subject_contains"}]
    assert result["signature_set"]["operator_file"]["name"] == "signatures.json" and len(load_signatures()[0]) == 12


def test_supporting_rules_alone_do_not_raise_classification(tmp_path: Path) -> None:
    extra = tmp_path / "s.json"
    extra.write_text(json.dumps({"schema_version": 1, "providers": [{"id": "p", "provider": "P", "cname_suffixes": ["p.example.net"], "evidence_rules": [{"type": "http_status_in", "value": [404], "signal": "supporting"}]}]}), encoding="utf-8")
    intel = _intel([{"hostname": "x.example.com", "status": "success", "records": {"cname": ["a.p.example.net"], "a": ["8.8.8.8"]}}])
    assert analyze_takeover(intel, {"records": [{"hostname": "x.example.com", "status_code": 404}]}, signatures_path=extra)["assessed_aliases"][0]["classification"] == "informational"
    for bad in ({"schema_version": 2, "providers": []}, {"schema_version": 1, "providers": [{"id": "x", "provider": "X"}]}, {"schema_version": 1, "providers": [{"id": "x", "provider": "X", "cname_suffixes": ["a"], "evidence_rules": [{"type": "t", "value": 1, "signal": "magic"}]}]}):
        extra.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(ValueError):
            load_signatures(extra)


# ------------------------------------------------------------------ PSL install / update workflow

def _psl_text() -> str:
    return "// VERSION: test\n// ===BEGIN ICANN DOMAINS===\n" + "\n".join(f"tld{i}" for i in range(5100)) + "\nco.uk\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\ngithub.io\n// ===END PRIVATE DOMAINS===\n"


def test_offline_psl_install_validates_and_records_integrity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    destination = tmp_path / "data" / "public_suffix_list.dat"
    monkeypatch.setattr(public_suffix, "_OFFICIAL_LOCAL", destination)
    monkeypatch.delenv("DOMAINRECON_PSL_FILE", raising=False)
    source = tmp_path / "downloaded.dat"
    source.write_text(_psl_text(), encoding="utf-8")
    meta = public_suffix.install_public_suffix_list(source, destination=destination)
    assert meta["source_url"] == "local_file:downloaded.dat" and meta["private_rule_count"] == 1
    status = public_suffix.status()
    assert status["active"] == "official" and status["integrity"] == "verified"
    bad = tmp_path / "bad.dat"
    bad.write_text("not a list", encoding="utf-8")
    before = destination.read_bytes()
    with pytest.raises(ValueError):
        public_suffix.install_public_suffix_list(bad, destination=destination)
    assert destination.read_bytes() == before
    public_suffix._load.cache_clear()


def test_psl_update_refuses_other_hosts_and_redirects(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        public_suffix.update_public_suffix_list(destination=tmp_path / "p.dat", url="https://mirror.example.net/list.dat")

    class Redirected:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def geturl(self):
            return "https://evil.example.net/list.dat"
        def read(self, _n):
            return _psl_text().encode()

    with patch("domainrecon.core.public_suffix.urlopen", return_value=Redirected()):
        with pytest.raises(ValueError, match="redirected"):
            public_suffix.update_public_suffix_list(destination=tmp_path / "p.dat")
    assert not (tmp_path / "p.dat").exists()
    public_suffix._load.cache_clear()
