from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from domainrecon.cli import main
from domainrecon.interactive import PASSIVE_ACK, InteractiveApp


def _input_sequence(values: list[str]):
    items = iter(values)
    return lambda _prompt="": next(items)


def _app(tmp_path: Path, values: list[str], **paths: Path) -> tuple[InteractiveApp, list[str]]:
    output: list[str] = []
    app = InteractiveApp(
        input_fn=_input_sequence(values),
        output_fn=output.append,
        results_root=tmp_path / "results",
        subfinder=paths.get("subfinder", tmp_path / "missing-subfinder.exe"),
        dnsx=paths.get("dnsx", tmp_path / "missing-dnsx.exe"),
        httpx=paths.get("httpx", tmp_path / "missing-httpx.exe"),
        nmap=paths.get("nmap", tmp_path / "missing-nmap.exe"),
    )
    return app, output


def test_interactive_target_validation_and_invalid_main_selection(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["bad domain", "example.com", "88", "0"])
    assert app.run() == 0
    assert app.scope is not None and app.scope.root_domain == "example.com"
    assert any("Invalid target domain" in line for line in output)
    assert any("Invalid selection" in line for line in output)
    assert any("Scope validation: VALID" in line for line in output)


def test_passive_back_navigation_does_not_collect_or_create_a_run(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "1", "0", "0"])
    with patch("domainrecon.interactive.collect_subfinder") as subfinder, patch("domainrecon.interactive.collect_crtsh") as crtsh:
        assert app.run() == 0
    subfinder.assert_not_called()
    crtsh.assert_not_called()
    assert app.session_directory is None
    assert any("[0] Back" in line for line in output)


def test_passive_wrong_acknowledgement_never_queries_a_source(tmp_path: Path) -> None:
    app, _output = _app(tmp_path, ["example.com", "1", "2", "wrong", "0"])
    with patch("domainrecon.interactive.collect_crtsh") as crtsh:
        assert app.run() == 0
    crtsh.assert_not_called()
    assert app.session_directory is None


def test_passive_and_dns_results_persist_in_session_without_reenumeration(tmp_path: Path) -> None:
    subfinder = tmp_path / "subfinder.exe"
    dnsx = tmp_path / "dnsx.exe"
    subfinder.touch()
    dnsx.touch()
    app, _output = _app(tmp_path, ["example.com", "1", "3", PASSIVE_ACK, "2", "0"], subfinder=subfinder, dnsx=dnsx)
    with patch("domainrecon.interactive.collect_subfinder", return_value=(["api.example.com"], None)) as subfinder_call, patch(
        "domainrecon.interactive.collect_crtsh", return_value=(["api.example.com", "www.example.com"], None)
    ) as crtsh_call, patch(
        "domainrecon.interactive.collect_dns",
        return_value=[
            {"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}},
            {"hostname": "www.example.com", "status": "unresolved"},
        ],
    ) as dns_call:
        assert app.run() == 0
    subfinder_call.assert_called_once()
    crtsh_call.assert_called_once()
    dns_call.assert_called_once()
    assert app.passive_authorized is True
    assert app.passive_records == [
        {"hostname": "api.example.com", "sources": ["crtsh", "subfinder"]},
        {"hostname": "www.example.com", "sources": ["crtsh"]},
    ]
    assert app.dns_records is not None and len(app.dns_records) == 2
    assert app.session_directory is not None
    passive = json.loads((app.session_directory / "passive-01" / "passive.json").read_text(encoding="utf-8"))
    dns = json.loads((app.session_directory / "dns-01" / "dns.json").read_text(encoding="utf-8"))
    assert passive["records"][0]["sources"] == ["crtsh", "subfinder"]
    assert dns["records"][0]["records"]["a"] == ["8.8.8.8"]
    assert (app.session_directory / "passive-01" / "subdomains.csv").is_file()


def test_all_passive_sources_fail_and_dns_is_blocked(tmp_path: Path) -> None:
    subfinder = tmp_path / "subfinder.exe"
    dnsx = tmp_path / "dnsx.exe"
    subfinder.touch()
    dnsx.touch()
    app, output = _app(tmp_path, ["example.com", "1", "3", PASSIVE_ACK, "2", "0"], subfinder=subfinder, dnsx=dnsx)
    with patch("domainrecon.interactive.collect_subfinder", return_value=([], "subfinder failed")), patch(
        "domainrecon.interactive.collect_crtsh", return_value=([], "crt.sh failed")
    ), patch("domainrecon.interactive.collect_dns") as dns:
        assert app.run() == 0
    dns.assert_not_called()
    assert app.passive_payload is not None and app.passive_payload["status"] == "failed"
    assert app.passive_records == []
    assert any("DNS skipped: passive collection failed" in line for line in output)
    assert any("passive collection failed; retry enumeration" in line for line in output)
    assert any(line.startswith("[3] Live Web Services Discovery") and "passive collection failed" in line for line in output)


def test_passive_failure_blocks_httpx_before_probe_process(tmp_path: Path) -> None:
    httpx = tmp_path / "httpx.exe"
    httpx.touch()
    app, output = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "3", "0"], httpx=httpx)
    with patch("domainrecon.interactive.collect_crtsh", return_value=([], "crt.sh unavailable")), patch(
        "domainrecon.interactive.probe_httpx"
    ) as probe:
        assert app.run() == 0
    probe.assert_not_called()
    assert app.passive_payload is not None and app.passive_payload["status"] == "failed"
    assert any("HTTPX blocked: passive collection failed" in line for line in output)
    assert any(line.startswith("[3] Live Web Services Discovery") and "passive collection failed" in line for line in output)


def test_successful_passive_collection_with_zero_results_is_not_failure(tmp_path: Path) -> None:
    dnsx = tmp_path / "dnsx.exe"
    dnsx.touch()
    app, output = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "2", "0"], dnsx=dnsx)
    with patch("domainrecon.interactive.collect_crtsh", return_value=([], None)), patch(
        "domainrecon.interactive.collect_dns", return_value=[]
    ) as dns:
        assert app.run() == 0
    assert app.passive_payload is not None and app.passive_payload["status"] == "success"
    assert app.passive_records == []
    dns.assert_called_once()
    assert dns.call_args.args[2] == []
    assert app.dns_records == []
    assert app.passive_session_directory == app.dns_session_directory == app.session_directory
    assert any("completed successfully with zero in-scope subdomains" in line for line in output)


def test_changing_target_resets_scope_authorization_and_session_state(tmp_path: Path) -> None:
    answers = iter(["example.com", "1", "2", PASSIVE_ACK, "2", "9", "0"])
    app: InteractiveApp

    def input_with_state_setup(prompt: str = "") -> str:
        if prompt.startswith("Enter new Target Domain"):
            app.httpx_records = [{"classification": "LIVE"}]
            app.nmap_records = {"status": "success"}
            app.database_inventory = {"inventory": [{"finding_id": "old"}]}
            app._intelligence_payloads = {"asset_inventory": {"assets": [{"asset_id": "old"}]}}
            app.last_nmap_artifact = tmp_path / "old-nmap.json"
            return "example.net"
        return next(answers)

    app = InteractiveApp(
        input_fn=input_with_state_setup,
        output_fn=lambda _line: None,
        results_root=tmp_path / "results",
        dnsx=tmp_path / "dnsx.exe",
        subfinder=tmp_path / "missing-subfinder.exe",
        httpx=tmp_path / "missing-httpx.exe",
        nmap=tmp_path / "missing-nmap.exe",
    )
    app.dnsx.touch()
    with patch("domainrecon.interactive.discover_nmap", return_value=None), patch(
        "domainrecon.interactive.collect_crtsh", return_value=(["api.example.com"], None)
    ), patch(
        "domainrecon.interactive.collect_dns",
        return_value=[{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}],
    ):
        assert app.run() == 0
    assert app.scope is not None and app.scope.root_domain == "example.net"
    assert app.passive_authorized is False
    assert app.passive_records is None
    assert app.passive_payload is None and app.source_stats is None
    assert app.passive_session_directory is None
    assert app.dns_records is None and app.dns_session_directory is None
    assert app.httpx_records is None and app.nmap_records is None
    assert app.last_nmap_artifact is None
    assert app.database_inventory is None
    assert app._intelligence_payloads == {}
    assert app.session_directory is None


def test_dns_and_httpx_block_when_passive_result_is_missing(tmp_path: Path) -> None:
    dnsx = tmp_path / "dnsx.exe"
    httpx = tmp_path / "httpx.exe"
    dnsx.touch()
    httpx.touch()
    app, output = _app(tmp_path, ["example.com", "2", "3", "0"], dnsx=dnsx, httpx=httpx)
    with patch("domainrecon.interactive.discover_nmap", return_value=None), patch(
        "domainrecon.interactive.collect_dns"
    ) as dns, patch("domainrecon.interactive.probe_httpx") as probe:
        assert app.run() == 0
    dns.assert_not_called()
    probe.assert_not_called()
    assert any("DNS skipped: no passive collection result" in line for line in output)
    assert any("HTTPX blocked: passive enumeration has not completed" in line for line in output)


def test_missing_dependencies_are_reported_and_not_invoked(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "2", "3", "4", "6", "0"])
    with patch("domainrecon.interactive.discover_nmap", return_value=None):
        assert app.run() == 0
    joined = "\n".join(output)
    assert "DNS skipped: no passive collection result" in joined
    assert "HTTPX blocked: passive enumeration has not completed" in joined
    assert "Nmap Port Scanning is unavailable" in joined
    assert "requires a successful Nmap result and a local NVD JSON feed" in joined


def test_httpx_blocks_dns_results_from_a_different_session(tmp_path: Path) -> None:
    httpx = tmp_path / "httpx.exe"
    httpx.touch()
    output: list[str] = []
    app = InteractiveApp(input_fn=lambda _prompt: "unexpected", output_fn=output.append, httpx=httpx)
    app._set_target("example.com")
    current = tmp_path / "results" / "example.com" / "current"
    app.session_directory = current
    app.passive_payload = {"status": "success"}
    app.passive_records = []
    app.source_stats = {"sources": {}}
    app.passive_session_directory = current
    app.dns_records = []
    app.dns_session_directory = tmp_path / "results" / "example.com" / "previous"
    with patch("domainrecon.interactive.probe_httpx") as probe:
        app._run_httpx()
    probe.assert_not_called()
    assert any("DNS results from the current successful passive session are required" in line for line in output)


def test_httpx_wrong_acknowledgement_never_calls_probe(tmp_path: Path) -> None:
    subfinder = tmp_path / "subfinder.exe"
    dnsx = tmp_path / "dnsx.exe"
    httpx = tmp_path / "httpx.exe"
    for executable in (subfinder, dnsx, httpx):
        executable.touch()
    app, _output = _app(
        tmp_path,
        ["example.com", "1", "3", PASSIVE_ACK, "2", "3", "not the phrase", "0"],
        subfinder=subfinder,
        dnsx=dnsx,
        httpx=httpx,
    )
    with patch("domainrecon.interactive.collect_subfinder", return_value=(["api.example.com"], None)), patch(
        "domainrecon.interactive.collect_crtsh", return_value=([], None)
    ), patch(
        "domainrecon.interactive.collect_dns",
        return_value=[{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}],
    ), patch("domainrecon.interactive.probe_httpx") as probe:
        assert app.run() == 0
    probe.assert_not_called()
    assert app.httpx_records is None


def test_nmap_wrong_acknowledgement_never_calls_scanner(tmp_path: Path) -> None:
    nmap = tmp_path / "nmap.exe"
    nmap.touch()
    app, _output = _app(tmp_path, ["example.com", "4", "1", "no", "0"], nmap=nmap)
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap version test"), patch("domainrecon.interactive.run_nmap") as scanner:
        assert app.run() == 0
    scanner.assert_not_called()
    assert app.session_directory is None


def test_nmap_resume_wrong_acknowledgement_never_calls_resume_api(tmp_path: Path) -> None:
    nmap = tmp_path / "nmap.exe"
    nmap.touch()
    resume_file = tmp_path / "results" / "example.com" / "20261111T000000Z" / "nmap-01" / "scan.nmap"
    resume_file.parent.mkdir(parents=True)
    resume_file.write_text("resume evidence placeholder\n", encoding="utf-8")
    app, _output = _app(tmp_path, ["example.com", "4", "4", "no", "0"], nmap=nmap)
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap version test"), patch(
        "domainrecon.interactive.resume_nmap"
    ) as resume:
        assert app.run() == 0
    resume.assert_not_called()
    assert app.session_directory is None


def test_full_workflow_passive_failure_skips_dns_httpx_and_nmap(tmp_path: Path) -> None:
    subfinder = tmp_path / "subfinder.exe"
    dnsx = tmp_path / "dnsx.exe"
    httpx = tmp_path / "httpx.exe"
    nmap = tmp_path / "nmap.exe"
    for executable in (subfinder, dnsx, httpx, nmap):
        executable.touch()
    app, output = _app(
        tmp_path,
        ["example.com", "7", PASSIVE_ACK, "0"],
        subfinder=subfinder,
        dnsx=dnsx,
        httpx=httpx,
        nmap=nmap,
    )
    with patch("domainrecon.interactive.discover_nmap", return_value=nmap), patch(
        "domainrecon.interactive.nmap_version", return_value="Nmap version test"
    ), patch("domainrecon.interactive.collect_subfinder", return_value=([], "subfinder failed")), patch(
        "domainrecon.interactive.collect_crtsh", return_value=([], "crt.sh failed")
    ), patch("domainrecon.interactive.collect_dns") as dns, patch(
        "domainrecon.interactive.probe_httpx"
    ) as probe, patch("domainrecon.interactive.run_nmap") as scanner:
        assert app.run() == 0
    dns.assert_not_called()
    probe.assert_not_called()
    scanner.assert_not_called()
    assert any("DNS, HTTPX, and Nmap stages were skipped" in line for line in output)


def test_full_workflow_never_starts_active_stages_without_separate_opt_in(tmp_path: Path) -> None:
    dnsx = tmp_path / "dnsx.exe"
    httpx = tmp_path / "httpx.exe"
    nmap = tmp_path / "nmap.exe"
    for executable in (dnsx, httpx, nmap):
        executable.touch()
    app, _output = _app(
        tmp_path,
        ["example.com", "7", PASSIVE_ACK, "NO", "NO", "0"],
        dnsx=dnsx,
        httpx=httpx,
        nmap=nmap,
    )
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap version test"), patch(
        "domainrecon.interactive.collect_crtsh", return_value=(["api.example.com"], None)
    ), patch(
        "domainrecon.interactive.collect_dns",
        return_value=[{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}],
    ), patch("domainrecon.interactive.probe_httpx") as probe, patch("domainrecon.interactive.run_nmap") as scanner:
        assert app.run() == 0
    probe.assert_not_called()
    scanner.assert_not_called()
    assert app.passive_records == [{"hostname": "api.example.com", "sources": ["crtsh"]}]
    assert app.dns_records is not None


def test_ctrl_c_returns_to_menu_and_exits_cleanly(tmp_path: Path) -> None:
    answers = iter(["example.com", KeyboardInterrupt(), "0"])

    def interrupt_once(_prompt=""):
        answer = next(answers)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    output: list[str] = []
    app = InteractiveApp(
        input_fn=interrupt_once,
        output_fn=output.append,
        results_root=tmp_path / "results",
        subfinder=tmp_path / "missing-subfinder.exe",
        dnsx=tmp_path / "missing-dnsx.exe",
        httpx=tmp_path / "missing-httpx.exe",
        nmap=tmp_path / "missing-nmap.exe",
    )
    assert app.run() == 0
    assert any("Cancelled. Returning to the main menu" in line for line in output)


def test_no_argument_cli_launches_interactive_without_changing_explicit_cli() -> None:
    with patch("domainrecon.interactive.run_interactive", return_value=17) as interactive:
        assert main([]) == 17
        interactive.assert_called_once_with()


def test_interactive_offline_asset_menu_persists_enveloped_inventory(tmp_path: Path) -> None:
    dnsx = tmp_path / "dnsx.exe"
    dnsx.touch()
    app, _output = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "2", "10", "3", "0", "0"], dnsx=dnsx)
    with patch("domainrecon.interactive.discover_nmap", return_value=None), patch(
        "domainrecon.interactive.collect_crtsh", return_value=(["api.example.com"], None)
    ), patch("domainrecon.interactive.collect_dns", return_value=[
        {"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}},
    ]):
        assert app.run() == 0
    assert app.session_directory is not None
    path = app.session_directory / "asset_inventory-01" / "asset_inventory.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["target"] == "example.com"
    assert payload["stage"] == "asset_inventory"
    assert payload["run_id"] == app.session_directory.name
    assert payload["assets"]


def test_wildcard_probe_requires_separate_authorization(tmp_path: Path) -> None:
    dnsx = tmp_path / "dnsx.exe"
    dnsx.touch()
    app, output = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "10", "2", "no", "0", "0"], dnsx=dnsx)
    with patch("domainrecon.interactive.collect_crtsh", return_value=([], None)), patch("domainrecon.interactive.probe_wildcard_dns") as probe:
        assert app.run() == 0
    probe.assert_not_called()
    assert any("Wildcard DNS probe not authorized" in line for line in output)


def test_interactive_unified_report_writes_json_csv_html_without_network(tmp_path: Path) -> None:
    app, _output = _app(tmp_path, ["example.com", "12", "0"])
    with patch("domainrecon.interactive.discover_nmap", return_value=None):
        assert app.run() == 0
    assert app.session_directory is not None
    report_dir = app.session_directory / "report-01"
    report = json.loads((report_dir / "unified_report.json").read_text(encoding="utf-8"))
    assert report["status"] == "partial"
    assert report["target"] == "example.com"
    assert (report_dir / "unified_report.csv").is_file()
    page = (report_dir / "unified_report.html").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in page
    assert "Limitations and Missing Data" in page


def test_stage_two_uses_local_nvd_feed_and_never_fetches_or_executes_exploits(tmp_path: Path) -> None:
    cpe = "cpe:2.3:a:acme:widget:1.2:*:*:*:*:*:*:*"
    nmap_artifact = tmp_path / "nmap.json"
    nmap_artifact.write_text(json.dumps({
        "schema_version": 1, "scanner": "nmap", "status": "success", "target": "example.com",
        "hosts": [{"address": "8.8.8.8", "ports": [{"port": 80, "protocol": "tcp", "state": "open", "service": "http", "product": "Widget", "version": "1.2", "cpes": [{"original": cpe, "vendor": "acme", "product": "widget", "version": "1.2"}]}]}],
    }), encoding="utf-8")
    feed_path = tmp_path / "nvd.json"
    feed_path.write_text(json.dumps({"vulnerabilities": [{"cve": {
        "id": "CVE-2026-12345", "descriptions": [{"lang": "en", "value": "Local fixture vulnerability."}],
        "configurations": {"nodes": [{"cpeMatch": [{"criteria": cpe, "vulnerable": True}]}]},
    }}]}), encoding="utf-8")
    app = InteractiveApp(input_fn=_input_sequence([str(feed_path)]), output_fn=lambda _line: None, results_root=tmp_path / "results")
    app._set_target("example.com")
    app.last_nmap_artifact = nmap_artifact
    app._run_vulnerability_intelligence()
    assert app.session_directory is not None
    output = json.loads((app.session_directory / "vulnerability-01" / "vulnerability_intelligence.json").read_text(encoding="utf-8"))
    assert output["status"] == "success"
    assert output["findings"][0]["cve_id"] == "CVE-2026-12345"
    assert output["findings"][0]["assessment"] == "candidate_match_not_confirmed_exploitability"


def test_kill_chain_status_discloses_actual_scope_and_limits(tmp_path: Path) -> None:
    app = InteractiveApp(input_fn=lambda _prompt="": "", output_fn=lambda _line: None, httpx=tmp_path / "missing-httpx.exe")
    output: list[str] = []
    app.output = output.append
    app._show_kill_chain_status()
    text = "\n".join(output)
    assert "Stage 01 Reconnaissance: Implemented" in text
    assert "HTTPX is unavailable in this installation (binary missing)" in text
    assert "Stage 05 Persistence Indicators: Implemented (offline)" in text
    assert "no endpoint access" in text
    assert "Stage 06 Command and Control Intelligence: Implemented (offline)" in text
    assert "DNS behavioral (tunneling) analysis is not supported" in text
    assert "no financial-loss estimation" in text
