from __future__ import annotations

import json
import csv
import http.client
import socket
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest

from domainrecon.active.httpx_probe import check_httpx_pinning, export_live_inventory, probe_httpx, validate_redirect
from domainrecon.analysis.comparison import compare_snapshots
from domainrecon.analysis.fingerprint import fingerprint
from domainrecon.analysis.tls import extract_tls
from domainrecon.collectors.dns_intelligence import collect_dns
from domainrecon.collectors.passive import collect_subfinder, enumerate_passive, enumerate_passive_detailed
from domainrecon.collectors.rdap import lookup_public_ip
from domainrecon.core.errors import ArtifactExists, AuthorizationRequired, ScopeViolation
from domainrecon.core.models import ActiveAuthorization, ObservationStatus
from domainrecon.core.scope import ScopePolicy, canonical_domain
from domainrecon.core.storage import create_scan_directory, read_v1_scan, write_json_artifact
from domainrecon.reports.html_report import render_report, write_report
from domainrecon.scanners.nmap import NmapScanOptions, TcpScanMode, _command, nmap_version, resume_nmap, run_nmap


def test_foundation_rejects_scope_bypass_and_deception() -> None:
    scope = ScopePolicy("example.com")
    assert scope.permits_hostname("api.example.com")
    assert not scope.permits_hostname("example.com.evil.test")
    assert not scope.permits_hostname("evilexample.com")
    for candidate in ("*.example.com", "https://api.example.com", "api.example.com:443", "api.example.com & whoami", " api.example.com"):
        assert not scope.permits_hostname(candidate)
    assert canonical_domain("BÜCHER.example") == "xn--bcher-kva.example"


def test_public_ip_policy_blocks_private_reserved_and_loopback() -> None:
    scope = ScopePolicy("example.com")
    assert scope.require_public_ip("8.8.8.8") == "8.8.8.8"
    for address in ("127.0.0.1", "10.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.1", "::1"):
        with pytest.raises(ScopeViolation):
            scope.require_public_ip(address)


def test_httpx_ip_policy_is_public_only_except_explicit_loopback_lab() -> None:
    production = ScopePolicy("example.com")
    lab = ScopePolicy("example.com", allow_loopback_for_lab=True)
    with pytest.raises(ScopeViolation):
        production.require_httpx_ip("127.0.0.1")
    assert lab.require_httpx_ip("127.0.0.1") == "127.0.0.1"
    for address in ("10.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.1", "::1", "fc00::1", "fe80::1", "ff02::1"):
        with pytest.raises(ScopeViolation):
            lab.require_httpx_ip(address)


def test_nmap_loopback_is_allowed_only_by_explicit_lab_policy() -> None:
    production_scope = ScopePolicy("example.com")
    lab_scope = ScopePolicy("example.com", allow_loopback_for_lab=True)
    with pytest.raises(ScopeViolation):
        production_scope.require_nmap_target("127.0.0.1")
    assert lab_scope.require_nmap_target("127.0.0.1") == "127.0.0.1"
    assert lab_scope.require_nmap_ip("127.0.0.1") == "127.0.0.1"
    for address in ("10.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.1", "::1", "fc00::1", "fe80::1", "ff02::1", "2001:db8::1"):
        with pytest.raises(ScopeViolation):
            lab_scope.require_nmap_ip(address)


def test_root_url_and_malicious_redirect_are_revalidated() -> None:
    scope = ScopePolicy("example.com")
    assert scope.validate_root_url("https://api.example.com/") == ("api.example.com", 443)
    assert not validate_redirect(scope, "https://evil.test/")
    assert not validate_redirect(scope, "https://api.example.com/private")
    assert not validate_redirect(scope, "ftp://api.example.com/")
    assert not validate_redirect(scope, "https://api.example.com:invalid/")


def test_immutable_artifacts_and_unique_scan_directories() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        first = create_scan_directory(root, "example.com")
        second = create_scan_directory(root, "example.com")
        assert first != second
        write_json_artifact(first, "manifest.json", {"ok": True})
        with pytest.raises(ArtifactExists):
            write_json_artifact(first, "manifest.json", {"ok": False})
        assert json.loads((first / "manifest.json").read_text(encoding="utf-8"))["ok"] is True


def test_v1_import_is_read_only_and_scope_filtered() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        scan = Path(temporary)
        original = {"domain": "example.com", "subdomains": [{"hostname": "api.example.com", "sources": ["crtsh"]}, {"hostname": "evil.test"}]}
        source = scan / "subdomains.json"
        source.write_text(json.dumps(original), encoding="utf-8")
        before = source.read_bytes()
        records = read_v1_scan(scan, ScopePolicy("example.com"))
        assert records == [{"hostname": "api.example.com", "sources": ["crtsh"]}]
        assert source.read_bytes() == before


@patch("domainrecon.collectors.dns_intelligence.subprocess.run")
def test_dns_intelligence_is_scoped_and_uses_argument_array(run: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "dnsx.exe"
        executable.touch()
        output = "\n".join([json.dumps({"host": "api.example.com", "a": ["8.8.8.8"]}), json.dumps({"host": "evil.test", "a": ["8.8.4.4"]})])
        run.return_value = subprocess.CompletedProcess([], 0, output, "")  # type: ignore[attr-defined]
        records = collect_dns(executable, ScopePolicy("example.com"), ["api.example.com", "evil.test"])
        assert records[0]["hostname"] == "api.example.com"
        assert records[0]["status"] == ObservationStatus.SUCCESS
        assert run.call_args.kwargs["shell"] is False  # type: ignore[attr-defined]
        assert "-caa" in run.call_args.args[0]  # type: ignore[attr-defined]


@patch("domainrecon.collectors.passive.subprocess.run")
def test_passive_subfinder_is_scoped_and_uses_argument_array(run: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "subfinder.exe"
        executable.touch()
        run.return_value = subprocess.CompletedProcess([], 0, "api.example.com\nevil.test\n", "")  # type: ignore[attr-defined]
        names, error = collect_subfinder(executable, ScopePolicy("example.com"))
        assert error is None and names == ["api.example.com"]
        assert run.call_args.kwargs["shell"] is False  # type: ignore[attr-defined]


@patch("domainrecon.collectors.passive.urlopen", side_effect=TimeoutError("provider timeout"))
def test_crtsh_failure_is_contained(_open: object) -> None:
    from domainrecon.collectors.passive import collect_crtsh
    names, error = collect_crtsh(ScopePolicy("example.com"), retries=0)
    assert names == []
    assert "timeout" in (error or "")


def test_passive_enumeration_deduplicates_and_records_source_statistics() -> None:
    with patch("domainrecon.collectors.passive.collect_subfinder", return_value=(["api.example.com", "shared.example.com"], None)), patch(
        "domainrecon.collectors.passive.collect_crtsh", return_value=(["shared.example.com", "www.example.com"], None)
    ):
        payload, stats = enumerate_passive_detailed(Path("subfinder"), ScopePolicy("example.com"))
    assert set(payload) == {"root_domain", "status", "errors", "records"}
    assert payload["status"] == "success"
    assert payload["records"] == [
        {"hostname": "api.example.com", "sources": ["subfinder"]},
        {"hostname": "shared.example.com", "sources": ["crtsh", "subfinder"]},
        {"hostname": "www.example.com", "sources": ["crtsh"]},
    ]
    assert stats["unique_subdomains"] == 3
    assert stats["sources"]["subfinder"]["discovered_count"] == 2
    assert stats["sources"]["crt.sh"]["discovered_count"] == 2
    assert stats["elapsed_seconds"] >= 0


def test_passive_enumeration_retains_partial_results_and_labels_failed_source() -> None:
    with patch("domainrecon.collectors.passive.collect_subfinder", return_value=([], "subfinder timed out")), patch(
        "domainrecon.collectors.passive.collect_crtsh", return_value=(["api.example.com"], None)
    ):
        payload, stats = enumerate_passive_detailed(Path("subfinder"), ScopePolicy("example.com"))
    assert payload["status"] == "success"
    assert payload["records"] == [{"hostname": "api.example.com", "sources": ["crtsh"]}]
    assert payload["errors"] == ["subfinder timed out"]
    assert stats["sources"]["subfinder"]["status"] == "failed"
    assert stats["sources"]["crt.sh"]["status"] == "success"


def test_subfinder_timeout_is_returned_as_a_source_error() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "subfinder.exe"
        executable.touch()
        with patch("domainrecon.collectors.passive.subprocess.run", side_effect=subprocess.TimeoutExpired([str(executable)], 360)):
            names, error = collect_subfinder(executable, ScopePolicy("example.com"))
    assert names == []
    assert "timed out" in (error or "").lower()


def test_missing_dnsx_returns_failed_rows_without_invoking_a_process() -> None:
    records = collect_dns(Path("missing-dnsx.exe"), ScopePolicy("example.com"), ["api.example.com", "evil.test"])
    assert records == [{"hostname": "api.example.com", "status": ObservationStatus.FAILED, "error": "dnsx is not installed"}]


def test_passive_cli_writes_compatible_json_summary_and_readable_exports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from domainrecon.cli import main

    passive = {
        "root_domain": "example.com",
        "status": "success",
        "errors": [],
        "records": [
            {"hostname": "api.example.com", "sources": ["subfinder", "crtsh"]},
            {"hostname": "missing.example.com", "sources": ["crtsh"]},
            {"hostname": "slow.example.com", "sources": ["subfinder"]},
        ],
    }
    stats = {
        "elapsed_seconds": 0.02,
        "unique_subdomains": 3,
        "sources": {
            "subfinder": {"status": "success", "discovered_count": 2, "elapsed_seconds": 0.01, "error": None},
            "crt.sh": {"status": "success", "discovered_count": 2, "elapsed_seconds": 0.01, "error": None},
        },
    }
    dns_records = [
        {"hostname": "api.example.com", "status": "success", "records": {"host": "api.example.com", "a": ["8.8.8.8"]}},
        {"hostname": "missing.example.com", "status": "unresolved"},
        {"hostname": "slow.example.com", "status": "failed", "error": "dnsx is not installed"},
    ]
    results = tmp_path / "results"
    monkeypatch.setattr(sys, "argv", ["main.py", "example.com", "--acknowledge", "I AM AUTHORIZED", "--dns", "--results", str(results)])
    with patch("domainrecon.cli.enumerate_passive_detailed", return_value=(passive, stats)), patch("domainrecon.cli.collect_dns", return_value=dns_records) as dns_call, patch(
        "domainrecon.cli.collect_dns_policy", return_value=[]
    ):
        exit_code = main()
    scan_dir = Path(capsys.readouterr().out.strip())
    assert exit_code == 1  # Partial output is saved, but a requested source failed.
    assert dns_call.call_args.args[2] == ["api.example.com", "missing.example.com", "slow.example.com"]
    passive_json = json.loads((scan_dir / "passive.json").read_text(encoding="utf-8"))
    dns_json = json.loads((scan_dir / "dns.json").read_text(encoding="utf-8"))
    assert passive_json == passive
    assert set(passive_json) == {"root_domain", "status", "errors", "records"}
    assert dns_json == {"root_domain": "example.com", "records": dns_records}
    summary = json.loads((scan_dir / "enumeration_summary.json").read_text(encoding="utf-8"))
    assert summary["passive"]["sources"] == stats["sources"]
    assert summary["dns"]["resolved"] == ["api.example.com"]
    assert summary["dns"]["unresolved"] == ["missing.example.com"]
    assert summary["dns"]["failed"] == ["slow.example.com"]
    with (scan_dir / "subdomains.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["sources"] == "crtsh;subfinder"
    assert rows[0]["addresses"] == "8.8.8.8"
    text = (scan_dir / "subdomains.txt").read_text(encoding="utf-8")
    assert "api.example.com" in text and "DNS=success" in text
    assert all((scan_dir / name).is_file() for name in ("scan_manifest.json", "passive.json", "dns.json", "enumeration_summary.json", "subdomains.csv", "subdomains.txt"))


def test_passive_cli_without_dns_never_invokes_dnsx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from domainrecon.cli import main

    passive = {"root_domain": "example.com", "status": "success", "errors": [], "records": [{"hostname": "api.example.com", "sources": ["crtsh"]}]}
    stats = {"elapsed_seconds": 0.01, "unique_subdomains": 1, "sources": {"subfinder": {"status": "success", "discovered_count": 1, "elapsed_seconds": 0.005, "error": None}, "crt.sh": {"status": "success", "discovered_count": 1, "elapsed_seconds": 0.005, "error": None}}}
    results = tmp_path / "results"
    monkeypatch.setattr(sys, "argv", ["main.py", "example.com", "--acknowledge", "I AM AUTHORIZED", "--results", str(results)])
    with patch("domainrecon.cli.enumerate_passive_detailed", return_value=(passive, stats)), patch("domainrecon.cli.collect_dns") as dns_call:
        assert main() == 0
    scan_dir = Path(capsys.readouterr().out.strip())
    dns_call.assert_not_called()
    assert not (scan_dir / "dns.json").exists()
    summary = json.loads((scan_dir / "enumeration_summary.json").read_text(encoding="utf-8"))
    assert summary["dns"]["status"] == "not_requested"
    with (scan_dir / "subdomains.csv").open(encoding="utf-8", newline="") as handle:
        assert next(csv.DictReader(handle))["dns_status"] == "not_requested"


def test_passive_cli_validates_hosts_file_before_creating_output_or_collecting(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from domainrecon.cli import main

    results = tmp_path / "results"
    monkeypatch.setattr(sys, "argv", ["main.py", "example.com", "--acknowledge", "I AM AUTHORIZED", "--dns", "--hosts-file", str(tmp_path / "missing.txt"), "--results", str(results)])
    with patch("domainrecon.cli.enumerate_passive_detailed") as passive_call, patch("domainrecon.cli.collect_dns") as dns_call:
        with pytest.raises(SystemExit) as error:
            main()
    assert error.value.code == 2
    assert not results.exists()
    passive_call.assert_not_called()
    dns_call.assert_not_called()


def test_httpx_cli_requires_dns_and_explicit_active_ack_before_collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from domainrecon.cli import main

    results = tmp_path / "results"
    monkeypatch.setattr(sys, "argv", ["main.py", "example.com", "--acknowledge", "I AM AUTHORIZED", "--http-probe", "--results", str(results)])
    with patch("domainrecon.cli.check_httpx_pinning") as pin_check, patch("domainrecon.cli.enumerate_passive_detailed") as passive_call:
        with pytest.raises(SystemExit) as error:
            main()
    assert error.value.code == 2
    assert not results.exists()
    pin_check.assert_not_called()
    passive_call.assert_not_called()


def test_httpx_cli_writes_separate_live_web_inventory_artifacts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from domainrecon.cli import main

    passive = {"root_domain": "example.com", "status": "success", "errors": [], "records": [{"hostname": "api.example.com", "sources": ["subfinder"]}]}
    stats = {"elapsed_seconds": 0.01, "unique_subdomains": 1, "sources": {"subfinder": {"status": "success", "discovered_count": 1, "elapsed_seconds": 0.01, "error": None}}}
    dns = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}]
    http_records = [{"hostname": "api.example.com", "url": "https://api.example.com/", "final_url": "https://api.example.com/", "status": "success", "classification": "LIVE", "status_code": 200, "title": "API", "web_server": "test", "technologies": ["HTML"], "response_time": "12ms", "redirect_url": None, "redirect_allowed": None, "redirect_error": None, "ip": "8.8.8.8", "tls": {"status": "success", "version": "TLS13", "subject_dn": "CN=api.example.com"}, "error": None}]
    results = tmp_path / "results"
    monkeypatch.setattr(sys, "argv", ["main.py", "example.com", "--acknowledge", "I AM AUTHORIZED", "--dns", "--http-probe", "--acknowledge-active", "I AUTHORIZE ACTIVE PROBING", "--results", str(results)])
    with patch("domainrecon.cli.check_httpx_pinning", return_value=(1, 13, 0)), patch("domainrecon.cli.enumerate_passive_detailed", return_value=(passive, stats)), patch("domainrecon.cli.collect_dns", return_value=dns), patch("domainrecon.cli.collect_dns_policy", return_value=[]), patch("domainrecon.cli.probe_httpx", return_value=http_records) as httpx_call:
        assert main() == 0
    scan_dir = Path(capsys.readouterr().out.strip())
    httpx_call.assert_called_once()
    payload = json.loads((scan_dir / "live_web_inventory.json").read_text(encoding="utf-8"))
    assert payload["records"][0]["classification"] == "LIVE"
    assert payload["records"][0]["ip"] == "8.8.8.8"
    assert "LIVE https://api.example.com/" in (scan_dir / "live_web_inventory.txt").read_text(encoding="utf-8")
    with (scan_dir / "live_web_inventory.csv").open(encoding="utf-8", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert row["hostname"] == "api.example.com" and row["status_code"] == "200"


def test_cli_health_reports_passive_tool_availability(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from domainrecon.cli import main

    subfinder = tmp_path / "subfinder.exe"
    dnsx = tmp_path / "dnsx.exe"
    monkeypatch.setattr(sys, "argv", ["main.py", "--health", "--subfinder", str(subfinder), "--dnsx", str(dnsx)])
    with patch("domainrecon.cli.nmap_version", return_value="not installed"):
        assert main() == 0
    health = json.loads(capsys.readouterr().out)
    assert health["subfinder"] == f"not installed: {subfinder}"
    assert health["dnsx"] == f"not installed: {dnsx}"
    assert health["httpx"] == f"not installed: {Path('tools/httpx/httpx.exe')}"


def test_main_entrypoint_help_runs_from_project_root() -> None:
    project = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, "main.py", "--help"], cwd=project, shell=False, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0
    assert "usage: domainrecon-v2" in result.stdout
    assert "--acknowledge" in result.stdout
    assert "--dns" in result.stdout
    assert "--hosts-file" in result.stdout
    assert "--http-probe" in result.stdout
    assert "--httpx" in result.stdout


def test_rdap_rejects_non_public_ip_before_network() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        with pytest.raises(ScopeViolation):
            lookup_public_ip("127.0.0.1", ScopePolicy("example.com"), Path(temporary))


def _httpx_fixture_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    if "-version" in command:
        return subprocess.CompletedProcess(command, 0, "Current httpx version v1.13.0\n", "")
    input_path = Path(command[command.index("-l") + 1])
    input_lines = input_path.read_text(encoding="utf-8").splitlines()
    output = []
    for line in input_lines:
        target = json.loads(line)
        scheme = target["target"].split(":", 1)[0]
        output.append(json.dumps({
            "input": line,
            "url": target["target"],
            "host_ip": target["ip"],
            "status_code": 200,
            "headers": {"X-DomainRecon-Test": "observed", "Strict-Transport-Security": "max-age=31536000", "Set-Cookie": "session=secret"},
            "title": "Test Portal",
            "webserver": "test-server",
            "tech": ["HTML", "Test Framework"],
            "time": "15ms",
            "tls": {"version": "TLS13", "subject_dn": "CN=api.example.com", "issuer_dn": "Test CA"} if scheme == "https" else None,
        }))
    return subprocess.CompletedProcess(command, 0, "\n".join(output), "")


@patch("domainrecon.active.httpx_probe.subprocess.run")
def test_httpx_pin_capability_preflight_uses_controlled_loopback_http_and_tls(run: object, tmp_path: Path) -> None:
    executable = tmp_path / "httpx.exe"
    executable.touch()
    captured_hosts: list[str] = []

    def side_effect(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if "-version" in command:
            return subprocess.CompletedProcess(command, 0, "Current httpx version v1.13.0", "")
        input_path = Path(command[command.index("-l") + 1])
        targets = [json.loads(line) for line in input_path.read_text(encoding="utf-8").splitlines()]
        output: list[str] = []
        for target in targets:
            parsed = urlsplit(target["target"])
            if parsed.scheme == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                try:
                    with socket.create_connection(("127.0.0.1", parsed.port), timeout=3) as raw:
                        with context.wrap_socket(raw, server_hostname=parsed.hostname):
                            pass
                except ssl.SSLError:
                    # The loopback responder deliberately has no certificate; the
                    # self-test checks that the ClientHello SNI was still observed.
                    pass
                output.append(json.dumps({"status_code": 0, "host_ip": target["ip"]}))
                continue
            connection = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=3)
            connection.request("GET", parsed.path, headers={"Host": f"{parsed.hostname}:{parsed.port}"})
            response = connection.getresponse()
            response.read()
            connection.close()
            captured_hosts.append(f"{parsed.hostname}:{parsed.port}")
            output.append(json.dumps({"status_code": response.status, "host_ip": target["ip"], "headers": {"X-DomainRecon-Probe": "pin-self-test"}}))
        return subprocess.CompletedProcess(command, 0, "\n".join(output), "")

    run.side_effect = side_effect  # type: ignore[attr-defined]
    assert check_httpx_pinning(executable) == (1, 13, 0)
    assert run.call_count == 2  # version query plus one local-only HTTP/TLS check  # type: ignore[attr-defined]
    assert captured_hosts and captured_hosts[0].startswith("pin-check.invalid:")


@patch("domainrecon.active.httpx_probe.subprocess.run")
def test_httpx_requires_authorization_and_rejects_unsupported_binary_before_targets(run: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "httpx.exe"
        executable.touch()
        scope = ScopePolicy("example.com")
        passive = [{"hostname": "api.example.com", "sources": ["subfinder"]}]
        dns = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}]
        with pytest.raises(AuthorizationRequired):
            probe_httpx(executable, scope, ActiveAuthorization("example.com"), passive, dns)
        run.assert_not_called()  # type: ignore[attr-defined]
        run.return_value = subprocess.CompletedProcess([], 0, "Current httpx version v1.12.0", "")  # type: ignore[attr-defined]
        auth = ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING")
        with pytest.raises(RuntimeError, match="pinned target/IP input"):
            probe_httpx(executable, scope, auth, passive, dns)
        assert run.call_count == 1  # type: ignore[attr-defined]
        assert "-version" in run.call_args.args[0]  # type: ignore[attr-defined]


@patch("domainrecon.active.httpx_probe.check_httpx_pinning", return_value=(1, 13, 0))
@patch("domainrecon.active.httpx_probe.subprocess.run", side_effect=_httpx_fixture_run)
def test_httpx_pins_every_target_and_exports_live_inventory(run: object, pin_check: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "httpx.exe"
        executable.touch()
        scope = ScopePolicy("example.com")
        auth = ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING")
        passive = [{"hostname": "api.example.com", "sources": ["crtsh", "subfinder"]}]
        dns = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}]
        records = probe_httpx(executable, scope, auth, passive, dns)
        assert len(records) == 2
        assert {record["classification"] for record in records} == {"LIVE"}
        assert all(record["ip"] == "8.8.8.8" for record in records)
        https = next(record for record in records if record["url"].startswith("https://"))
        assert https["title"] == "Test Portal"
        assert https["web_server"] == "test-server"
        assert https["technologies"] == ["HTML", "Test Framework"]
        assert https["tls"]["version"] == "TLS13"
        assert https["headers"]["x-domainrecon-test"] == "observed"
        assert https["response_headers_status"] == "observed"
        assert https["headers"]["set-cookie"] == "[REDACTED]"
        assert "secret" not in json.dumps(https["headers"])
        scan_call = run.call_args_list[0]  # type: ignore[attr-defined]
        command = scan_call.args[0]
        assert "-x" in command and command[command.index("-x") + 1] == "GET"
        assert command[command.index("-threads") + 1] == "2"
        assert command[command.index("-rate-limit") + 1] == "2"
        assert command[command.index("-timeout") + 1] == "5"
        assert "-include-response-header" in command
        assert not any(flag in command for flag in ("-follow-redirects", "-fr", "-proxy", "-http-proxy", "-unsafe", "-http2"))
        csv_text, txt = export_live_inventory(records)
        rows = list(csv.DictReader(csv_text.splitlines()))
        assert len(rows) == 2 and rows[0]["ip"] == "8.8.8.8"
        assert "LIVE https://api.example.com/" in txt


@patch("domainrecon.active.httpx_probe.check_httpx_pinning", return_value=(1, 13, 0))
@patch("domainrecon.active.httpx_probe.subprocess.run", side_effect=_httpx_fixture_run)
def test_httpx_blocks_private_dns_and_out_of_scope_redirect_without_following(run: object, pin_check: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "httpx.exe"
        executable.touch()
        scope = ScopePolicy("example.com")
        auth = ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING")
        passive = [{"hostname": "api.example.com", "sources": ["subfinder"]}]
        # Public IPv6 is no longer blanket-blocked: it is gated by the IPv6 pinning check (see test_platform_modules.py).
        for address in ("10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.1", "::1", "fc00::1", "::ffff:8.8.8.8", "2002:808:808::1"):
            private = probe_httpx(executable, scope, auth, passive, [{"hostname": "api.example.com", "status": "success", "records": {"a": [address]}}])
            assert private[0]["status"] == ObservationStatus.BLOCKED
            assert private[0]["classification"] == "ACCESS_RESTRICTED"
        run.assert_not_called()  # type: ignore[attr-defined]


@patch("domainrecon.active.httpx_probe.check_httpx_pinning", return_value=(1, 13, 0))
@patch("domainrecon.active.httpx_probe.subprocess.run")
def test_httpx_classifies_http_errors_and_rejects_redirect_targets(run: object, pin_check: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "httpx.exe"
        executable.touch()
        calls = 0

        def side_effect(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            if "-version" in command:
                return subprocess.CompletedProcess(command, 0, "v1.13.0", "")
            lines = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").splitlines()
            output = []
            for line in lines:
                target = json.loads(line)
                scheme = target["target"].split(":", 1)[0]
                host = urlsplit(target["target"]).hostname
                status = 302 if scheme == "https" else 404
                location = "https://outside.invalid/" if host == "api.example.com" else "https://api.example.com/"
                output.append(json.dumps({
                    "input": line, "url": target["target"], "host_ip": target["ip"],
                    "status_code": status, "location": location if status == 302 else None,
                }))
            return subprocess.CompletedProcess(command, 0, "\n".join(output), "")

        run.side_effect = side_effect  # type: ignore[attr-defined]
        auth = ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING")
        records = probe_httpx(
            executable, ScopePolicy("example.com"), auth,
            [{"hostname": "api.example.com", "sources": ["crtsh"]}, {"hostname": "www.example.com", "sources": ["subfinder"]}],
            [
                {"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}},
                {"hostname": "www.example.com", "status": "success", "records": {"a": ["1.1.1.1"]}},
            ],
        )
        api_https = next(record for record in records if record["hostname"] == "api.example.com" and record["url"].startswith("https://"))
        www_https = next(record for record in records if record["hostname"] == "www.example.com" and record["url"].startswith("https://"))
        api_http = next(record for record in records if record["hostname"] == "api.example.com" and record["url"].startswith("http://"))
        assert api_https["classification"] == "REDIRECT"
        assert api_https["redirect_url"] == "https://outside.invalid/"
        assert api_https["redirect_allowed"] is False
        assert "not followed" in api_https["redirect_error"]
        assert api_https["final_url"] == api_https["url"]
        assert www_https["classification"] == "REDIRECT"
        assert www_https["redirect_allowed"] is True
        assert api_http["classification"] == "NOT_FOUND"
        assert calls == 1


@patch("domainrecon.active.httpx_probe.check_httpx_pinning", return_value=(1, 13, 0))
@patch("domainrecon.active.httpx_probe.subprocess.run")
def test_httpx_classifies_auth_required_and_access_restricted(run: object, pin_check: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "httpx.exe"
        executable.touch()

        def side_effect(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            lines = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").splitlines()
            output = []
            for line in lines:
                target = json.loads(line)
                host = urlsplit(target["target"]).hostname
                code = 401 if host == "auth.example.com" else 403
                output.append(json.dumps({"input": line, "url": target["target"], "host_ip": target["ip"], "status_code": code}))
            return subprocess.CompletedProcess(command, 0, "\n".join(output), "")

        run.side_effect = side_effect  # type: ignore[attr-defined]
        records = probe_httpx(
            executable, ScopePolicy("example.com"), ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING"),
            [{"hostname": "auth.example.com", "sources": ["subfinder"]}, {"hostname": "blocked.example.com", "sources": ["crtsh"]}],
            [
                {"hostname": "auth.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}},
                {"hostname": "blocked.example.com", "status": "success", "records": {"a": ["1.1.1.1"]}},
            ],
        )
        classes = {(record["hostname"], record["url"].split(":", 1)[0]): record["classification"] for record in records}
        assert classes[("auth.example.com", "https")] == "AUTH_REQUIRED"
        assert classes[("blocked.example.com", "https")] == "ACCESS_RESTRICTED"


@patch("domainrecon.active.httpx_probe.check_httpx_pinning", return_value=(1, 13, 0))
@patch("domainrecon.active.httpx_probe.subprocess.run")
def test_httpx_classifies_tls_timeout_and_connection_refused(run: object, pin_check: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "httpx.exe"
        executable.touch()

        def side_effect(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            if "-version" in command:
                return subprocess.CompletedProcess(command, 0, "v1.13.0", "")
            lines = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").splitlines()
            output = []
            for line in lines:
                target = json.loads(line)
                host = urlsplit(target["target"]).hostname
                scheme = urlsplit(target["target"]).scheme
                error = "x509: certificate signed by unknown authority" if host == "api.example.com" and scheme == "https" else "connection refused"
                if host == "www.example.com" and scheme == "https":
                    error = "context deadline exceeded while awaiting headers"
                output.append(json.dumps({"input": line, "url": target["target"], "failed": True, "error": error}))
            return subprocess.CompletedProcess(command, 0, "\n".join(output), "")

        run.side_effect = side_effect  # type: ignore[attr-defined]
        records = probe_httpx(
            executable, ScopePolicy("example.com"), ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING"),
            [{"hostname": "api.example.com", "sources": ["subfinder"]}, {"hostname": "www.example.com", "sources": ["crtsh"]}],
            [
                {"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}},
                {"hostname": "www.example.com", "status": "success", "records": {"a": ["1.1.1.1"]}},
            ],
        )
        classes = {(record["hostname"], record["url"].split(":", 1)[0]): record["classification"] for record in records}
        assert classes[("api.example.com", "https")] == "TLS_ERROR"
        assert classes[("api.example.com", "http")] == "CONNECTION_REFUSED"
        assert classes[("www.example.com", "https")] == "TIMEOUT"
        assert all(record.get("final_url") is None for record in records)


@patch("domainrecon.active.httpx_probe.subprocess.run")
def test_httpx_dns_failure_and_out_of_scope_discovery_never_launch(run: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "httpx.exe"
        executable.touch()
        auth = ActiveAuthorization("example.com", True, "I AUTHORIZE ACTIVE PROBING")
        passive = [{"hostname": "api.example.com", "sources": ["subfinder"]}, {"hostname": "other.test", "sources": ["crtsh"]}]
        dns = [{"hostname": "api.example.com", "status": "timeout", "error": "dns timeout"}]
        records = probe_httpx(executable, ScopePolicy("example.com"), auth, passive, dns)
        assert len(records) == 2
        assert any(record["status"] == ObservationStatus.SKIPPED for record in records)
        assert any(record["status"] == ObservationStatus.BLOCKED for record in records)
        run.assert_not_called()  # type: ignore[attr-defined]


def test_comparison_keeps_failed_observations_unknown() -> None:
    previous = {"hosts": [{"hostname": "old.example.com", "dns": {"status": "success", "a": ["8.8.8.8"]}}, {"hostname": "api.example.com", "http": {"status": "success", "code": 200}}]}
    current = {"enumeration_status": "failed", "hosts": [{"hostname": "api.example.com", "http": {"status": "failed"}}]}
    result = compare_snapshots(previous, current)
    assert result["removed_assets"] == []
    assert result["unknown_removed_assets"] == ["old.example.com"]
    assert result["changes"]["http"] == []


def test_comparison_reports_confirmed_asset_and_record_changes() -> None:
    previous = {"hosts": [{"hostname": "api.example.com", "dns": {"status": "success", "a": ["8.8.8.8"]}, "ips": ["8.8.8.8"], "http": {"status": "success", "code": 200}, "tls": {"status": "success", "serial": "1"}}]}
    current = {"enumeration_status": "success", "hosts": [{"hostname": "api.example.com", "dns": {"status": "success", "a": ["1.1.1.1"]}, "ips": ["1.1.1.1"], "http": {"status": "success", "code": 301}, "tls": {"status": "success", "serial": "2"}}, {"hostname": "new.example.com"}]}
    result = compare_snapshots(previous, current)
    assert result["new_assets"] == ["new.example.com"]
    assert all(result["changes"][kind] for kind in ("dns", "ip", "http", "tls"))


def test_fingerprinting_and_html_are_escaped_and_immutable() -> None:
    clues = fingerprint({"headers": {"server": "nginx", "x-powered-by": "<script>"}, "title": "Portal"})
    assert clues["server"] == "nginx"
    html = render_report({"title": "<img src=x>", "root_domain": "example.com"}, [{"hostname": "<script>alert(1)</script>", "dns": "ok", "http": "200", "tls": "ok"}])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Content-Security-Policy" in html
    with tempfile.TemporaryDirectory() as temporary:
        report = Path(temporary) / "report.html"
        write_report(report, {"root_domain": "example.com"}, [])
        with pytest.raises(ArtifactExists):
            write_report(report, {"root_domain": "example.com"}, [])


def test_tls_intelligence_extracts_only_expected_httpx_fields() -> None:
    tls = extract_tls({"tls": {"version": "TLS13", "serial": "abc", "issuer_dn": "issuer", "unexpected": "discard"}})
    assert tls == {"status": "success", "version": "TLS13", "serial": "abc", "issuer_dn": "issuer"}
    assert extract_tls({}) == {"status": "unknown"}


def test_nmap_options_require_explicit_full_or_valid_custom_ports() -> None:
    NmapScanOptions(TcpScanMode.COMMON).validate()
    NmapScanOptions(TcpScanMode.FULL).validate()
    NmapScanOptions(TcpScanMode.CUSTOM, "443,8000-8010").validate()
    for options in (NmapScanOptions(TcpScanMode.CUSTOM, "0,80"), NmapScanOptions(TcpScanMode.CUSTOM, "100-10"), NmapScanOptions(TcpScanMode.COMMON, "443")):
        with pytest.raises(ValueError):
            options.validate()


@patch("domainrecon.scanners.nmap.discover_nmap", return_value=None)
def test_nmap_version_reports_missing_tool(_discover: object) -> None:
    assert nmap_version(Path("definitely-not-nmap.exe")) == "not installed"


@patch("domainrecon.scanners.nmap.subprocess.run")
def test_nmap_requires_authorization_and_parses_structured_xml(run: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        executable = root / "nmap.exe"
        executable.touch()
        scope = ScopePolicy("example.com")
        options = NmapScanOptions(TcpScanMode.CUSTOM, "443", True, 10, 1, 30)
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo") as resolver:
            with pytest.raises(AuthorizationRequired):
                run_nmap(executable, scope, "api.example.com", options, root, active_acknowledgement="no")
        resolver.assert_not_called()
        run.assert_not_called()  # type: ignore[attr-defined]

        def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            xml_path = Path(command[command.index("-oX") + 1])
            normal_path = Path(command[command.index("-oN") + 1])
            normal_path.write_text("Nmap scan report", encoding="utf-8")
            xml_path.write_text("""<nmaprun><host><address addr='203.0.113.10'/><ports><port protocol='tcp' portid='443'><state state='open' reason='syn-ack'/><service name='https' product='Example' version='1.2'/></port></ports></host></nmaprun>""", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")

        run.side_effect = fake_run  # type: ignore[attr-defined]
        progress: list[str] = []
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", return_value=_dns_answer("8.8.8.8")) as resolver:
            result = run_nmap(executable, scope, "api.example.com", options, root, active_acknowledgement="I AUTHORIZE PORT SCANNING", progress=progress.append)
        command = run.call_args.args[0]  # type: ignore[attr-defined]
        assert result["status"] == "success"
        assert result["target"] == "api.example.com"
        assert result["hosts"][0]["ports"][0]["product"] == "Example"
        assert result["hosts"][0]["ports"][0]["port"] == 443
        assert command[-1] == "8.8.8.8"
        assert resolver.call_count == 2
        assert "-sT" in command and "-sV" in command and "--version-light" in command
        assert "--max-rate" in command and "--max-parallelism" in command
        assert run.call_args.kwargs["shell"] is False  # type: ignore[attr-defined]
        assert progress == ["started", "completed"]


def _dns_answer(address: str) -> list[tuple[int, int, int, str, tuple[str, int]]]:
    return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0))]


def test_nmap_out_of_scope_hostname_is_rejected_before_resolution_or_execution() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        executable.touch()
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo") as resolver, patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation):
                run_nmap(executable, ScopePolicy("example.com"), "example.com.evil.test", NmapScanOptions(), Path(temporary), active_acknowledgement="I AUTHORIZE PORT SCANNING")
        resolver.assert_not_called()
        run.assert_not_called()


@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "192.0.2.1", "0.0.0.0"])
def test_nmap_rejects_non_public_dns_answers_without_scanner_execution(address: str) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        executable.touch()
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", return_value=_dns_answer(address)) as resolver, patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation):
                run_nmap(executable, ScopePolicy("example.com"), "api.example.com", NmapScanOptions(), Path(temporary), active_acknowledgement="I AUTHORIZE PORT SCANNING")
        assert resolver.call_count == 1
        run.assert_not_called()


def test_nmap_dns_failure_prevents_scanner_execution() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        executable.touch()
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=socket.gaierror("name resolution failed")), patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation, match="DNS resolution failed"):
                run_nmap(executable, ScopePolicy("example.com"), "api.example.com", NmapScanOptions(), Path(temporary), active_acknowledgement="I AUTHORIZE PORT SCANNING")
        run.assert_not_called()


def test_nmap_dns_rebinding_during_preflight_prevents_scanner_execution() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        executable.touch()
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=[_dns_answer("8.8.8.8"), _dns_answer("1.1.1.1")]) as resolver, patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation, match="DNS answers changed"):
                run_nmap(executable, ScopePolicy("example.com"), "api.example.com", NmapScanOptions(), Path(temporary), active_acknowledgement="I AUTHORIZE PORT SCANNING")
        assert resolver.call_count == 2
        run.assert_not_called()


def test_nmap_command_helper_rejects_unvalidated_hostname_and_private_ip() -> None:
    scope = ScopePolicy("example.com")
    options = NmapScanOptions()
    with pytest.raises(ScopeViolation):
        _command(Path("nmap.exe"), ("api.example.com",), options, Path("scan.xml"), Path("scan.nmap"), scope=scope)  # type: ignore[arg-type]
    with pytest.raises(ScopeViolation):
        _command(Path("nmap.exe"), ("10.0.0.1",), options, Path("scan.xml"), Path("scan.nmap"), scope=scope)


def test_nmap_explicit_lab_policy_runs_only_pinned_loopback_with_mocked_process() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        executable = root / "nmap.exe"
        executable.touch()

        def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            Path(command[command.index("-oX") + 1]).write_text("<nmaprun><host><address addr='127.0.0.1'/><ports/></host></nmaprun>", encoding="utf-8")
            Path(command[command.index("-oN") + 1]).write_text("controlled loopback lab", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, "", "")

        lab_scope = ScopePolicy("example.com", allow_loopback_for_lab=True)
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo") as resolver, patch("domainrecon.scanners.nmap.subprocess.run", side_effect=fake_run) as run:
            result = run_nmap(executable, lab_scope, "127.0.0.1", NmapScanOptions(), root, active_acknowledgement="I AUTHORIZE PORT SCANNING")
        assert result["status"] == "success"
        assert run.call_args.args[0][-1] == "127.0.0.1"
        resolver.assert_not_called()


def _resume_log(target: str) -> str:
    return (
        "# Nmap 7.99 scan initiated Tue Nov 10 17:29:25 2026 as: nmap -sT -n --reason "
        "--max-rate 10 --max-parallelism 1 --host-timeout 30s -oX scan.xml -oN scan.nmap "
        f"--top-ports 100 {target}\nNmap scan report for {target}\n"
    )


def test_resume_nmap_requires_authorization_before_resolution_or_execution() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        resume_file = Path(temporary) / "scan.nmap"
        executable.touch()
        resume_file.write_text(_resume_log("8.8.8.8"), encoding="utf-8")
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo") as resolver, patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(AuthorizationRequired):
                resume_nmap(executable, resume_file, scope=ScopePolicy("example.com"), target="api.example.com")
        resolver.assert_not_called()
        run.assert_not_called()


def test_resume_nmap_rejects_out_of_scope_hostname_before_resolution_or_execution() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        resume_file = Path(temporary) / "scan.nmap"
        executable.touch()
        resume_file.write_text(_resume_log("8.8.8.8"), encoding="utf-8")
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo") as resolver, patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation):
                resume_nmap(executable, resume_file, scope=ScopePolicy("example.com"), target="example.net", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        resolver.assert_not_called()
        run.assert_not_called()


def test_resume_nmap_requires_matching_scoped_pinned_target_before_execution() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        resume_file = Path(temporary) / "scan.nmap"
        executable.touch()
        resume_file.write_text(_resume_log("1.1.1.1"), encoding="utf-8")
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", return_value=_dns_answer("8.8.8.8")), patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation, match="do not match"):
                resume_nmap(executable, resume_file, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        run.assert_not_called()


def test_resume_nmap_rejects_unsupported_scan_capabilities_in_log() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        resume_file = Path(temporary) / "scan.nmap"
        executable.touch()
        resume_file.write_text(_resume_log("8.8.8.8").replace("--top-ports 100", "--script default --top-ports 100"), encoding="utf-8")
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", return_value=_dns_answer("8.8.8.8")), patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation, match="unsupported option"):
                resume_nmap(executable, resume_file, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        run.assert_not_called()


def test_resume_nmap_rejects_private_address_recorded_in_log() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        resume_file = Path(temporary) / "scan.nmap"
        executable.touch()
        resume_file.write_text(_resume_log("10.0.0.1"), encoding="utf-8")
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", return_value=_dns_answer("8.8.8.8")), patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation):
                resume_nmap(executable, resume_file, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        run.assert_not_called()


def test_resume_nmap_dns_change_prevents_resume_subprocess() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        resume_file = Path(temporary) / "scan.nmap"
        executable.touch()
        resume_file.write_text(_resume_log("8.8.8.8"), encoding="utf-8")
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=[_dns_answer("8.8.8.8"), _dns_answer("1.1.1.1")]) as resolver, patch("domainrecon.scanners.nmap.subprocess.run") as run:
            with pytest.raises(ScopeViolation, match="DNS answers changed"):
                resume_nmap(executable, resume_file, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        assert resolver.call_count == 2
        run.assert_not_called()


def test_resume_nmap_authorizes_and_revalidates_matching_pinned_target() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        executable = Path(temporary) / "nmap.exe"
        resume_file = Path(temporary) / "scan.nmap"
        executable.touch()
        resume_file.write_text(_resume_log("8.8.8.8"), encoding="utf-8")
        completed = subprocess.CompletedProcess([str(executable), "--resume", str(resume_file)], 1, "", "completed scans cannot resume")
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", return_value=_dns_answer("8.8.8.8")) as resolver, patch("domainrecon.scanners.nmap.subprocess.run", return_value=completed) as run:
            result = resume_nmap(executable, resume_file, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        assert result["status"] == "failed"
        assert resolver.call_count == 2
        assert run.call_args.args[0] == [str(executable), "--resume", str(resume_file)]


@pytest.mark.parametrize(("status", "expected_exit"), [("success", 0), ("failed", 1), ("timeout", 1)])
def test_nmap_cli_exit_code_tracks_result_status(status: str, expected_exit: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    from domainrecon.cli import main

    result = {"schema_version": 1, "scanner": "nmap", "target": "example.com", "status": status}
    monkeypatch.setattr(sys, "argv", ["domainrecon-v2", "example.com", "--nmap-mode", "common", "--acknowledge-active", "I AUTHORIZE PORT SCANNING", "--results", str(tmp_path / "results")])
    with patch("domainrecon.cli.run_nmap", return_value=result):
        exit_code = main()

    assert exit_code == expected_exit
    scan_dir = Path(capsys.readouterr().out.strip())
    assert scan_dir.is_dir()
    persisted = json.loads((scan_dir / "nmap.json").read_text(encoding="utf-8"))
    assert persisted["status"] == status


@patch("domainrecon.scanners.nmap.subprocess.run")
def test_nmap_timeout_preserves_native_resume_token_and_resume_is_constrained(run: object) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        executable = root / "nmap.exe"
        executable.touch()
        options = NmapScanOptions(TcpScanMode.COMMON, timeout_seconds=30)
        scope = ScopePolicy("example.com")
        run.side_effect = subprocess.TimeoutExpired([str(executable)], 30)  # type: ignore[attr-defined]
        with patch("domainrecon.scanners.nmap.socket.getaddrinfo", return_value=_dns_answer("8.8.8.8")):
            result = run_nmap(executable, scope, "api.example.com", options, root, active_acknowledgement="I AUTHORIZE PORT SCANNING")
        assert result["status"] == "timeout"
        with pytest.raises(AuthorizationRequired):
            resume_nmap(executable, root / "not-a-resume.xml")
        with pytest.raises(ValueError):
            resume_nmap(executable, root / "not-a-resume.xml", scope=scope, target="api.example.com", active_acknowledgement="I AUTHORIZE PORT SCANNING")
