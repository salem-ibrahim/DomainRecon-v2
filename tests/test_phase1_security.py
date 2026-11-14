"""Phase 1 remediation regression tests: scope roots, CSV safety, authorization audit, Nmap resume/per-host."""
from __future__ import annotations

import csv
import io
import json
import re
import socket
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from domainrecon.active.httpx_probe import export_live_inventory
from domainrecon.analysis.database_discovery import analyze_nmap_artifact
from domainrecon.cli import _subdomain_exports, main
from domainrecon.core import public_suffix
from domainrecon.core.authorization import AuthorizationLedger, build_record
from domainrecon.core.csv_safe import neutralize_cell, render_csv
from domainrecon.core.errors import AuthorizationRequired, ScopeViolation
from domainrecon.core.scope import ScopePolicy
from domainrecon.interactive import NMAP_ACK, PASSIVE_ACK, InteractiveApp
from domainrecon.reporting.unified_report import build_unified_report, render_report_csv
from domainrecon.scanners.nmap import NmapScanOptions, TcpScanMode, plan_nmap_hosts, resume_nmap, run_nmap_hosts

ACK = "I AUTHORIZE PORT SCANNING"
_NOISE = re.compile(r"^[\s\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\ufeff]+")
_TRIGGERS = set("=+-@\uff1d\uff0b\uff0d\uff20")
_NUMBER = re.compile(r"^[+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?$")


def _formula_safe(cell: str) -> bool:
    if cell.startswith("'") or _NUMBER.fullmatch(cell):
        return True
    stripped = _NOISE.sub("", cell)
    return stripped[:1] not in _TRIGGERS and not (cell[:1] and cell[:1] != " " and _NOISE.match(cell[:1]))


# ---------------------------------------------------------------- public suffix roots

@pytest.fixture(autouse=True)
def _bundled_psl(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DOMAINRECON_PSL_FILE", raising=False)
    public_suffix._load.cache_clear()
    yield
    public_suffix._load.cache_clear()


@pytest.mark.parametrize("root", ["example.com", "example.co.uk", "example.com.sa", "sub.example.co.uk", "project.github.io", "www.ck", "bücher.de", "例え.jp", "bucket.s3.amazonaws.com", "company.example"])
def test_registrable_domains_are_accepted_as_roots(root: str) -> None:
    assert ScopePolicy(root).root_domain == root.encode("idna").decode("ascii")


@pytest.mark.parametrize("root", ["co.uk", "com.sa", "github.io", "gov.eg", "ac.jp", "s3.amazonaws.com", "anything.ck", "anything.bd", "公司.cn", "com.zz", "org.qq"])
def test_public_and_registry_suffixes_are_rejected_as_roots(root: str) -> None:
    with pytest.raises(ScopeViolation, match="public/registry suffix"):
        ScopePolicy(root)


@pytest.mark.parametrize("root", ["", "com", "*.example.com", "exa mple.com", "-bad.example.com", "example..com", "https://example.com", " example.com"])
def test_invalid_domains_are_still_rejected(root: str) -> None:
    with pytest.raises(ScopeViolation):
        ScopePolicy(root)


def test_public_suffix_rejection_does_not_affect_hostname_checks_under_valid_root() -> None:
    scope = ScopePolicy("example.co.uk")
    assert scope.permits_hostname("api.example.co.uk")
    assert not scope.permits_hostname("other.co.uk")
    assert not scope.permits_hostname("co.uk")


def test_official_list_override_is_authoritative_and_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    official = tmp_path / "public_suffix_list.dat"
    official.write_text("// test copy\ncom\nco.uk\n*.example-wild\n!ok.example-wild\n", encoding="utf-8")
    monkeypatch.setenv("DOMAINRECON_PSL_FILE", str(official))
    public_suffix._load.cache_clear()
    with pytest.raises(ScopeViolation):
        ScopePolicy("co.uk")
    with pytest.raises(ScopeViolation):
        ScopePolicy("x.example-wild")
    assert ScopePolicy("ok.example-wild").root_domain == "ok.example-wild"
    # The fail-closed heuristic is disabled when the official list is supplied.
    assert ScopePolicy("com.zz").root_domain == "com.zz"
    monkeypatch.setenv("DOMAINRECON_PSL_FILE", str(tmp_path / "missing.dat"))
    public_suffix._load.cache_clear()
    with pytest.raises(ScopeViolation, match="Public Suffix List unavailable"):  # fails closed, no traceback
        ScopePolicy("example.com")


def test_dmarc_policy_name_is_narrow_and_does_not_widen_hostname_scope() -> None:
    scope = ScopePolicy("example.com")
    assert scope.require_dns_policy_name("_dmarc.example.com") == "_dmarc.example.com"
    assert scope.require_dns_policy_name("_DMARC.mail.example.com.") == "_dmarc.mail.example.com"
    for bad in ("_dmarc.example.net", "_domainkey.example.com", "_dmarc", "x._dmarc.example.com", "_dmarc.evil.test"):
        assert not scope.permits_dns_policy_name(bad)
    assert not scope.permits_hostname("_dmarc.example.com")


# ---------------------------------------------------------------- CSV formula injection

@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2+3", "@SUM(1,1)", " =HYPERLINK(\"http://x\")", "\t=cmd", "\r=cmd", "\n@x", "\x00=cmd", "\u200b=cmd", "\ufeff+x", "\uff1dcmd", "=cmd|' /C calc'!A0"])
def test_formula_leading_values_are_neutralized(value: str) -> None:
    neutralized = neutralize_cell(value)
    assert neutralized.startswith("'") and neutralized[1:] == value


@pytest.mark.parametrize("value", ["-12", "+3.5", "0.25", "1e5", "example.com", "a=b", "text with - dash", "", "https://example.com/?a=1"])
def test_legitimate_values_are_preserved(value: str) -> None:
    assert neutralize_cell(value) == value


def test_non_string_values_are_serialized_safely() -> None:
    assert neutralize_cell(None) == ""
    assert neutralize_cell(-5) == -5
    assert neutralize_cell(["=x"]) == '["=x"]'


def _cells(text: str) -> list[str]:
    return [cell for row in csv.reader(io.StringIO(text)) for cell in row]


def test_live_web_inventory_csv_neutralizes_remote_title_server_header_and_url() -> None:
    record = {
        "hostname": "app.example.com", "url": "@SUM(1+1)", "classification": "LIVE", "status_code": 200,
        "title": "=HYPERLINK(\"https://evil.invalid\",\"click\")", "web_server": "+cmd|' /C calc'!A0",
        "technologies": ["-2+3"], "headers": {"x-evil": "=1+1"}, "redirect_url": "=WEBSERVICE(\"http://x\")",
        "error": "\t@x", "sources": ["=crtsh"], "final_url": " -1+1", "tls": {"subject_dn": "=CN"},
    }
    csv_text, _ = export_live_inventory([record])
    cells = _cells(csv_text)
    assert all(_formula_safe(cell) for cell in cells), cells
    row = next(csv.DictReader(io.StringIO(csv_text)))
    assert row["title"] == "'=HYPERLINK(\"https://evil.invalid\",\"click\")"
    assert row["status_code"] == "200"


def test_all_csv_writers_share_the_safe_serializer() -> None:
    scope = ScopePolicy("example.com")
    report = build_unified_report(scope, {"vulnerability": {"root_domain": "example.com", "status": "success", "findings": [{"finding_id": "=f", "title": "+x", "severity": "-HIGH", "evidence": {"v": "=e"}}]}}, run_id="r1", generated_at="fixed")
    subdomain_csv, _ = _subdomain_exports([{"hostname": "api.example.com", "sources": ["=crtsh"]}], [], dns_requested=False)
    rendered = render_csv(["a"], [{"a": "=x"}])
    for text in (render_report_csv(report), subdomain_csv, rendered):
        assert all(_formula_safe(cell) for cell in _cells(text))


# ---------------------------------------------------------------- authorization audit trail

def _app(tmp_path: Path, values: list[str], **paths: Path) -> tuple[InteractiveApp, list[str]]:
    items = iter(values)
    output: list[str] = []
    app = InteractiveApp(
        input_fn=lambda _prompt="": next(items), output_fn=output.append, results_root=tmp_path / "results",
        subfinder=paths.get("subfinder", tmp_path / "missing-subfinder.exe"), dnsx=paths.get("dnsx", tmp_path / "missing-dnsx.exe"),
        httpx=paths.get("httpx", tmp_path / "missing-httpx.exe"), nmap=paths.get("nmap", tmp_path / "missing-nmap.exe"),
    )
    return app, output


def _records(directory: Path) -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("authorization-*.json"))]


def test_passive_authorization_is_recorded_before_any_source_is_queried(tmp_path: Path) -> None:
    app, _ = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "0"])

    def crtsh(_scope):
        assert app.session_directory is not None
        records = _records(app.session_directory)
        assert records and records[-1]["operation"] == "passive_enumeration" and records[-1]["result"] == "granted"
        return ["api.example.com"], None

    with patch("domainrecon.interactive.collect_crtsh", side_effect=crtsh):
        assert app.run() == 0
    record = _records(app.session_directory)[0]
    for key in ("target", "operation", "authorized_at_utc", "session_id", "run_id", "authorization_method", "result"):
        assert record[key]
    assert record["target"] == "example.com" and record["run_id"] == app.session_directory.name
    session = json.loads((app.session_directory / "interactive_session.json").read_text(encoding="utf-8"))
    assert session["session_id"] == record["session_id"]


def test_denied_phrase_is_recorded_without_creating_a_run_or_storing_typed_text(tmp_path: Path) -> None:
    secret = "my-password-123"
    app, _ = _app(tmp_path, ["example.com", "1", "2", secret, "1", "2", PASSIVE_ACK, "0"])
    with patch("domainrecon.interactive.collect_crtsh", return_value=([], None)):
        assert app.run() == 0
    assert app.authorization.history[0]["result"] == "denied"
    records = _records(app.session_directory)
    assert [r["result"] for r in records] == ["denied", "granted"]
    assert records[0]["recorded_before_run_directory_existed"] is True
    for path in app.session_directory.rglob("*"):
        if path.is_file():
            assert secret not in path.read_text(encoding="utf-8")


def test_denied_phrase_alone_never_creates_a_run_directory(tmp_path: Path) -> None:
    app, _ = _app(tmp_path, ["example.com", "1", "2", "wrong", "0"])
    with patch("domainrecon.interactive.collect_crtsh") as crtsh:
        assert app.run() == 0
    crtsh.assert_not_called()
    assert app.session_directory is None
    assert app.authorization.history[-1]["result"] == "denied"


def test_passive_authorization_is_not_reused_for_nmap(tmp_path: Path) -> None:
    nmap = tmp_path / "nmap.exe"
    nmap.touch()
    app, _ = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "4", "1", PASSIVE_ACK, "0"], nmap=nmap)
    with patch("domainrecon.interactive.collect_crtsh", return_value=([], None)), patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch(
        "domainrecon.interactive.run_nmap"
    ) as scanner:
        assert app.run() == 0
    scanner.assert_not_called()
    records = _records(app.session_directory)
    assert [(r["operation"], r["result"]) for r in records] == [("passive_enumeration", "granted"), ("nmap_tcp_scan", "denied")]


def test_dns_records_reuse_of_session_passive_authorization_explicitly(tmp_path: Path) -> None:
    dnsx = tmp_path / "dnsx.exe"
    dnsx.touch()
    app, _ = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "2", "0"], dnsx=dnsx)
    with patch("domainrecon.interactive.collect_crtsh", return_value=(["api.example.com"], None)), patch(
        "domainrecon.interactive.collect_dns", return_value=[{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}]
    ), patch("domainrecon.interactive.collect_dns_policy", return_value=[]):
        assert app.run() == 0
    dns_record = [r for r in _records(app.session_directory) if r["operation"] == "dns_resolution"][0]
    assert dns_record["authorization_method"] == "interactive_session_passive_acknowledgement"


def test_authorization_record_rejects_unknown_results_and_filters_sensitive_details() -> None:
    with pytest.raises(ValueError):
        build_record(target="example.com", operation="nmap_tcp_scan", method="m", result="maybe", session_id="s", run_id=None)
    record = build_record(target="example.com", operation="nmap_tcp_scan", method="m", result="granted", session_id="s", run_id="r", details={"mode": "common", "api_token": "abc", "typed_phrase": "x"})
    assert record["details"] == {"mode": "common"}
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "authorization_record_v1.json").read_text(encoding="utf-8"))
    assert set(schema["required"]) <= set(record)


def test_ledger_drops_pending_records_on_target_change(tmp_path: Path) -> None:
    ledger = AuthorizationLedger("session")
    ledger.record(target="example.com", operation="nmap_tcp_scan", method="m", result="denied", run_directory=None)
    ledger.reset_pending()
    run = tmp_path / "run"
    run.mkdir()
    ledger.attach(run)
    assert not list(run.glob("authorization-*.json"))
    assert len(ledger.history) == 1


def test_cli_records_passive_and_dns_authorization_before_collection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def enumerate_passive(_subfinder, scope):
        scan_dirs = list((tmp_path / "results" / "example.com").iterdir())
        operations = [r["operation"] for r in _records(scan_dirs[0])]
        assert operations == ["passive_enumeration", "dns_resolution"]
        return {"root_domain": "example.com", "status": "success", "errors": [], "records": []}, {"elapsed_seconds": 0, "unique_subdomains": 0, "sources": {}}

    monkeypatch.setattr("domainrecon.cli.enumerate_passive_detailed", enumerate_passive)
    monkeypatch.setattr("domainrecon.cli.collect_dns", lambda *_args: [])
    monkeypatch.setattr("domainrecon.cli.collect_dns_policy", lambda *_args: [])
    assert main(["example.com", "--acknowledge", "I AM AUTHORIZED", "--dns", "--results", str(tmp_path / "results")]) == 0
    scan_dir = Path(capsys.readouterr().out.strip())
    assert all(r["authorization_method"] == "command_line_acknowledgement" for r in _records(scan_dir))


def test_cli_rejects_public_suffix_root_before_creating_results(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(["co.uk", "--acknowledge", "I AM AUTHORIZED", "--results", str(tmp_path / "results")])
    assert not (tmp_path / "results").exists()


# ---------------------------------------------------------------- Nmap resume timeout handling

def _dns(mapping: dict[str, list[str]]):
    def resolve(host: str, *_args, **_kwargs):
        addresses = mapping.get(host.rstrip("."))
        if addresses is None:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0)) for address in addresses]
    return resolve


def _resume_fixture(directory: Path, *, xml_name: str = "scan.xml") -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    resume = directory / "scan.nmap"
    xml_path = directory / xml_name if "/" not in xml_name and "\\" not in xml_name else Path(xml_name)
    header = (
        f'# Nmap 7.99 scan initiated Tue Nov 10 17:29:25 2026 as: "C:\\\\Program Files (x86)\\\\Nmap\\\\nmap.exe" -sT -n --reason '
        f"--max-rate 10 --max-parallelism 1 --host-timeout 30s -oX {str(xml_path).replace(chr(92), chr(92) * 2)} -oN {str(resume).replace(chr(92), chr(92) * 2)} --top-ports 100 8.8.8.8\n"
    )
    resume.write_text(header + "Nmap scan report for 8.8.8.8\n", encoding="utf-8")
    if xml_path.parent == directory:
        xml_path.write_text("<nmaprun><host><address addr='8.8.8.8'/><ports/></host>", encoding="utf-8")
    return resume


def test_resume_timeout_is_explicit_actionable_and_preserves_pre_resume_evidence(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.touch()
    resume = _resume_fixture(tmp_path / "old-run")
    original = {path.name: path.read_bytes() for path in resume.parent.iterdir()}
    evidence = tmp_path / "new-op"
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns({"api.example.com": ["8.8.8.8"]})), patch(
        "domainrecon.scanners.nmap.subprocess.run", side_effect=subprocess.TimeoutExpired(["nmap"], 60)
    ):
        result = resume_nmap(executable, resume, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement=ACK, evidence_directory=evidence, timeout_seconds=60)
    assert result["status"] == "timeout"
    assert "Resume Previous Scan" in result["error"] and "60 seconds" in result["error"]
    copies = {path.name.removeprefix("pre-resume-"): path.read_bytes() for path in evidence.glob("pre-resume-*")}
    assert copies == original
    assert result["artifact_hashes_before"] == result["artifact_hashes_after"]


def test_resume_success_requires_parseable_xml(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.touch()
    resume = _resume_fixture(tmp_path / "run")

    def finish(command, **_kwargs):
        (resume.parent / "scan.xml").write_text("<nmaprun><host><address addr='8.8.8.8'/><ports><port protocol='tcp' portid='22'><state state='open'/></port></ports></host></nmaprun>", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns({"api.example.com": ["8.8.8.8"]})), patch("domainrecon.scanners.nmap.subprocess.run", side_effect=finish):
        result = resume_nmap(executable, resume, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement=ACK, evidence_directory=tmp_path / "op1")
    assert result["status"] == "success" and result["hosts"][0]["ports"][0]["port"] == 22
    assert "xml" in result["native_files_modified_by_nmap"]

    resume2 = _resume_fixture(tmp_path / "run2")
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns({"api.example.com": ["8.8.8.8"]})), patch(
        "domainrecon.scanners.nmap.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")
    ):
        unparsed = resume_nmap(executable, resume2, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement=ACK)
    assert unparsed["status"] == "completed_unparsed" and unparsed["status"] != "success"


def test_resume_rejects_output_paths_outside_the_resume_folder(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.touch()
    resume = _resume_fixture(tmp_path / "run", xml_name=str(tmp_path / "elsewhere" / "scan.xml"))
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns({"api.example.com": ["8.8.8.8"]})), patch("domainrecon.scanners.nmap.subprocess.run") as run:
        with pytest.raises(ScopeViolation, match="beside the resume log"):
            resume_nmap(executable, resume, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement=ACK)
    run.assert_not_called()


def test_resume_never_overwrites_existing_evidence_copies(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.touch()
    resume = _resume_fixture(tmp_path / "run")
    evidence = tmp_path / "op"
    evidence.mkdir()
    (evidence / "pre-resume-scan.xml").write_text("earlier evidence", encoding="utf-8")
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns({"api.example.com": ["8.8.8.8"]})), patch("domainrecon.scanners.nmap.subprocess.run") as run:
        with pytest.raises(FileExistsError):
            resume_nmap(executable, resume, scope=ScopePolicy("example.com"), target="api.example.com", active_acknowledgement=ACK, evidence_directory=evidence)
    run.assert_not_called()
    assert (evidence / "pre-resume-scan.xml").read_text(encoding="utf-8") == "earlier evidence"


def test_interactive_resume_subprocess_error_never_crashes_or_reports_success(tmp_path: Path) -> None:
    nmap = tmp_path / "nmap.exe"
    nmap.touch()
    resume_file = tmp_path / "results" / "example.com" / "20261111T000000Z" / "nmap-01" / "scan.nmap"
    resume_file.parent.mkdir(parents=True)
    resume_file.write_text("placeholder\n", encoding="utf-8")
    app, output = _app(tmp_path, ["example.com", "4", "4", NMAP_ACK, "1", "0"], nmap=nmap)
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch("domainrecon.interactive.resume_nmap", side_effect=subprocess.TimeoutExpired(["nmap"], 5)):
        assert app.run() == 0
    saved = json.loads(next(app.session_directory.rglob("nmap_resume.json")).read_text(encoding="utf-8"))
    assert saved["status"] == "failed" and "subprocess error" in saved["error"]
    assert app.last_nmap_artifact is None


def test_main_loop_survives_unexpected_subprocess_errors(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "12", "0"])
    with patch("domainrecon.interactive.discover_nmap", return_value=None), patch.object(InteractiveApp, "_run_unified_report", side_effect=subprocess.TimeoutExpired(["x"], 1)):
        assert app.run() == 0
    assert any("No result was recorded as successful" in line for line in output)


# ---------------------------------------------------------------- per-host Nmap

def _xml_writer(calls: list[list[str]] | None = None, *, fail_for: set[str] | None = None, delay: float = 0.0, active: list[int] | None = None, lock: threading.Lock | None = None):
    def fake_run(command: list[str], **_kwargs):
        if active is not None and lock is not None:
            with lock:
                active[0] += 1
                active[1] = max(active[1], active[0])
        time.sleep(delay)
        if calls is not None:
            calls.append(command)
        targets = [part for part in command if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", part)]
        if active is not None and lock is not None:
            with lock:
                active[0] -= 1
        if fail_for and set(targets) & fail_for:
            return subprocess.CompletedProcess(command, 1, "", "simulated failure")
        hosts = "".join(f"<host><address addr='{ip}'/><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https'/></port><port protocol='tcp' portid='5432'><state state='open'/><service name='postgresql' product='PostgreSQL' version='15.4'/></port></ports></host>" for ip in targets)
        Path(command[command.index("-oX") + 1]).write_text(f"<nmaprun>{hosts}</nmaprun>", encoding="utf-8")
        Path(command[command.index("-oN") + 1]).write_text("log", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")
    return fake_run


DNS_MAP = {"a.example.com": ["8.8.8.8"], "b.example.com": ["8.8.8.8"], "c.example.com": ["1.1.1.1"], "private.example.com": ["10.0.0.5"]}


def test_plan_validates_scope_deduplicates_and_records_provenance() -> None:
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns(DNS_MAP)):
        plan = plan_nmap_hosts(ScopePolicy("example.com"), ["a.example.com", "A.example.com", "b.example.com", "c.example.com", "evil.test", "private.example.com", "10.0.0.1"])
    assert plan["hostname_provenance"] == {"a.example.com": ["8.8.8.8"], "b.example.com": ["8.8.8.8"], "c.example.com": ["1.1.1.1"]}
    assert [(u["addresses"], u["hostnames"]) for u in plan["units"]] == [(["1.1.1.1"], ["c.example.com"]), (["8.8.8.8"], ["a.example.com", "b.example.com"])]
    reasons = {row["hostname"]: row["reason"] for row in plan["rejected_hostnames"]}
    assert set(reasons) == {"evil.test", "private.example.com", "10.0.0.1"}
    assert "Non-public" in reasons["private.example.com"]


def test_per_hostname_mode_is_explicit_and_may_repeat_ips() -> None:
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns(DNS_MAP)):
        plan = plan_nmap_hosts(ScopePolicy("example.com"), ["a.example.com", "b.example.com"], per_hostname=True)
    assert [u["addresses"] for u in plan["units"]] == [["8.8.8.8"], ["8.8.8.8"]]


def test_run_nmap_hosts_requires_authorization_before_resolution(tmp_path: Path) -> None:
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo") as resolver, patch("domainrecon.scanners.nmap.subprocess.run") as run:
        with pytest.raises(AuthorizationRequired):
            run_nmap_hosts(tmp_path / "nmap.exe", ScopePolicy("example.com"), ["a.example.com"], NmapScanOptions(), tmp_path, active_acknowledgement="no")
    resolver.assert_not_called()
    run.assert_not_called()


def test_run_nmap_hosts_scans_each_unique_ip_once_with_bounded_concurrency(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.touch()
    calls: list[list[str]] = []
    active, lock = [0, 0], threading.Lock()
    mapping = {f"h{i}.example.com": [f"8.8.{i}.{i}"] for i in range(1, 7)} | {"dup.example.com": ["8.8.1.1"]}
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns(mapping)), patch(
        "domainrecon.scanners.nmap.subprocess.run", side_effect=_xml_writer(calls, delay=0.05, active=active, lock=lock)
    ):
        result = run_nmap_hosts(executable, ScopePolicy("example.com"), sorted(mapping), NmapScanOptions(TcpScanMode.CUSTOM, "443,5432", True, 100, 2, 60), tmp_path / "ev", active_acknowledgement=ACK, max_concurrency=2)
    assert result["status"] == "success"
    assert len(calls) == 6 and active[1] <= 2
    assert all(c[c.index("--max-rate") + 1] == "50" for c in calls)
    assert all(c[-1] in {f"8.8.{i}.{i}" for i in range(1, 7)} and "-n" in c for c in calls)
    shared = next(h for h in result["hosts"] if h["address"] == "8.8.1.1")
    assert shared["hostnames"] == ["dup.example.com", "h1.example.com"]
    assert result["hostname_provenance"]["dup.example.com"] == ["8.8.1.1"]


def test_run_nmap_hosts_skips_hosts_whose_dns_changes_before_execution(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.touch()
    answers = {"a.example.com": [["8.8.8.8"], ["9.9.9.9"]], "c.example.com": [["1.1.1.1"], ["1.1.1.1"]]}

    def changing(host, *_args, **_kwargs):
        value = answers[host.rstrip(".")].pop(0)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in value]

    calls: list[list[str]] = []
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=changing), patch("domainrecon.scanners.nmap.subprocess.run", side_effect=_xml_writer(calls)):
        result = run_nmap_hosts(executable, ScopePolicy("example.com"), ["a.example.com", "c.example.com"], NmapScanOptions(), tmp_path / "ev", active_acknowledgement=ACK)
    assert [c[-1] for c in calls] == ["1.1.1.1"]
    assert any(r["hostname"] == "a.example.com" and "changed" in r["reason"] for r in result["rejected_hostnames"])


def test_partial_multi_host_results_are_preserved_and_usable_offline(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.touch()
    with patch("domainrecon.scanners.nmap.socket.getaddrinfo", side_effect=_dns(DNS_MAP)), patch("domainrecon.scanners.nmap.subprocess.run", side_effect=_xml_writer(fail_for={"1.1.1.1"})):
        result = run_nmap_hosts(executable, ScopePolicy("example.com"), ["a.example.com", "c.example.com"], NmapScanOptions(), tmp_path / "ev", active_acknowledgement=ACK)
    assert result["status"] == "partial"
    assert {u["status"] for u in result["units"]} == {"success", "failed"}
    inventory = analyze_nmap_artifact(json.loads(json.dumps(result)), ScopePolicy("example.com"))
    assert inventory["source_status"] == "partial"
    assert inventory["inventory"][0]["hostname"] == "a.example.com"


def test_run_nmap_hosts_rejects_excessive_host_lists(tmp_path: Path) -> None:
    executable = tmp_path / "nmap.exe"
    executable.touch()
    with patch("domainrecon.scanners.nmap.subprocess.run") as run:
        with pytest.raises(ScopeViolation, match="at most"):
            run_nmap_hosts(executable, ScopePolicy("example.com"), [f"h{i}.example.com" for i in range(5)], NmapScanOptions(), tmp_path, active_acknowledgement=ACK, max_hosts=3)
    run.assert_not_called()


def test_interactive_discovered_host_scan_uses_only_current_session_dns_hosts(tmp_path: Path) -> None:
    dnsx = tmp_path / "dnsx.exe"
    nmap = tmp_path / "nmap.exe"
    dnsx.touch()
    nmap.touch()
    app, _ = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "2", "4", "5", "1", "1", NMAP_ACK, "0"], dnsx=dnsx, nmap=nmap)
    fake_result = {"schema_version": 1, "scanner": "nmap", "target": "example.com", "status": "success", "hosts": [{"address": "8.8.8.8", "ports": [], "hostnames": ["api.example.com"]}]}
    with patch("domainrecon.interactive.collect_crtsh", return_value=(["api.example.com", "gone.example.com"], None)), patch(
        "domainrecon.interactive.collect_dns", return_value=[{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}, {"hostname": "gone.example.com", "status": "unresolved"}]
    ), patch("domainrecon.interactive.collect_dns_policy", return_value=[]), patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch(
        "domainrecon.interactive.run_nmap_hosts", return_value=fake_result
    ) as scanner:
        assert app.run() == 0
    assert scanner.call_args.args[2] == ["api.example.com"]
    assert scanner.call_args.kwargs["active_acknowledgement"] == NMAP_ACK
    record = [r for r in _records(app.session_directory) if r["operation"] == "nmap_host_scan"][0]
    assert record["result"] == "granted" and record["details"]["hostnames"] == ["api.example.com"]
    assert app.last_nmap_artifact is not None and app.last_nmap_artifact.is_file()


def test_cli_nmap_hosts_file_records_authorization_and_uses_host_scanner(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    hosts = tmp_path / "hosts.txt"
    hosts.write_text("# selected\napi.example.com\nwww.example.com\n", encoding="utf-8")
    with patch("domainrecon.cli.run_nmap_hosts", return_value={"status": "success", "hosts": []}) as scanner, patch("domainrecon.cli.run_nmap") as apex:
        code = main(["example.com", "--nmap-mode", "common", "--acknowledge-active", ACK, "--nmap-hosts-file", str(hosts), "--results", str(tmp_path / "results")])
    assert code == 0
    apex.assert_not_called()
    assert scanner.call_args.args[2] == ["api.example.com", "www.example.com"]
    scan_dir = Path(capsys.readouterr().out.strip())
    assert _records(scan_dir)[0]["operation"] == "nmap_host_scan"
    with pytest.raises(SystemExit):
        main(["example.com", "--nmap-per-hostname", "--acknowledge", "I AM AUTHORIZED"])
