"""Focused checks for the redesigned interactive CLI (renderer, dashboard, navigation, guided workflow)."""
from __future__ import annotations

import builtins
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from domainrecon import ui
from domainrecon.interactive import NMAP_ACK, PASSIVE_ACK, InteractiveApp
from domainrecon.ui import Console, detect_capabilities, menu_state, sanitize, visible_length

GROUPS = [("RECONNAISSANCE", [
    {"number": "1", "label": "Passive Subdomain Enumeration", "kind": "PASSIVE", "note": "available"},
    {"number": "3", "label": "Live Web Services Discovery (ProjectDiscovery HTTPX)", "short": "HTTP Services Discovery (HTTPX)", "kind": "ACTIVE", "note": "unavailable: HTTPX binary missing; passive collection required"},
    {"number": "8", "label": "View Previous Results", "kind": "ADMIN", "note": ""},
]), ("WORKFLOWS", [{"number": "0", "label": "Exit", "kind": "", "note": ""}])]
DNS_ROWS = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}, {"hostname": "old.example.com", "status": "success", "records": {"cname": ["gone.azurewebsites.net"]}}]


class _Stream:
    def __init__(self, tty: bool, encoding: str = "utf-8") -> None:
        self._tty, self.encoding = tty, encoding

    def isatty(self) -> bool:
        return self._tty


def _console(**kwargs) -> tuple[Console, list[str]]:
    lines: list[str] = []
    return Console(lines.append, **kwargs), lines


def _app(tmp_path: Path, values: list, *, layout: bool = False, width: int = 100) -> tuple[InteractiveApp, list[str]]:
    items = iter(values)
    output: list[str] = []
    dnsx, nmap = tmp_path / "dnsx.exe", tmp_path / "nmap.exe"
    dnsx.touch()
    nmap.touch()

    def ask(_prompt: str = "") -> str:
        value = next(items)
        if isinstance(value, BaseException):
            raise value
        return value

    app = InteractiveApp(input_fn=ask, output_fn=None if layout else output.append, results_root=tmp_path / "results", subfinder=tmp_path / "x.exe", dnsx=dnsx, httpx=tmp_path / "missing-httpx.exe", nmap=nmap)
    if layout:
        app.ui = Console(output.append, layout=True, color=False, unicode=True, width=width)
        app.output = app.ui.emit
    return app, output


def _recon():
    return (patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch("domainrecon.interactive.collect_crtsh", return_value=(["api.example.com", "old.example.com"], None)),
            patch("domainrecon.interactive.collect_dns", return_value=DNS_ROWS), patch("domainrecon.interactive.collect_dns_policy", return_value=[]))


# ------------------------------------------------------------------ renderer and terminal compatibility

def test_plain_mode_keeps_legacy_menu_lines_and_passthrough_messages() -> None:
    console, lines = _console()
    console.menu(GROUPS)
    assert lines == ["RECONNAISSANCE", "[1] Passive Subdomain Enumeration - available", "[3] Live Web Services Discovery (ProjectDiscovery HTTPX) - unavailable: HTTPX binary missing; passive collection required",
                     "[8] View Previous Results", "WORKFLOWS", "[0] Exit"]
    lines.clear()
    console.emit("Operation could not be completed: boom")
    console.success("saved")
    assert lines == ["Operation could not be completed: boom", "saved"]


@pytest.mark.parametrize("width", [60, 80, 100, 140])
@pytest.mark.parametrize("unicode_ok", [True, False])
def test_layout_respects_terminal_width(width: int, unicode_ok: bool) -> None:
    console, lines = _console(layout=True, color=False, unicode=unicode_ok, width=width)
    console.banner("2.0.0", "tagline")
    console.key_values("SESSION", [("Target", "example.com", "OK"), ("Findings", "x" * 300, None)] * 4)
    console.menu(GROUPS)
    console.panel("ACTIVE OPERATION - AUTHORIZATION REQUIRED", ["Operation : " + "y" * 200], "WARN")
    console.table([{"key": "a", "title": "Asset", "flex": True}, {"key": "s", "title": "Severity", "kind": "severity"}, {"key": "t", "title": "Finding", "flex": True}],
                  [{"a": "host-" + "z" * 90 + ".example.com", "s": "HIGH", "t": "t" * 150}] * 3, title="FINDINGS")
    console.emit("Passive results saved to: " + "C:\\very\\long\\path\\" * 12)
    assert max(len(line) for line in lines) <= width, [line for line in lines if len(line) > width][:2]
    if not unicode_ok:
        assert all(ord(char) < 128 for line in lines for char in line)


def test_layout_classifies_messages_and_strips_terminal_escapes() -> None:
    console, lines = _console(layout=True, color=False, unicode=False, width=100)
    for message in ("Nmap scan blocked or failed: x", "HTTPX is unavailable because y", "DNS results saved to: z", "Unique in-scope subdomains: 4"):
        console.emit(message)
    assert [line[:1] for line in lines] == ["x", "!", "+", "U"]
    lines.clear()
    console.emit("title \x1b]0;pwned\x07\x1b[31m red")
    console.table([{"key": "t", "title": "Title"}], [{"t": "evil\x1b[2J\x9b0m"}])
    assert not any("\x1b" in line or "\x07" in line or "\x9b" in line for line in lines)
    assert sanitize("a\x1b[31mb\rc") == "a[31mbc"


def test_color_mode_uses_ansi_without_affecting_alignment() -> None:
    console, lines = _console(layout=True, color=True, unicode=True, width=100)
    console.table([{"key": "s", "title": "Severity", "kind": "severity"}, {"key": "a", "title": "Asset"}], [{"s": "CRITICAL", "a": "x"}, {"s": "LOW", "a": "y"}])
    assert "\x1b[" in lines[2] and "\x1b[" in lines[0]
    assert lines[2].index("x") - lines[2].count("\x1b[") * 0 > 0 and visible_length(lines[0]) == visible_length(lines[1])
    assert visible_length(console.severity("HIGH")) == 4 and console.severity({"level": "medium"}).count("MEDIUM") == 1
    assert menu_state("available; gate runs") == ("READY", "gate runs") and menu_state("unavailable: Nmap not installed")[0] == "BLOCKED" and menu_state("needs DNS")[0] == "NEEDS"


@pytest.mark.parametrize(("env", "tty", "encoding", "injected", "expected"), [
    ({}, True, "utf-8", False, (True, True)),
    ({}, False, "utf-8", False, (False, False)),          # piped output -> legacy plain lines
    ({}, True, "utf-8", True, (False, False)),            # injected output (tests/embedding)
    ({"DOMAINRECON_UI": "plain"}, True, "utf-8", False, (False, False)),
    ({"DOMAINRECON_UI": "ascii"}, True, "utf-8", False, (True, False)),
    ({}, True, "cp1252", False, (True, False)),           # legacy Windows console -> ASCII borders
    ({"DOMAINRECON_UI": "styled", "DOMAINRECON_UI_WIDTH": "90"}, False, "utf-8", False, (True, True)),
])
def test_capability_detection(env: dict, tty: bool, encoding: str, injected: bool, expected: tuple) -> None:
    with patch.object(ui, "enable_ansi", return_value=True):
        caps = detect_capabilities(injected_output=injected, stream=_Stream(tty, encoding), environ=env)
    assert (caps["layout"], caps["unicode"]) == expected
    if "DOMAINRECON_UI_WIDTH" in env:
        assert caps["width"] == 90


def test_color_disabled_by_no_color_or_when_ansi_cannot_be_enabled() -> None:
    with patch.object(ui, "enable_ansi", return_value=True):
        assert detect_capabilities(injected_output=False, stream=_Stream(True), environ={"NO_COLOR": "1"})["color"] is False
        assert detect_capabilities(injected_output=False, stream=_Stream(True), environ={})["color"] is True
    with patch.object(ui, "enable_ansi", return_value=False):
        caps = detect_capabilities(injected_output=False, stream=_Stream(True), environ={})
    assert caps["layout"] is True and caps["color"] is False


def test_missing_optional_colorama_never_breaks_startup() -> None:
    real_import = builtins.__import__

    def no_colorama(name, *args, **kwargs):
        if name == "colorama":
            raise ImportError("not installed")
        return real_import(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=no_colorama):
        assert isinstance(ui.enable_ansi(), bool)
    console, lines = _console(layout=True, color=False, unicode=False, width=80)  # renderer needs no third-party package
    console.menu(GROUPS)
    assert lines and "rich" not in ui.__dict__


# ------------------------------------------------------------------ dashboard and navigation

def test_dashboard_shows_session_readiness_and_no_secrets(tmp_path: Path) -> None:
    secret = "hunter2-wrong-phrase"
    app, output = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "4", "1", secret, "0"])
    patches = _recon()
    with patches[0], patches[1], patches[2], patches[3], patch("domainrecon.interactive.run_nmap") as scanner:
        assert app.run() == 0
    scanner.assert_not_called()
    text = "\n".join(output)
    for expected in ("Scope validation: VALID", "Engagement: none (root-domain scope only)", f"Session ID: {app.authorization.session_id[:12]}", "HTTPX: not installed", "Public Suffix List: ",
                     "Active authorization: typed phrase per operation; never stored", "Last operation: passive enumeration: success", "Last operation: nmap_tcp_scan: not authorized", "Findings: none recorded yet", "Modules: "):
        assert expected in text, expected
    assert secret not in text and app.authorization.session_id not in text.replace(app.authorization.session_id[:12], "")
    assert "--- ACTIVE OPERATION - AUTHORIZATION REQUIRED ---" in text and "Target    : example.com" in text and "Operation : Nmap TCP connect scan  [ACTIVE]" in text
    assert "--- PASSIVE OPERATION - AUTHORIZATION REQUIRED ---" in text and "DISCOVERED ASSETS (2)" in text


def test_grouped_menu_contains_every_working_entry_once(tmp_path: Path) -> None:
    app, _ = _app(tmp_path, [])
    app._set_target("example.com")
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"):
        groups = app._menu_groups()
    assert [title for title, _ in groups] == ["ENGAGEMENT", "RECONNAISSANCE", "INTELLIGENCE", "ANALYSIS", "REPORTING", "WORKFLOWS"]
    numbers = [entry["number"] for _title, entries in groups for entry in entries]
    assert sorted(numbers, key=int) == [str(n) for n in range(0, 28)] and len(set(numbers)) == 28


def test_invalid_input_back_navigation_and_ctrl_c(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "abc", "99", "1", "0", "10", "0", "16", "0", KeyboardInterrupt(), "0"])
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch("domainrecon.interactive.collect_crtsh") as crtsh:
        assert app.run() == 0
    crtsh.assert_not_called()
    text = "\n".join(output)
    assert text.count("Invalid selection. Choose one of the numbered options shown (0 exits).") == 2
    assert "Cancelled. Returning to the main menu" in text and "Last operation: operation: cancelled by operator (Ctrl+C)" in text
    assert app.session_directory is None and app.scope.root_domain == "example.com"


def test_scope_review_shows_exclusions_and_violations(tmp_path: Path) -> None:
    engagement = tmp_path / "e.json"
    engagement.write_text(json.dumps({"engagement": {"name": "Pilot", "target": "example.com", "scope": {"excluded_assets": ["legacy.example.com", "203.0.113.0/24"]}, "operations": {"port_scanning": False}}}), encoding="utf-8")
    app, output = _app(tmp_path, ["example.com", "15", "1", str(engagement), "26", "api.example.com", "legacy.example.com", "evil.test", "10.0.0.5", "8.8.8.8", "", "0"])
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"):
        assert app.run() == 0
    text = "\n".join(output)
    assert "Excluded hostnames: legacy.example.com" in text and "Excluded networks: 203.0.113.0/24" in text
    assert "IN SCOPE: api.example.com" in text and "IN SCOPE as a destination: 8.8.8.8 is public" in text
    assert text.count("OUT OF SCOPE - scope violation:") == 3
    assert any(line.startswith("[4] Nmap Port Scanning - unavailable: disabled by engagement") for line in output)
    assert "Engagement: Pilot [eng-" in text


def test_styled_session_runs_end_to_end_within_width(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "1", "2", PASSIVE_ACK, "2", "20", "", "22", "23", "0"], layout=True, width=100)
    patches = _recon()
    with patches[0], patches[1], patches[2], patches[3]:
        assert app.run() == 0
    text = "\n".join(output)
    for expected in ("SESSION", "READINESS", "RECONNAISSANCE", "TAKEOVER INDICATORS (1)", "CORRELATED FINDINGS", "ATTACK-PATH HYPOTHESES", "THEORETICAL - not tested", "MITRE ATT&CK MAPPING", "DNS RECORDS (2)"):
        assert expected in text, expected
    assert max(len(line) for line in output) <= 100
    assert app._intelligence_payloads["correlation"]["canonical_findings"]


# ------------------------------------------------------------------ guided pilot workflow

def test_guided_workflow_cancellations_and_validation_run_nothing(tmp_path: Path) -> None:
    for answers, message in ((["0"], "Guided workflow cancelled; nothing was run."), (["1", "no"], "Scope not confirmed"), (["1", "YES", ""], "No stage selected"), (["1", "YES", "1,9,x"], "Invalid stage selection: 9, x")):
        app, output = _app(tmp_path, answers)
        app._set_target("example.com")
        with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch("domainrecon.interactive.collect_crtsh") as crtsh:
            app._guided_workflow()
        crtsh.assert_not_called()
        assert any(message in line for line in output), message
        assert app.session_directory is None


def test_guided_workflow_requires_confirmation_for_each_active_stage(tmp_path: Path) -> None:
    # stages 1,2 (passive), 3 (HTTPX: blocked, binary missing), 4 (TLS: declined), 5 (Nmap: confirmed, then wrong phrase), 6, 7
    answers = ["1", "YES", "1,2,3,4,5,6,7", PASSIVE_ACK, "no", "YES", "1", "wrong phrase"]
    app, output = _app(tmp_path, answers)
    app._set_target("example.com")
    patches = _recon()
    with patches[0], patches[1], patches[2], patches[3], patch("domainrecon.interactive.run_nmap") as scanner, patch("domainrecon.platform_menu.probe_tls") as tls, patch("domainrecon.interactive.probe_httpx") as httpx:
        app._guided_workflow()
    scanner.assert_not_called()
    tls.assert_not_called()
    httpx.assert_not_called()
    text = "\n".join(output)
    assert "Stage skipped: HTTP/HTTPS probing (HTTPX) is unavailable: HTTPX binary is not installed" in text
    assert "Stage declined: TLS certificate inspection; nothing was sent." in text
    assert "STEP 7 OF 7 - REPORT AND SUMMARY" in text and "CORRELATED FINDINGS" in text
    assert (app.session_directory / "report-01" / "unified_report.json").is_file()
    records = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(app.session_directory.glob("authorization-*.json"))]
    assert [(r["operation"], r["result"]) for r in records] == [("passive_enumeration", "granted"), ("dns_resolution", "granted"), ("nmap_tcp_scan", "denied")]
    assert "wrong phrase" not in text


def test_guided_workflow_respects_engagement_disabled_operations(tmp_path: Path) -> None:
    engagement = tmp_path / "e.json"
    engagement.write_text(json.dumps({"engagement": {"name": "Passive only", "target": "example.com", "profile": "passive"}}), encoding="utf-8")
    app, output = _app(tmp_path, ["2", str(engagement), "YES", "4,5"])
    app._set_target("example.com")
    with patch("domainrecon.interactive.nmap_version", return_value="Nmap 7.99"), patch("domainrecon.interactive.run_nmap") as scanner, patch("domainrecon.platform_menu.probe_tls") as tls:
        app._guided_workflow()
    scanner.assert_not_called()
    tls.assert_not_called()
    text = "\n".join(output)
    assert text.count("Stage skipped:") == 2 and "disabled by engagement 'Passive only'" in text
