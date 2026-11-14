"""Focused checks for the feature-freeze gap closure (mocked/offline only)."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from domainrecon.active.httpx_probe import HTTPX_INSTALL_GUIDANCE
from domainrecon.collectors.rdap import lookup_public_ip
from domainrecon.core import public_suffix
from domainrecon.core.engagement import load_engagement
from domainrecon.core.errors import ScopeViolation
from domainrecon.core.scope import ScopePolicy
from domainrecon.reporting.unified_report import build_unified_report, render_report_html

ROOT = Path(__file__).resolve().parents[1]
SCOPE = ScopePolicy("example.com")


def test_wildcard_probe_evidence_is_reported_without_duplicate_findings() -> None:
    probe = {"root_domain": "example.com", "labels": ["dr-wildcard-1.example.com"], "records": [{"hostname": "dr-wildcard-1.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}],
             "status": "success", "findings": [], "artifact_path": "wildcard_probe-01/wildcard_probe.json"}
    dns_intel = {"root_domain": "example.com", "status": "success", "findings": [{"type": "wildcard_dns", "classification": "suspected"}]}
    report = build_unified_report(SCOPE, {"wildcard_probe": probe, "dns_intelligence": dns_intel}, run_id="r1")
    assert report["stages"]["wildcard_probe"]["artifact_available"] and report["stages"]["wildcard_probe"]["source"] == "wildcard_probe-01/wildcard_probe.json"
    assert report["sections"]["dns_security"]["wildcard_probe"]["labels"] == ["dr-wildcard-1.example.com"]
    assert [f["stage"] for f in report["findings"]] == ["dns_intelligence"]
    assert "dr-wildcard-1.example.com" in render_report_html(report)


def test_operator_pinned_psl_failure_fails_closed_without_traceback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pinned = tmp_path / "public_suffix_list.dat"
    pinned.write_text("// ===BEGIN ICANN DOMAINS===\ncom\n// ===BEGIN PRIVATE DOMAINS===\n", encoding="utf-8")
    pinned.with_suffix(".dat.meta.json").write_text(json.dumps({"sha256": "0" * 64}), encoding="utf-8")
    monkeypatch.setenv("DOMAINRECON_PSL_FILE", str(pinned))
    public_suffix._load.cache_clear()
    with pytest.raises(ScopeViolation, match="failed integrity verification"):
        ScopePolicy("example.com")
    public_suffix._load.cache_clear()


def test_rdap_compat_cache_is_windows_safe_and_atomic(tmp_path: Path) -> None:
    class Response:
        def __enter__(self):
            return self
        def __exit__(self, *_):
            return False
        def read(self, _n):
            return b'{"handle": "NET6"}'

    with patch("domainrecon.collectors.rdap.urlopen", return_value=Response()):
        assert lookup_public_ip("2606:4700:4700::1111", SCOPE, tmp_path)["handle"] == "NET6"
    assert [p.name for p in tmp_path.iterdir()] == ["2606_4700_4700__1111.json"]


def test_example_engagement_loads_and_has_no_deprecated_switch() -> None:
    engagement = load_engagement(ROOT / "engagement.example.yaml")
    assert "vulnerability_validation" not in engagement.operations and engagement.deprecations == ()


def test_httpx_guidance_states_the_upstream_blocker_and_setup_validates_locally() -> None:
    assert "v1.12.0" in HTTPX_INSTALL_GUIDANCE and "--check-httpx" in HTTPX_INSTALL_GUIDANCE
    setup = (ROOT / "setup.ps1").read_text(encoding="utf-8")
    assert "main.py --check-httpx" in setup and "InstallPublicSuffixList" in setup and "'--update-psl', '--confirm-download'" in setup
    assert "Read-Host 'Download the official Public Suffix List" in setup  # explicit typed confirmation


def test_every_cli_option_is_documented() -> None:
    help_text = subprocess.run([sys.executable, "main.py", "--help"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
    options = sorted(set(re.findall(r"(--[a-z][a-z0-9-]+)", help_text)) - {"--help"})
    docs = "".join((ROOT / name).read_text(encoding="utf-8") for name in ("README.md", "OWNER_CLI_GUIDE.md", "docs/MODULES.md"))
    assert [option for option in options if option not in docs] == []
