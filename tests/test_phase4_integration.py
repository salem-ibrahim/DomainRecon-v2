"""Phase 4 integration tests: exports, Stage 03-07 menu wiring, prerequisites, and unified reporting."""
from __future__ import annotations

import csv
import importlib
import io
import json
from pathlib import Path
from unittest.mock import patch

import domainrecon.intelligence as intelligence
from domainrecon.core.scope import ScopePolicy
from domainrecon.interactive import PASSIVE_ACK, InteractiveApp
from domainrecon.reporting.unified_report import build_unified_report, render_report_csv, render_report_html
from domainrecon.scanners.nmap import parse_nmap_xml

FIXTURES = Path(__file__).parent / "fixtures"
DNS_ROWS = [{"hostname": "api.example.com", "status": "success", "records": {"a": ["8.8.8.8"]}}]
POLICY_ROWS = [
    {"hostname": "example.com", "status": "success", "records": {"mx": ["mx.mail.example.net"], "txt": ["v=spf1 -all"]}, "query_purpose": "apex_email_and_ca_policy"},
    {"hostname": "_dmarc.example.com", "status": "success", "records": {"txt": ["v=DMARC1; p=reject"]}, "query_purpose": "dmarc_policy"},
]


def _app(tmp_path: Path, values: list[str]) -> tuple[InteractiveApp, list[str]]:
    items = iter(values)
    output: list[str] = []
    dnsx = tmp_path / "dnsx.exe"
    dnsx.touch()
    app = InteractiveApp(
        input_fn=lambda _prompt="": next(items), output_fn=output.append, results_root=tmp_path / "results",
        subfinder=tmp_path / "missing-subfinder.exe", dnsx=dnsx, httpx=tmp_path / "missing-httpx.exe", nmap=tmp_path / "missing-nmap.exe",
    )
    return app, output


def _recon_patches():
    return (
        patch("domainrecon.interactive.discover_nmap", return_value=None),
        patch("domainrecon.interactive.collect_crtsh", return_value=(["api.example.com"], None)),
        patch("domainrecon.interactive.collect_dns", return_value=DNS_ROWS),
        patch("domainrecon.interactive.collect_dns_policy", return_value=POLICY_ROWS),
    )


def test_all_intelligence_modules_are_exported_and_importable() -> None:
    expected = {"delivery_intelligence", "vulnerability_assessment", "persistence_intelligence", "c2_intelligence", "impact_analysis"}
    assert expected <= set(intelligence.__all__)
    for name in intelligence.__all__:
        importlib.import_module(f"domainrecon.intelligence.{name}")


def test_defensive_menu_reports_prerequisites_and_runs_nothing_when_unavailable(tmp_path: Path) -> None:
    app, output = _app(tmp_path, ["example.com", "14", "1", "14", "2", "14", "5", "0"])
    with patch("domainrecon.interactive.discover_nmap", return_value=None):
        assert app.run() == 0
    text = "\n".join(output)
    assert "Stage 03 Delivery & Exposure Intelligence - unavailable: current-session DNS, HTTPX, or Nmap evidence required" in text
    assert "Stage 04 Safe Vulnerability Assessment - unavailable: run Stage 02 with a local NVD feed first" in text
    assert "Stage 05 Persistence Evidence Import (local Windows/Sysmon/Wazuh/Linux audit export) - available" in text
    assert text.count("Nothing was run.") == 3
    assert app.session_directory is None


def test_offline_stage_03_to_07_flow_and_unified_report(tmp_path: Path) -> None:
    evidence = tmp_path / "security.jsonl"
    evidence.write_text(json.dumps({"EventID": "7045", "Computer": "api.example.com", "message": "A service was installed"}) + "\n{broken\n", encoding="utf-8")
    feed = tmp_path / "feed.csv"
    feed.write_text("value,type,source,id\napi.example.com,domain,local-ti,r1\n", encoding="utf-8")
    config = tmp_path / "criticality.json"
    config.write_text(json.dumps({"schema_version": 1, "assets": [{"asset_id": "api.example.com", "criticality": "HIGH", "source": "owner workshop 2026-11-12", "cia": {"confidentiality": 4, "integrity": 4, "availability": 3}}]}), encoding="utf-8")
    app, output = _app(tmp_path, [
        "example.com", "1", "2", PASSIVE_ACK, "2",
        "14", "1",
        "14", "3", str(evidence), "WS export",
        "14", "4", str(feed),
        "14", "5", str(config),
        "12", "0",
    ])
    patches = _recon_patches()
    with patches[0], patches[1], patches[2], patches[3]:
        assert app.run() == 0
    run = app.session_directory
    delivery = json.loads((run / "delivery-01" / "delivery_intelligence.json").read_text(encoding="utf-8"))
    assert delivery["stage"] == "delivery" and delivery["target"] == "example.com" and delivery["artifact_path"] == "delivery-01/delivery_intelligence.json"
    assert {row["policy"]: row["classification"] for row in delivery["email_observations"]}["DMARC"] == "confirmed_policy"
    assert set(delivery["input_stages"]) == {"dns"}
    persistence = json.loads((run / "persistence-01" / "persistence_evidence.json").read_text(encoding="utf-8"))
    assert persistence["status"] == "partial" and persistence["invalid_records"] == 1 and len(persistence["findings"]) == 1
    c2 = json.loads((run / "c2-01" / "c2_intelligence.json").read_text(encoding="utf-8"))
    assert [m["matched_asset"] for m in c2["matches"]] == ["api.example.com"]
    impact = json.loads((run / "impact-01" / "impact_analysis.json").read_text(encoding="utf-8"))
    estimate = next(f for f in impact["findings"] if f["observed_finding"]["stage"] == "c2")
    assert estimate["asset_criticality"] == "HIGH" and estimate["estimated_impact"]["score"] == 16
    assert (run / "dns-01" / "dns_policy.json").is_file()

    report = json.loads((run / "report-01" / "unified_report.json").read_text(encoding="utf-8"))
    for stage, label in (("delivery", "03"), ("persistence", "05"), ("c2", "06"), ("impact", "07")):
        assert report["stages"][stage]["artifact_available"] is True
        assert report["stages"][stage]["kill_chain_stage"].startswith(label)
    assert report["stages"]["vulnerability_assessment"]["status"] == "not_run"
    assert report["status"] == "partial"
    assert report["executive_summary"]["finding_count"] == 2  # impact estimates are not double counted
    persistence_finding = next(f for f in report["findings"] if f["stage"] == "persistence")
    assert persistence_finding["source_artifact"] == "persistence-01/persistence_evidence.json"
    assert persistence_finding["asset_identifier"] == "api.example.com"
    assert report["executive_summary"]["impact_summary"]["estimated_impact_findings"] >= 1
    page = (run / "report-01" / "unified_report.html").read_text(encoding="utf-8")
    assert "13. Threat Intelligence and Imported Evidence" in page and "16. Business Impact" in page and "Content-Security-Policy" in page
    rows = list(csv.DictReader(io.StringIO((run / "report-01" / "unified_report.csv").read_text(encoding="utf-8"))))
    assert {row["kill_chain_stage"] for row in rows if row["record_type"] == "finding"} == {"05 Installation / Persistence Intelligence", "06 Command and Control Intelligence"}
    operations = [json.loads(p.read_text(encoding="utf-8"))["operation"] for p in sorted(run.glob("authorization-*.json"))]
    assert operations == ["passive_enumeration", "dns_resolution"]  # offline stages need no network authorization
    assert any("Stage 07 impact analysis saved" in line for line in output)


def test_stage_04_runs_only_after_stage_02_with_feed(tmp_path: Path) -> None:
    nmap = tmp_path / "nmap.json"
    nmap.write_text(json.dumps({**parse_nmap_xml(FIXTURES / "nmap_services.xml", "example.com"), "status": "success"}), encoding="utf-8")
    app, output = _app(tmp_path, ["", "2", str(FIXTURES / "nvd_api_2_0_sample.json"), "2"])
    app._set_target("example.com")
    app.last_nmap_artifact = nmap
    app.nmap_records = json.loads(nmap.read_text(encoding="utf-8"))
    app._run_vulnerability_intelligence()  # blank feed path -> offline_no_feed
    app._defensive_menu()  # choose Stage 04 -> refused
    assert any("Stage 04 Safe Vulnerability Assessment is unavailable: run Stage 02 with a local NVD feed first" in line for line in output)
    assert not list(app.session_directory.glob("vulnerability_assessment-*"))
    app._run_vulnerability_intelligence()  # with the local NVD 2.0 fixture
    app._defensive_menu()  # choose Stage 04 -> runs
    assessment = json.loads((app.session_directory / "vulnerability_assessment-01" / "vulnerability_assessment.json").read_text(encoding="utf-8"))
    classes = {row["cve_id"]: row["classification"] for row in assessment["findings"]}
    assert classes["CVE-2099-0001"] == "CONFIRMED_VERSION_MATCH" and classes["CVE-2099-0002"] == "VERSION_RANGE_MATCH"
    risk = next(row for row in assessment["findings"] if row["cve_id"] == "CVE-2099-0001")["contextual_risk"]
    assert risk["inputs"]["public_exposure_factor"] == 1.0  # Nmap-observed public address


def test_impact_rejects_invalid_criticality_file_without_saving(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    app, output = _app(tmp_path, ["example.com", "14", "3", str(tmp_path / "missing.jsonl"), "14", "5", str(bad), "0"])
    app._intelligence_payloads["c2"] = {"findings": []}
    with patch("domainrecon.interactive.discover_nmap", return_value=None):
        app._choose_initial_target()
        app._intelligence_payloads["c2"] = {"findings": []}
        app.input("")  # "14"
        app._defensive_menu()
        app.input("")  # "14"
        app._defensive_menu()
    assert any("Local file not found" in line for line in output)
    assert any("could not be read as JSON" in line for line in output)
    assert app.session_directory is None


def test_partial_report_with_only_imported_evidence_marks_other_stages_not_run() -> None:
    scope = ScopePolicy("example.com")
    persistence = {"status": "success", "artifact_path": "persistence-01/persistence_evidence.json", "findings": [{"finding_id": "p1", "host": "=cmd", "persistence_category": "windows_service", "severity": {"level": "medium"}, "confidence": {"level": "medium"}, "evidence": {"x": "<script>"}}]}
    report = build_unified_report(scope, {"persistence": persistence}, run_id="r1", generated_at="fixed")
    assert report["status"] == "partial"
    assert all(state["status"] == "not_run" for name, state in report["stages"].items() if name != "persistence")
    assert report["executive_summary"]["risk_summary"]["observed_severity_counts"] == {"MEDIUM": 1}
    page = render_report_html(report)
    assert "<script>" not in page and "&lt;script&gt;" in page
    finding_row = next(row for row in csv.DictReader(io.StringIO(render_report_csv(report))) if row["record_type"] == "finding")
    assert finding_row["asset_identifier"] == "'=cmd" and finding_row["severity"] == "MEDIUM"
