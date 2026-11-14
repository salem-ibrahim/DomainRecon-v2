"""Phase 3 regression tests for the five Manus analyzers (Stages 03-07)."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from domainrecon.collectors.dns_intelligence import collect_dns_policy
from domainrecon.core.scope import ScopePolicy
from domainrecon.intelligence.c2_intelligence import correlate_iocs, load_ioc_feed, normalize_indicator, parse_stix_pattern
from domainrecon.intelligence.delivery_intelligence import analyze_delivery_exposure
from domainrecon.intelligence.dns_intelligence import analyze_dns_artifacts
from domainrecon.intelligence.impact_analysis import analyze_impact
from domainrecon.intelligence.persistence_intelligence import _normalize_event, analyze_persistence_evidence

SCOPE = ScopePolicy("example.com")


def _dns(rows: list[dict]) -> dict:
    return {"root_domain": "example.com", "records": rows}


def _policy(observations: list[dict]) -> dict[str, str]:
    return {row["policy"]: row["classification"] for row in observations}


# ---------------------------------------------------------------- 1. DMARC (narrow _dmarc validation)

def test_dmarc_and_bare_hostname_mx_are_assessed_from_policy_rows() -> None:
    dns = _dns([
        {"hostname": "example.com", "status": "success", "records": {"mx": ["mx1.mail.example.net", "mx2.mail.example.net."], "txt": ["v=spf1 include:_spf.example.net -all"]}},
        {"hostname": "_dmarc.example.com", "status": "success", "records": {"txt": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]}},
    ])
    result = analyze_delivery_exposure(SCOPE, dns=dns)
    assert _policy(result["email_observations"]) == {"MX": "confirmed_configured", "SPF": "confirmed_policy", "DMARC": "confirmed_policy"}
    assert result["findings"] == []
    assert not any(row["asset"].startswith("_dmarc") for row in result["exposures"])


def test_preference_style_mx_and_weak_dmarc_are_classified() -> None:
    dns = _dns([
        {"hostname": "example.com", "status": "success", "records": {"mx": ["10 mx1.example.net."], "txt": []}},
        {"hostname": "_dmarc.example.com", "status": "success", "records": {"txt": ["v=DMARC1; p=none"]}},
    ])
    result = analyze_delivery_exposure(SCOPE, dns=dns)
    assert _policy(result["email_observations"])["MX"] == "confirmed_configured"
    assert _policy(result["email_observations"])["DMARC"] == "weak"
    assert any(f["type"] == "email_policy_configuration" and f["severity"] == "MEDIUM" for f in result["findings"])


def test_dmarc_rows_for_other_domains_are_ignored_and_invalid_mx_detected() -> None:
    dns = _dns([
        {"hostname": "example.com", "status": "success", "records": {"mx": ["not a host!"]}},
        {"hostname": "_dmarc.evil.test", "status": "success", "records": {"txt": ["v=DMARC1; p=reject"]}},
    ])
    observations = _policy(analyze_delivery_exposure(SCOPE, dns=dns)["email_observations"])
    assert observations["DMARC"] == "not_assessed" and observations["MX"] == "invalid"


def test_dns_intelligence_reports_dmarc_from_policy_row() -> None:
    dns = _dns([{"hostname": "example.com", "status": "success", "records": {"txt": ["v=spf1 -all"]}}, {"hostname": "_dmarc.example.com", "status": "success", "records": {"txt": ["v=DMARC1; p=quarantine"]}}])
    result = analyze_dns_artifacts({"root_domain": "example.com", "status": "success", "records": []}, dns, SCOPE)
    dmarc = next(f for f in result["findings"] if f["type"] == "dmarc_observation")
    assert dmarc["classification"] == "present"
    assert all(not row["hostname"].startswith("_dmarc") for row in result["hosts"])


def test_collect_dns_policy_queries_only_apex_and_dmarc(tmp_path: Path) -> None:
    executable = tmp_path / "dnsx.exe"
    executable.touch()
    seen: dict = {}

    def fake_run(command, **_kwargs):
        seen["names"] = Path(command[command.index("-l") + 1]).read_text(encoding="utf-8").split()
        seen["command"] = command
        lines = [json.dumps({"host": "example.com", "mx": ["mx.example.net"]}), json.dumps({"host": "_dmarc.example.com", "txt": ["v=DMARC1; p=reject"]}), json.dumps({"host": "evil.test", "txt": ["x"]})]
        return subprocess.CompletedProcess(command, 0, "\n".join(lines), "")

    with patch("domainrecon.collectors.dns_intelligence.subprocess.run", side_effect=fake_run):
        rows = collect_dns_policy(executable, SCOPE)
    assert seen["names"] == ["example.com", "_dmarc.example.com"]
    assert "-txt" in seen["command"] and "-a" not in seen["command"] and seen["command"][0] == str(executable)
    assert [(row["hostname"], row["status"], row["query_purpose"]) for row in rows] == [("example.com", "success", "apex_email_and_ca_policy"), ("_dmarc.example.com", "success", "dmarc_policy")]


# ---------------------------------------------------------------- 2/3. IOC normalization and STIX hashes

@pytest.mark.parametrize("declared", ["domain", "Domain", "domain-name", "fqdn", "hostname"])
def test_domain_typed_indicators_match_discovered_assets(declared: str) -> None:
    feed = {"feed_name": "local", "indicators": [{"value": "API.Example.com.", "type": declared, "id": "ioc-1"}]}
    result = correlate_iocs(feed, dns={"records": [{"hostname": "api.example.com", "status": "success", "records": {}}]}, now="2026-11-12T00:00:00+00:00")
    assert len(result["matches"]) == 1
    match = result["matches"][0]
    assert match["ioc_value"] == "api.example.com" and match["matched_asset"] == "api.example.com"


def test_domain_indicator_from_csv_feed_matches(tmp_path: Path) -> None:
    feed_path = tmp_path / "feed.csv"
    feed_path.write_text("value,type,source,id\nwww.example.com,domain,local-ti,r1\n", encoding="utf-8")
    feed = load_ioc_feed(feed_path)
    assets = {"assets": [{"asset_id": "host-1", "fqdn": "www.example.com", "ip_addresses": []}]}
    result = correlate_iocs(feed, assets=assets, now="2026-11-12T00:00:00+00:00")
    assert [m["matched_asset"] for m in result["matches"]] == ["host-1"]
    assert result["feed_sha256"] == hashlib.sha256(feed_path.read_text(encoding="utf-8").encode()).hexdigest()


@pytest.mark.parametrize(("pattern", "expected"), [
    ("[file:hashes.'SHA-256' = '" + "A" * 64 + "']", ("sha256", "A" * 64)),
    ("[file:hashes.MD5 = '" + "b" * 32 + "']", ("md5", "b" * 32)),
    ('[file:hashes."SHA-1" = \'' + "c" * 40 + "']", ("sha1", "c" * 40)),
    ("[file:hashes.SHA512 = '" + "d" * 128 + "']", ("sha512", "d" * 128)),
    ("[domain-name:value = 'evil.example.org']", ("fqdn", "evil.example.org")),
    ("[ipv4-addr:value = '203.0.113.9']", ("ipv4", "203.0.113.9")),
    ("[url:value = 'https://evil.example.org/x']", ("url", "https://evil.example.org/x")),
])
def test_stix_patterns_are_parsed(pattern: str, expected: tuple[str, str]) -> None:
    assert parse_stix_pattern(pattern) == expected


def test_stix_bundle_loads_hashes_and_reports_unsupported_patterns(tmp_path: Path) -> None:
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "indicator", "id": "indicator--1", "pattern": "[file:hashes.'SHA-256' = '" + "a" * 64 + "']", "valid_until": "2099-01-01T00:00:00Z"},
        {"type": "indicator", "id": "indicator--2", "pattern": "[file:hashes.'SHA-256' = 'abc']"},
        {"type": "indicator", "id": "indicator--3", "pattern": "[domain-name:value = 'a.example.org'] AND [ipv4-addr:value = '203.0.113.1']"},
        {"type": "indicator", "id": "indicator--4", "pattern": "[domain-name:value = 'api.example.com']", "valid_until": "2020-01-01T00:00:00Z"},
        {"type": "malware", "id": "malware--1"},
    ]}
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    feed = load_ioc_feed(path)
    assert [row["type"] for row in feed["indicators"]] == ["sha256", "sha256", "fqdn"]
    assert [row["id"] for row in feed["parse_errors"]] == ["indicator--3"]
    result = correlate_iocs(feed, dns={"records": [{"hostname": "api.example.com", "status": "success"}]}, now="2026-11-12T00:00:00+00:00")
    assert result["indicators_loaded"] == 2 and result["expired_indicators"] == 1
    assert result["matches"] == []  # expired indicator is not matched
    assert {row["reason"] for row in result["feed_errors"]} == {"invalid_or_unsupported_indicator", "unsupported_stix_pattern"}
    assert result["dns_behavior"]["assessment"] == "not_supported_without_resolver_query_telemetry"


def test_hash_normalization_rejects_wrong_lengths() -> None:
    assert normalize_indicator("A" * 64, "sha256") == ("sha256", "a" * 64)
    assert normalize_indicator("abc", "sha256") is None


# ---------------------------------------------------------------- 4. Wazuh rule ID vs Windows event ID

def test_wazuh_alert_uses_windows_event_id_not_rule_id() -> None:
    alert = {"rule": {"id": "61138", "level": 5, "description": "New Windows Service Created"}, "agent": {"name": "WS01"},
             "data": {"win": {"system": {"eventID": "7045", "providerName": "Service Control Manager", "channel": "System"}, "eventdata": {"serviceName": "Updater"}}}}
    event = _normalize_event(alert, "alerts.json", 1)
    assert event["event_id"] == "7045" and event["wazuh_rule_id"] == "61138"
    assert event["category"] == "windows_service" and event["host"] == "WS01"


def test_wazuh_rule_id_alone_never_becomes_an_event_id() -> None:
    event = _normalize_event({"rule": {"id": "4698", "description": "linux rule"}, "full_log": "kernel: something"}, "alerts.json", 1)
    assert event["event_id"] is None and event["category"] is None and event["wazuh_rule_id"] == "4698"


def test_sysmon_run_key_detected_in_json_escaped_paths() -> None:
    event = {"EventID": 13, "Channel": "Microsoft-Windows-Sysmon/Operational", "TargetObject": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\updater"}
    assert _normalize_event(event, "sysmon.json", 1)["category"] == "registry_run_key"
    benign = {"EventID": 13, "Channel": "Microsoft-Windows-Sysmon/Operational", "TargetObject": "HKLM\\SOFTWARE\\Vendor\\Settings"}
    assert _normalize_event(benign, "sysmon.json", 2)["category"] is None


def test_task_scheduler_operational_ids_require_provider() -> None:
    assert _normalize_event({"EventID": 106, "Channel": "Microsoft-Windows-TaskScheduler/Operational"}, "x", 1)["category"] == "scheduled_task"
    assert _normalize_event({"EventID": 106, "Channel": "Application", "Provider": "OtherApp"}, "x", 2)["category"] is None


# ---------------------------------------------------------------- 5. invalid JSONL isolation

def test_invalid_jsonl_records_are_isolated_and_reported(tmp_path: Path) -> None:
    lines = [
        json.dumps({"EventID": "7045", "Computer": "WS01", "message": "A service was installed"}),
        '{"EventID": "4698", "broken": ',
        "[1, 2, 3]",
        json.dumps({"EventID": "4698", "Computer": "WS02"}),
        "",
    ]
    path = tmp_path / "export.jsonl"
    path.write_text("\n".join(lines), encoding="utf-8")
    result = analyze_persistence_evidence(path, source_label="Windows export")
    assert result["status"] == "partial"
    assert [f["persistence_category"] for f in result["findings"]] == ["windows_service", "scheduled_task"]
    assert [(e["line"], e["error"]) for e in result["errors"]] == [(2, "invalid_json"), (3, "record_not_object")]
    assert result["events_reviewed"] == 2 and result["invalid_records"] == 2
    assert result["source"]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert [f["evidence"]["source_line"] for f in result["findings"]] == [1, 4]


def test_whole_file_json_errors_are_reported_clearly(tmp_path: Path) -> None:
    path = tmp_path / "export.json"
    path.write_text('{"EventID": ', encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        analyze_persistence_evidence(path, source_label="x")


# ---------------------------------------------------------------- 6. systemd start messages

@pytest.mark.parametrize("message", [
    "systemd[1]: Started nginx.service - A high performance web server.",
    "systemd[1]: Starting sshd.service...",
    "systemd[1]: Stopped cron.service.",
    "systemd[1]: Reloading. unit /etc/systemd/system/nginx.service",
])
def test_routine_systemd_messages_are_not_persistence(message: str, tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    path.write_text(json.dumps({"message": message, "host": "srv1"}), encoding="utf-8")
    result = analyze_persistence_evidence(path, source_label="journald")
    assert result["findings"] == []


@pytest.mark.parametrize("record", [
    {"message": 'type=PATH msg=audit(1700000000.1:42): item=1 name="/etc/systemd/system/backdoor.service" nametype=CREATE'},
    {"message": "Created symlink /etc/systemd/system/multi-user.target.wants/backdoor.service -> /etc/systemd/system/backdoor.service."},
    {"syscheck": {"path": "/etc/systemd/system/backdoor.service", "event": "added"}, "rule": {"id": "554"}, "agent": {"name": "srv1"}},
])
def test_systemd_unit_creation_is_detected(record: dict, tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text(json.dumps(record), encoding="utf-8")
    findings = analyze_persistence_evidence(path, source_label="auditd")["findings"]
    assert [f["persistence_category"] for f in findings] == ["linux_systemd"]
    assert findings[0]["mitre_attack"]["technique_id"] == "T1543.002"


def test_routine_messages_are_counted_not_reported(tmp_path: Path) -> None:
    path = tmp_path / "journal.jsonl"
    path.write_text("\n".join(json.dumps({"message": f"systemd[1]: Started unit{i}.service"}) for i in range(3)), encoding="utf-8")
    assert analyze_persistence_evidence(path, source_label="journald")["routine_service_messages_ignored"] == 3


# ---------------------------------------------------------------- Stage 07 scoring sanity

def test_owner_rating_cannot_raise_low_severity_findings_to_high_priority() -> None:
    artifacts = {"delivery": {"root_domain": "example.com", "status": "success", "findings": [
        {"finding_id": "a", "asset_id": "example.com", "severity": "LOW", "type": "x"},
        {"finding_id": "b", "asset_id": "example.com", "severity": "HIGH", "type": "y"},
        {"finding_id": "c", "host": "srv1", "severity": {"level": "medium"}, "type": "z"},
    ]}}
    config = {"assets": [{"asset_id": "example.com", "criticality": "CRITICAL", "source": "owner", "cia": {"confidentiality": 5}}]}
    priorities = {f["observed_finding"]["finding_id"]: f["priority"] for f in analyze_impact(artifacts, config)["findings"]}
    assert priorities == {"a": "medium", "b": "high", "c": "review_owner_rating"}
