from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from domainrecon.analysis.database_discovery import SCHEMA_ID, analyze_nmap_artifact
from domainrecon.core.errors import ArtifactExists
from domainrecon.core.scope import ScopePolicy
from domainrecon.core.storage import write_json_artifact
from domainrecon.scanners.nmap import parse_nmap_xml


def _artifact(port: dict, *, status: str = "success", target: str = "db.example.com") -> dict:
    return {"schema_version": 1, "scanner": "nmap", "status": status, "target": target, "hosts": [{"address": "198.51.100.10", "ports": [port]}]}


def _port(service: str | None, product: str | None, version: str | None = None, *, number: int = 5432, cpes: list[dict] | None = None) -> dict:
    return {"port": number, "protocol": "tcp", "state": "open", "service": service, "product": product, "version": version, "extrainfo": None, "cpes": cpes or []}


@pytest.mark.parametrize(
    ("service", "product", "version", "port", "identity"),
    [
        ("mysql", "MySQL", "8.0.36", 3306, "mysql"),
        ("mysql", "MariaDB", "10.11.6", 3306, "mariadb"),
        ("postgresql", "PostgreSQL", "15.4", 5432, "postgresql"),
        ("ms-sql-s", "Microsoft SQL Server", "2019", 1433, "mssql"),
        ("mongodb", "MongoDB", "7.0", 27017, "mongodb"),
        ("redis", "Redis", "7.2", 6379, "redis"),
        ("oracle-tns", "Oracle Database", "19c", 1521, "oracle"),
    ],
)
def test_all_database_products_require_explicit_evidence(service: str, product: str, version: str, port: int, identity: str) -> None:
    result = analyze_nmap_artifact(_artifact(_port(service, product, version, number=port)), ScopePolicy("example.com"), "nmap.json", detected_at="2026-01-01T00:00:00+00:00")
    finding = result["inventory"][0]
    assert finding["identity"] == identity
    assert finding["product"] == product or (identity == "oracle" and finding["product"] == "Oracle Database")
    assert finding["version"] == version
    assert finding["nmap_service"] == service
    assert finding["confidence"] == "high"
    assert finding["detected_at"] == "2026-01-01T00:00:00+00:00"
    assert finding["vulnerability_status"] == "not_assessed"


def test_mysql_service_without_product_remains_ambiguous() -> None:
    result = analyze_nmap_artifact(_artifact(_port("mysql", None, number=3306)), ScopePolicy("example.com"))
    assert result["inventory"] == []
    candidate = result["candidates"][0]
    assert candidate["identity"] == "unknown"
    assert candidate["detection_method"] == "port_hint_only"
    assert candidate["product"] is None and candidate["version"] is None


def test_port_only_never_infers_identity_or_cpe() -> None:
    result = analyze_nmap_artifact(_artifact(_port("unknown", None, number=6379)), ScopePolicy("example.com"))
    candidate = result["candidates"][0]
    assert candidate["confidence"] == "low"
    assert candidate["evidence"]["nmap_cpes"] == []
    assert candidate["identity"] == "unknown"


def test_multiple_and_malformed_cpes_are_preserved() -> None:
    cpes = [
        {"original": "cpe:/a:redis:redis:7.2", "part": "a", "vendor": "redis", "product": "redis", "version": "7.2", "parse_status": "parsed"},
        {"original": "not-a-cpe", "part": None, "vendor": None, "product": None, "version": None, "parse_status": "unparsed"},
    ]
    result = analyze_nmap_artifact(_artifact(_port("redis", "Redis", None, number=6379, cpes=cpes)), ScopePolicy("example.com"))
    finding = result["inventory"][0]
    assert finding["version"] == "7.2"
    assert finding["evidence"]["nmap_cpes"] == cpes


def test_conflicting_product_and_cpe_remains_candidate() -> None:
    cpe = {"original": "cpe:/a:mariadb:mariadb:10.11", "part": "a", "vendor": "mariadb", "product": "mariadb", "version": "10.11", "parse_status": "parsed"}
    result = analyze_nmap_artifact(_artifact(_port("mysql", "MySQL", "8.0", number=3306, cpes=[cpe])), ScopePolicy("example.com"))
    candidate = result["candidates"][0]
    assert candidate["classification_status"] == "contradictory"
    assert candidate["candidate_identities"] == ["mariadb", "mysql"]
    assert candidate["version"] is None


def test_nmap_xml_cpe_parser_preserves_multiple_entries(tmp_path: Path) -> None:
    xml = tmp_path / "scan.xml"
    xml.write_text("""<nmaprun><host><address addr='198.51.100.10'/><ports><port protocol='tcp' portid='5432'><state state='open'/><service name='postgresql' product='PostgreSQL' version='15.4'><cpe>cpe:/a:postgresql:postgresql:15.4</cpe><cpe>malformed-cpe</cpe><cpe>cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*</cpe></service></port></ports></host></nmaprun>""", encoding="utf-8")
    port = parse_nmap_xml(xml, "db.example.com")["hosts"][0]["ports"][0]
    assert len(port["cpes"]) == 3
    assert port["cpes"][0]["vendor"] == "postgresql"
    assert port["cpes"][1]["parse_status"] == "unparsed"
    assert port["cpes"][2]["version"] == "15.4"


@pytest.mark.parametrize("payload", [{}, {"schema_version": 2, "scanner": "nmap"}, _artifact(_port("redis", "Redis"), status="failed"), {"schema_version": 1, "scanner": "nmap", "status": "success", "target": "db.example.com", "hosts": "wrong"}])
def test_malformed_or_unsupported_artifacts_fail_cleanly(payload: dict) -> None:
    with pytest.raises(ValueError):
        analyze_nmap_artifact(payload, ScopePolicy("example.com"))


def test_invalid_port_entries_are_recorded_not_crashes() -> None:
    payload = _artifact({"port": "bad", "protocol": "tcp", "state": "open"})
    result = analyze_nmap_artifact(payload, ScopePolicy("example.com"))
    assert result["inventory"] == [] and result["errors"][0]["code"] == "invalid_endpoint"


def test_database_artifact_is_immutable(tmp_path: Path) -> None:
    data = analyze_nmap_artifact(_artifact(_port("redis", "Redis", "7.2", number=6379)), ScopePolicy("example.com"))
    artifact = write_json_artifact(tmp_path, "database_inventory.json", data)
    assert json.loads(artifact.read_text(encoding="utf-8"))["schema_id"] == SCHEMA_ID
    with pytest.raises(ArtifactExists):
        write_json_artifact(tmp_path, "database_inventory.json", data)


def test_offline_cli_creates_inventory_and_rejects_invalid_input(tmp_path: Path) -> None:
    source = tmp_path / "nmap.json"
    source.write_text(json.dumps(_artifact(_port("postgresql", "PostgreSQL", "15.4"))), encoding="utf-8")
    project = Path(__file__).resolve().parents[1]
    command = [sys.executable, "main.py", "example.com", "--database-discovery", "--nmap-input", str(source), "--results", str(tmp_path / "results")]
    completed = subprocess.run(command, cwd=project, shell=False, capture_output=True, text=True, timeout=30, check=False)
    assert completed.returncode == 0
    output_dir = Path(completed.stdout.strip())
    inventory = json.loads((output_dir / "database_inventory.json").read_text(encoding="utf-8"))
    assert inventory["inventory"][0]["identity"] == "postgresql"
    assert (output_dir / "database-discovery.events.jsonl").is_file()
    invalid = subprocess.run([sys.executable, "main.py", "example.com", "--database-discovery", "--nmap-input", str(tmp_path / "missing.json")], cwd=project, shell=False, capture_output=True, text=True, timeout=30, check=False)
    assert invalid.returncode != 0
