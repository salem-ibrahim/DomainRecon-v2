# Phase 2 — Database Discovery implementation report

## Outcome

Phase 2 implements offline-only Database Discovery. It accepts a successful Phase 1 `nmap.json` artifact, classifies supported database evidence, and writes a new immutable `database_inventory.json` plus an append-only JSONL event log. It performs no network activity, database connection, authentication, query, Metasploit operation, or CVE lookup.

## Files created

- `domainrecon/analysis/database_discovery.py`
- `schemas/database_inventory_v1.json`
- `tests/test_database_discovery.py`
- `PHASE2_IMPLEMENTATION_REPORT.md`

## Files modified

- `domainrecon/scanners/nmap.py` — additive extraction and preservation of all service-level Nmap CPE entries.
- `domainrecon/cli.py` — `--database-discovery` and `--nmap-input` offline command path.
- `README.md` — Phase 2 usage and safety documentation.

## Features implemented

- Pure standard-library classifier for MySQL, MariaDB, PostgreSQL, Microsoft SQL Server, MongoDB, Redis, and Oracle Database.
- Separate fields for raw Nmap service, normalized product, and controlled identity.
- MySQL/MariaDB ambiguity preservation; a bare `mysql` service or port `3306` never forces an identity.
- Multi-CPE preservation with original CPE string, parsed part/vendor/product/version where present, and malformed-CPE retention.
- Evidence-based high/medium/low confidence; ports are hints only and cannot generate products or CPEs.
- Versioned `domainrecon.database_inventory` schema, deterministic finding IDs, provenance, timestamps, and `not_assessed` vulnerability state.
- Immutable output and append-only `database-discovery.events.jsonl` logging.
- CLI input validation, scope validation of the source Nmap target, and nonzero exit for invalid input.

## Example `database_inventory.json`

```json
{
  "schema_id": "domainrecon.database_inventory",
  "schema_version": 1,
  "module": "database_discovery",
  "mode": "offline_nmap_analysis",
  "source_artifact": "nmap.json",
  "source_status": "success",
  "inventory": [
    {
      "finding_id": "db-6b6777f0c2d7",
      "identity": "postgresql",
      "product": "PostgreSQL",
      "version": "15.4",
      "hostname": "db.example.com",
      "ip_address": "198.51.100.10",
      "port": 5432,
      "transport": "tcp",
      "nmap_service": "postgresql",
      "detection_method": "nmap_product+nmap_service",
      "confidence": "high",
      "assessment_status": "service_observed",
      "vulnerability_status": "not_assessed"
    }
  ],
  "candidates": [],
  "errors": []
}
```

## Test commands and results

```powershell
$env:DOMAINRECON_RUN_NMAP_LAB='1'
python -m pytest -p no:cacheprovider -v
python main.py --health
```

Result: **39 passed**. The existing loopback-only Nmap integration test passed. The new offline Phase 2 tests cover all seven supported products, MySQL/MariaDB ambiguity, port-only candidates, multiple and malformed CPE values, CPE conflict evidence, Nmap XML CPE extraction, malformed/unsupported artifacts, immutable output, and CLI success/failure exit behavior.

## Known limitations

- Database identification is limited to Nmap evidence. Generic, absent, contradictory, proxied, TLS-obscured, or nonstandard service output remains ambiguous or unknown.
- No port, product, version, or CPE is a vulnerability finding. Product/version values are evidence only and require the later CVE Intelligence phase for candidate research.
- The module does not open network connections, so it cannot confirm database reachability beyond the saved Nmap observation or collect configuration state.
- The JSON Schema is supplied as a stable contract; runtime validation intentionally uses no additional dependency.

## V1 integrity

DomainRecon v1 was not modified. Its verified hashes remain:

```text
main.py:   3334A200E4322F8477EDB5E581AEB739A12D9A103DAF1089817BCA5B5B8BF4E9
setup.ps1: C463BFE4B83EBC14CC866BF8589DDB51F65D7492979B112853B7CCC9D3D15B46
```
