# Phase 2 — Database Discovery proposal

## Status and boundary

This document proposes Phase 2 only. It does not change code, dependencies, scan behavior, or v1. Database Discovery begins as an **offline analysis stage** over an already saved Phase 1 `nmap.json` artifact. A detected port or banner is evidence of an exposed service, not proof of access, a database instance state, or a vulnerability.

## 1. Current architecture findings

| Existing component | Reuse in Phase 2 | Required change later |
| --- | --- | --- |
| `ScopePolicy` | Remains the sole authorization boundary for any future live check. | None for offline analysis. |
| `scanners.nmap.parse_nmap_xml` | Supplies host address, protocol, port state, service, product, version, and extra info. | Add every Nmap `<cpe>` child verbatim plus parsed CPE part/vendor/product/version fields; preserve all existing fields. |
| `core.storage.write_json_artifact` | Writes immutable `database_inventory.json`. | None. |
| `core.events.log_event` | Writes append-only discovery events. | Use a per-run `database-discovery.events.jsonl`. |
| `analysis.comparison` | Supports later history/delta analysis. | Add database-identity-aware comparison without treating missing scans as removals. |
| `reports.html_report` | Supports later inventory/report rows. | Add escaped database table and confidence labels. |

The present CLI has passive and Nmap branches but no generic artifact-input command. Phase 2 should add one narrow offline command rather than rewriting either existing branch.

## 2. Proposed module structure

```text
domainrecon/
  analysis/
    database_discovery.py       # pure offline classifier and evidence normalizer
    database_comparison.py      # later: inventory deltas, no network activity
  schemas/
    database_inventory_v1.json  # documented JSON schema / examples
  reports/
    database_section.py         # later: escaped report-row adapter
  cli.py                        # later: one --database-discovery offline branch
tests/
  test_database_discovery.py
  fixtures/
    nmap_mysql.json
    nmap_mariadb.json
    nmap_postgresql.json
    nmap_mssql.json
    nmap_mongodb.json
    nmap_redis.json
    nmap_oracle.json
    nmap_ambiguous.json
```

`database_discovery.py` must be pure Python: it accepts parsed Nmap JSON and returns a JSON-safe result. It must not import `subprocess`, sockets, database drivers, Metasploit, or CVE logic.

The Nmap parser extension is additive: a port can carry `cpes: []`, where each entry preserves `original` and only the fields parsed directly from that original string. CPE data is copied from Nmap evidence; no CPE is generated from a port, service-name guess, or product-name heuristic.

## 3. Detection model

### Supported identities

- MySQL
- MariaDB
- PostgreSQL
- Microsoft SQL Server
- MongoDB
- Redis
- Oracle Database

### Evidence hierarchy

| Confidence | Required corroboration | Result behavior |
| --- | --- | --- |
| High | Nmap service name explicitly identifies the product, or normalized product/CPE explicitly identifies it. | Emit identified product; keep exact evidence. |
| Medium | Product/version text plus a compatible service name, or a protocol fingerprint strongly identifies a product. | Emit identified product with caution. |
| Low | A conventional database port plus a generic/unknown service. | Emit `candidate` only; database type remains `unknown`. |
| None | Closed/filtered ports, no relevant evidence, or contradictory evidence. | Do not emit a database finding. |

Default port mappings are supporting signals only: MySQL/MariaDB `3306`, PostgreSQL `5432`, SQL Server `1433`, MongoDB `27017`, Redis `6379`, and Oracle `1521`. Port evidence cannot independently establish identity. Shared MySQL/MariaDB port usage is explicitly modeled as ambiguous unless the product, CPE, or service fingerprint resolves it.

Version is stored only when Nmap supplied a product-specific version or the normalized evidence contains a version format bound to a known product. Generic banners, extra-info strings, and guessed port defaults must not populate `version`.

### Service, product, and identity are independent fields

`nmap_service` is Nmap's protocol/service label and must never be overwritten by the classifier. `product` is the database product identified from explicit product/CPE evidence. `identity` is the normalized controlled vocabulary used by later modules. These fields may differ or be absent independently.

For example, a service label of `mysql` is not sufficient to classify a service as MySQL rather than MariaDB because both commonly use the same protocol and port. An explicit `MariaDB` product string or CPE can establish `identity: mariadb`; an explicit MySQL product/CPE can establish `identity: mysql`; otherwise the output remains an `ambiguous_mysql_family` candidate. Port `3306` alone remains only a low-confidence candidate.

## 3.1 CPE preservation rules

1. Parse every CPE Nmap provides; preserve multiple entries in source order.
2. Store the exact original Nmap CPE string unchanged.
3. Parse and store `part`, `vendor`, `product`, and `version` only when those components are present in that original CPE.
4. Keep malformed or unsupported CPE strings as `parse_status: "unparsed"` with the original value; do not discard evidence.
5. Never infer, synthesize, normalize into a replacement, or select a CPE based only on port number, a generic service name, or a guessed product.
6. A CPE can raise confidence only when its explicit vendor/product agrees with other evidence. Conflicting CPEs lower confidence or create an ambiguous result.

## 4. Input and output schemas

### Input contract

The initial input is a successful Phase 1 artifact:

```json
{
  "schema_version": 1,
  "scanner": "nmap",
  "status": "success",
  "target": "db.company.example",
  "hosts": [
    {
      "address": "198.51.100.22",
      "ports": [
        {
          "port": 5432,
          "protocol": "tcp",
          "state": "open",
          "service": "postgresql",
          "product": "PostgreSQL",
          "version": "15.4",
          "extrainfo": null,
          "cpes": [
            {
              "original": "cpe:/a:postgresql:postgresql:15.4",
              "part": "a",
              "vendor": "postgresql",
              "product": "postgresql",
              "version": "15.4",
              "parse_status": "parsed"
            }
          ]
        }
      ]
    }
  ]
}
```

Malformed JSON, unsupported schema versions, a non-successful source scan, hosts without an address, non-open ports, or wrong field types produce structured skipped/error entries; they never crash the analysis.

### Output contract: `database_inventory.json`

```json
{
  "schema_version": 1,
  "schema_id": "domainrecon.database_inventory",
  "module": "database_discovery",
  "mode": "offline_nmap_analysis",
  "source_artifact": "nmap.json",
  "source_status": "success",
  "generated_at": "2026-11-10T17:30:00+00:00",
  "inventory": [
    {
      "finding_id": "db-6b6777f0c2d7",
      "identity": "postgresql",
      "product": "PostgreSQL",
      "version": "15.4",
      "hostname": "db.company.example",
      "ip_address": "198.51.100.22",
      "port": 5432,
      "transport": "tcp",
      "detection_method": "nmap_service_product_version",
      "confidence": "high",
      "detected_at": "2026-11-10T17:30:00+00:00",
      "source": {
        "artifact": "nmap.json",
        "schema_version": 1,
        "scanner": "nmap"
      },
      "evidence": {
        "nmap_service": "postgresql",
        "nmap_product": "PostgreSQL",
        "nmap_version": "15.4",
        "nmap_state": "open",
        "nmap_port": 5432,
        "nmap_protocol": "tcp",
        "nmap_cpes": [
          {
            "original": "cpe:/a:postgresql:postgresql:15.4",
            "part": "a",
            "vendor": "postgresql",
            "product": "postgresql",
            "version": "15.4",
            "parse_status": "parsed"
          }
        ]
      },
      "assessment_status": "service_observed",
      "vulnerability_status": "not_assessed"
    }
  ],
  "candidates": [],
  "errors": []
}
```

Every inventory entry must retain the source artifact, endpoint (`ip_address`, `hostname` when available, port, transport), Nmap service, product/version, all CPE entries, detection method, confidence, detection timestamp, and supporting evidence. `assessment_status` is deliberately limited to observation. `vulnerability_status` remains `not_assessed` until the later CVE Intelligence phase. Neither an exposed port nor a version creates a verified finding.

### Stable future-consumer contract

`schema_id` and `schema_version` are mandatory at the document root. The first stable version is append-only: future fields may be added, but published field names/types and evidence semantics cannot change in place. A breaking schema change requires a new `schema_version` and migration reader.

The stable finding contract for future consumers is:

```json
{
  "finding_id": "stable-deterministic-id",
  "identity": "postgresql|mysql|mariadb|mssql|mongodb|redis|oracle|unknown",
  "endpoint": {"hostname": "optional", "ip_address": "required", "port": 5432, "transport": "tcp"},
  "product": "optional explicit evidence only",
  "version": "optional explicit evidence only",
  "confidence": "high|medium|low",
  "evidence": {"nmap_service": "...", "nmap_cpes": []},
  "assessment_status": "service_observed",
  "vulnerability_status": "not_assessed"
}
```

Metasploit Auxiliary Research may later consume `identity`, endpoint, version, CPE entries, confidence, and evidence to **search metadata only**. CVE Intelligence may consume identity/product/version/CPE entries to create candidates. Vulnerability Assessment and Risk Prioritization may append separately versioned assessment objects referencing `finding_id`; they must not mutate original discovery evidence or reinterpret a candidate as a verified finding.

## 5. CLI proposal

The initial command performs only local file processing:

```powershell
python main.py company.example `
  --database-discovery `
  --nmap-input "D:\Recon\DomainRecon-v2\results\company.example\<scan>\nmap.json" `
  --results "D:\Recon\DomainRecon-v2\results"
```

Rules:

1. Parse the supplied root domain through `ScopePolicy`.
2. Confirm the Nmap artifact’s `target` is the root or an in-scope hostname.
3. Create a new v2 scan directory, never mutate the Nmap source directory.
4. Write one immutable `database_inventory.json` and JSONL event log.
5. Return nonzero for invalid input/artifact/schema; return zero with an empty inventory for a valid scan with no database evidence.

No network activity, credentials, database connection, Metasploit interaction, CVE query, or authentication acknowledgement is needed in this offline phase.

### Future opt-in live identification

This is intentionally deferred. If later approved, it must be a separately named module and require a new exact acknowledgement, for example `I AUTHORIZE DATABASE IDENTIFICATION`. It may only consume already scoped, Nmap-observed, open database endpoints; it must use bounded timeouts and protocol handshakes that do not authenticate, enumerate data, change settings, issue queries, or test credentials. It must remain disabled by default.

## 6. Integration workflow

```text
Nmap XML (including explicit CPE children) → nmap.json → Database Discovery (offline) → database_inventory.json
                                      │                         │
                                      ├── append-only events     ├── HTML report section
                                      ├── history comparison     └── later CVE candidate input
                                      └── later safe auxiliary-module search input
```

For history, compare `(hostname/IP, transport, port, identity, product, version, ordered original-CPE set, confidence)` only when both artifacts were successfully generated. A missing or failed inventory remains `unknown`; it is never a confirmed database removal.

The HTML report adapter later renders product, version, confidence, observation state, and exact Nmap evidence using escaped text. It must never label a potential database product as vulnerable or verified.

## 7. Cyber Kill Chain placement

Database Discovery belongs to:

- **Reconnaissance:** records externally observable database attack surface and product evidence.
- **Attack Surface Analysis:** identifies exposed data-service entry points for inventory ownership and risk review.

It is not exploitation, credential access, lateral movement, or actions on objectives. Later CVE Intelligence may create **potential vulnerability candidates** from an identity/product/version/CPE tuple. A later approved auxiliary check could elevate a candidate only with independent, non-destructive evidence. Risk prioritization should combine exposure, confidence, asset criticality supplied by the organization, CVSS context, and compensating controls—not port presence alone.

## 8. Testing strategy

### Unit tests

- Each supported product from explicit service, product, CPE, and version evidence.
- Multiple CPE entries, malformed CPE retention, CPE/product conflicts, and proof that no CPE is inferred from a database port.
- MySQL versus MariaDB shared-port ambiguity.
- Separate assertions for raw Nmap service, normalized product, normalized identity, version, confidence, and timestamp/evidence provenance.
- Conventional port alone creates a low-confidence candidate, not a product identity.
- Unknown, contradictory, closed, filtered, and non-TCP services.
- Missing, malformed, oversized, or unsupported-schema Nmap JSON.
- Version extraction only from product-bound evidence.
- Deterministic ordering, duplicate suppression, immutable artifact collision, and JSON serialization.

### Mocked integration tests

- Use Phase 1 fixture artifacts for all seven products.
- Validate source target scope mismatch rejection before output creation.
- Verify event-log entries and nonzero error paths.
- Verify history comparison preserves unknowns on failed source collection.
- Verify HTML output escapes hostile banners and evidence strings.

### Local lab tests, deferred to approved implementation

- Use loopback-only containerized or isolated services for the seven database products when organizational lab images are available.
- Use Nmap service/version detection only; never authenticate or send database queries.
- For products unavailable in the lab, use recorded XML fixtures and mark the coverage mocked rather than live.
- Do not start any database container or install any server dependency without separate approval.

## 9. Dependencies

Initial implementation requires **no new Python packages and no new scanning tools**. It consumes existing JSON and uses the standard library. Parsing Nmap CPE output only requires a narrow additive extension to the existing XML parser.

Optional later live identification must be assessed separately; do not add database client libraries merely for banner matching. Any dependency would require license, maintenance, transport-safety, and no-authentication review before approval.

## 10. Risks and limitations

- Nmap service detection can be absent, generic, inaccurate, or obscured by proxies, TLS, nonstandard ports, and network controls.
- Port numbers are weak hints; the module must preserve ambiguity and must never manufacture a CPE.
- Nmap CPE values are scanner assertions, not independently verified product inventories; multiple and contradictory values must remain visible in evidence.
- Product version exposure does not prove patch level, configuration, reachability to unauthorized users, exploitability, or a CVE condition.
- Nmap’s source address may be an IP rather than a hostname; hostname association must only use a trusted in-scope source artifact, never reverse-DNS expansion.
- Historical changes may reflect scanner coverage differences rather than asset changes; failed/missing observations must remain unknown.
- Future live identification increases operational impact and must retain independent authorization, scope, private-address, DNS-rebinding, rate-limit, and no-authentication controls.

## 11. Implementation milestones

1. **Offline classifier and schemas:** pure classifier, service/product/identity separation, CPE preservation rules, structured errors, fixture tests.
2. **Artifact/CLI integration:** immutable output, JSONL events, source scope check, exit codes.
3. **Nmap CPE enrichment:** additive XML parser fields and CPE-aware confidence rules, regression tests.
4. **History and HTML adapters:** conservative deltas and escaped inventory report table.
5. **Local lab validation:** only after explicit approval for local database service dependencies.
6. **Deferred final security review:** complete code/security audit after planned modules stabilize.

## Recommended smallest implementation plan

Implement milestones 1 and 2 first: a standard-library, offline `database_discovery` classifier that consumes immutable `nmap.json`, preserves all supplied CPE evidence, separates Nmap service from product identity, and writes immutable `database_inventory.json`. Do not add live probes, database drivers, containers, Metasploit, CVE matching, or report changes in the first increment. This is the smallest plan that preserves the existing architecture, produces immediately useful inventory evidence, and avoids converting a port scan into a database interaction.
