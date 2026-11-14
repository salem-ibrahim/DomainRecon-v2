# DomainRecon V2 module reference and feature inventory

All modules write immutable, enveloped JSON artifacts under `results\<domain>\<run>\<stage>-NN\`. They register in the interactive session (one target, one engagement, one run per session) and appear in the unified report with their Kill Chain stage and source-artifact path. "Offline" means the module performs no network activity.

## Feature inventory

| # | Module | Implementation | Integration (menu / CLI / report) | Runtime prerequisites | Remaining limitations |
|---|---|---|---|---|---|
| 01 | Engagement management (`core/engagement.py`, `simple_yaml.py`, `ledger.py`) | Complete | Menu 15; `--engagement`; report section 2 | None (optional YAML/JSON file) | YAML is a strict subset; one root domain per engagement; `vulnerability_validation` is deprecated (accepted only as `false`) |
| 02 | Public Suffix List (`core/public_suffix.py`) | Complete | Runs on every root validation; `--health`, `--update-psl --confirm-download`, `--install-psl`, `setup.ps1 -InstallPublicSuffixList` | Official list must be installed explicitly; the bundled 238-rule subset is used until then | The subset's fail-closed heuristic can reject a few legitimate `com.xx`-style roots; the PSL has no publisher signature, so integrity means "unchanged since install" |
| 03 | HTTPX integration (`active/httpx_probe.py`) | Implemented (discovery, version check, IPv4/IPv6 loopback gates, pinned probing, fail-closed, guidance) | Menu 3, 25->4; `--http-probe`, `--check-httpx`; report section 6 | ProjectDiscovery HTTPX v1.13.0+ with pinned target/IP input | **Blocked:** the newest published release is v1.12.0 (checked 2026-11-12), so no vetted binary exists; live probing and real HTTPX field names are unverified |
| 04 | IPv4/IPv6 (`core/scope.py`, HTTPX, Nmap, TLS) | Complete | Automatic; Nmap 4->5 (options 3/4), 4->6, `--nmap-ipv6` | Public IPv6 connectivity for live use | IPv6 HTTPX depends on module 03; IPv6 Nmap resume is unsupported; live IPv6 has only been exercised with mocks |
| 05 | Certificate & TLS (`intelligence/certificate_intelligence.py`, `collectors/tls_probe.py`) | Complete | Menu 16; report section 6 | Current-session DNS (active) or stored HTTPX TLS data (offline) | Signatures and chains not cryptographically validated; chain collection needs Python 3.13+; live inspection only verified on loopback |
| 06 | Advanced DNS (`intelligence/dns_intelligence.py`, DNSx collector, `dnssec_probe.py`) | Complete | Menus 2, 10->1, 10->2; full workflow; report section 5 (including wildcard-probe evidence) | DNSx (bundled); DNSSEC needs `dns.resolvers` in the engagement | DKIM only for operator-supplied selectors; SPF lookups counted at top level only; DNSSEC uses the resolver's AD flag, with no local validation |
| 07 | Subdomain takeover (`intelligence/takeover_intelligence.py`, `data/takeover_signatures.json`) | Complete | Menu 20 (optional operator signature file); full workflow; report section 12 | Current-session DNS | Signatures curated and unverified; response bodies not collected, so body rules match only imported `body_excerpt` evidence; passive only |
| 08 | Cloud intelligence (`intelligence/cloud_intelligence.py`) | Complete | Menu 18; full workflow (without range files); report section 9 | DNS or HTTPX evidence; optional provider range files / ASN CSV | "Confirmed" only with imported published ranges; no RDAP/WHOIS lookups |
| 09 | Technology fingerprinting (`intelligence/technology_fingerprint.py`) | Complete | Menu 17; full workflow; report section 8 | HTTPX, Nmap, or database evidence | Banner versions are self-reported; without HTTPX, only Nmap/database evidence is available |
| 10 | Vulnerability intelligence (`vulnerability_intel.py`, `vulnerability_assessment.py`) | Complete | Menus 6, 14->2; report section 10 | Successful Nmap result plus a local NVD JSON feed | Feed is user-supplied (no download); AND/platform configurations remain candidates; no exploitability claims |
| 11 | Misconfiguration (`intelligence/misconfiguration.py`) | Complete | Menu 19 (optional imports); full workflow (rules only); report section 11 | HTTPX/Nmap evidence or an imported tool file | Header checks need collected headers (HTTPX); HTTP method checks are import-only |
| 12 | AD assessment imports (`intelligence/ad_assessment.py`) | Complete | Menu 21; report section 13 | PingCastle XML, Certipy JSON, or generic JSON/CSV export | Import only; categories are keyword-derived; severity as reported by the tool |
| 13 | Threat intelligence (`intelligence/c2_intelligence.py`) | Complete | Menu 14->4; report section 13 | Local JSON/CSV/STIX feed | Exact matching only; compound STIX patterns are unsupported (reported); no DNS behavioral analysis without resolver telemetry |
| 14 | Attack path & risk correlation (`intelligence/correlation.py`) | Complete | Menu 22; full workflow; report sections 14 and 17 | At least one stage with findings | Paths are theoretical unless imported evidence states `verified: true`; scores are prioritization aids |
| -- | MITRE ATT&CK mapping (`intelligence/mitre_mapping.py`) | Complete | Menu 23; full workflow; report section 15 | Findings | Mappings are analyst aids, not detections |
| 15 | Unified reporting (`reporting/unified_report.py`) | Complete | Menu 12; full workflow | None | Derived stages (impact, correlation, ATT&CK, lifecycle) are reported in their own sections and not double counted; the report never includes itself |
| 16 | Findings lifecycle (`intelligence/findings_lifecycle.py`) | Complete | Menu 24; report (lifecycle snapshot) | A correlation result to sync | Status changes are operator-driven; retests record evidence references, they do not re-scan |
| -- | Session & artifacts (`platform_menu.py`) | Complete | Menu 25 | A started run for manifests | Manifests detect changes; they do not prevent them |
| -- | Stages 03-07 defensive analyzers (delivery, assessment, persistence, IOC, impact) | Complete | Menu 14; report sections 4, 10, 13, 16 | Stage-specific (shown in the menu) | Offline only |

## Session results and the unified report

Every stage result saved in the session is consumed by the report.
- `wildcard_probe` (raw random-label DNSx answers) appears as evidence in section 5. It carries no findings of its own; wildcard findings come only from DNS intelligence, so nothing is duplicated.
- `unified_report` is intentionally excluded: including the report in the next report would nest reports recursively.

## Legacy compatibility modules

These modules are not used by any DomainRecon workflow. They are retained only for import compatibility and their regression tests in `tests/test_v2.py`, and are scheduled for removal in the next major version.

| Module | Superseded by | Still required? | Action taken |
|---|---|---|---|
| `analysis/fingerprint.py` | `intelligence/technology_fingerprint.py` | Only for existing imports and tests | Marked deprecated in its docstring; behavior unchanged |
| `analysis/comparison.py` | `intelligence/change_detection.py` | Only for existing imports and tests | Marked deprecated; behavior unchanged |
| `reports/html_report.py` | `reporting/unified_report.py` | Only for existing imports and tests (it produced `example-report.html`) | Marked deprecated; behavior unchanged |
| `collectors/rdap.py` | Operator-imported ASN maps in cloud intelligence | Not wired into any menu or CLI path, so it generates no traffic | Marked not-integrated. Fixed the IPv6 cache filename (`:` would create an NTFS alternate data stream) and made cache writes atomic. Any future integration needs its own authorization record and engagement switch |

## Behavior notes

- **Engagement.**
  - Can exclude hostnames (whole subtrees), exclude IPs/CIDRs, restrict active targets to public `ip_ranges`, disable operations, and lower limits. Hard caps: concurrency 4, 10 requests/s, HTTPX 2/2.
  - Operation switches: `passive_recon`, `dns_assessment`, `http_assessment`, `tls_assessment`, `port_scanning`.
  - A disabled operation is refused before any prompt and recorded both as an authorization record and in the hash-chained operation history.
- **Public Suffix List.**
  - The official list is installed only by explicit commands. A list whose SHA-256 no longer matches its metadata is refused, and the bundled subset is used instead (`--health` reports this).
  - An operator-pinned list (`DOMAINRECON_PSL_FILE`) that is missing or fails verification makes every root fail closed with a clear error.
- **HTTPX.**
  - Local discovery (configured path, `tools\httpx`, PATH, Go bin) runs only `-version -duc`, and only ProjectDiscovery v1.13.0+ is accepted.
  - IPv4 targets are probed only after the loopback pinning/Host/SNI/DNS-bypass gate passes; IPv6 targets only after the same gate passes over `[::1]` (otherwise `IPV6_NOT_PROBED`).
  - Requests are GET-only with at most 2 threads and 2 requests per second. Redirects are recorded, not followed.
  - A missing or incompatible binary probes nothing and shows the install guidance.
- **TLS.**
  - Uses the acknowledgement `I AUTHORIZE TLS INSPECTION` and the `tls_assessment` switch.
  - Connects to literal validated IPs with SNI set to the in-scope hostname, plus one handshake per protocol version.
- **Takeover.**
  - Matchers: `http_text_contains`, `http_title_contains`, `http_body_contains`, `http_status_in`, `http_header_contains`. Unknown rule types are reported as `unsupported_rules`, and `supporting` rules never raise a classification on their own.
  - Nothing is registered or claimed.
- **Reporting.** 20 sections. The whole report is passed through secret redaction, CSV cells are formula-neutralized, and HTML is escaped under a script-free CSP.
