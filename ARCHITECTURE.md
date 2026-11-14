# DomainRecon v2 architecture

## Isolation and compatibility

V2 is isolated from v1 and reads v1 results only through `read_v1_scan`. The importer reads `subdomains.json`, filters it through the v2 policy, and performs no write against the source directory. New scans use unique timestamped directories and every artifact writer refuses an existing filename.

## Trust boundaries

`ScopePolicy` is the only hostname, URL, and IP validation authority. Every collector receives a `ScopePolicy` and must use it before processing input or starting a network operation. It rejects wildcard names, URLs, ports, command metacharacters, deceptive suffixes, invalid IDNA, non-root URL paths, and non-public addresses.

Passive enumeration requires the existing authorization acknowledgement. HTTP/TLS requires a second `ActiveAuthorization` acknowledgement. HTTPX receives only discovered, scope-validated root URLs on ports 80 and 443, pinned to validated addresses, with at most two threads, two requests/second, five-second timeout, and no credential or custom-path support. IPv6 targets are pinned only after the binary passes the IPv6 loopback pinning gate; otherwise they are recorded as IPV6_NOT_PROBED.

## DNS rebinding controls

DNS answers are captured before HTTPX starts. Only globally routable IPv4 answers proceed. HTTPX JSON must report a connected IP matching the pinned answer; a mismatch, missing address, or private answer is blocked and saved as evidence. The collector never retries against an unvalidated IP. Redirect destinations are parsed and policy-checked but never followed; the observed destination is retained only as redirect evidence.

## Modules and artifacts

| Milestone | Module | Immutable artifact / result |
| --- | --- | --- |
| A | `core` | scope, authorization, manifest, immutable storage |
| B | `collectors.dns_intelligence` | `dns.json` |
| C | `analysis.comparison` | offline comparison object |
| D | `active.httpx_probe` | authorized HTTP observations |
| E | `analysis.fingerprint` | header/title-derived hints |
| F | `analysis.tls` | normalized HTTPX TLS fields |
| G | `collectors.rdap` | separately cached public-IP registration data |
| H | `reports.html_report` | static CSP-restricted HTML |
| I | `intelligence.dns_intelligence` | offline DNS/CNAME/wildcard/shared-infrastructure analysis |
| J | `intelligence.asset_correlation` | stable hostname and distinct IP-infrastructure inventory |
| K | `intelligence.attack_surface` | offline nodes and typed evidence relationships |
| L | `intelligence.http_intelligence` | stored HTTP/TLS/security-header observations; no requests |
| M | `intelligence.change_detection` | conservative history with unavailable stages marked unknown |
| N | `intelligence.vulnerability_intel` | CPE 2.2/2.3 normalization; exact and NVD version-range matching against a local feed; labelled candidates |
| P | `intelligence.delivery_intelligence` | Stage 03 exposure (HTTPX/Nmap evidence only) and MX/SPF/DMARC observations |
| Q | `intelligence.vulnerability_assessment` | Stage 04 confirmed/range/possible version matches with separate contextual risk |
| R | `intelligence.persistence_intelligence` | Stage 05 imported Windows/Sysmon/Wazuh/Linux audit evidence mapped to ATT&CK |
| S | `intelligence.c2_intelligence` | Stage 06 exact IOC correlation against local JSON/CSV/STIX feeds |
| T | `intelligence.impact_analysis` | Stage 07 owner-rated criticality/CIA impact estimates |
| U | `core.public_suffix`, `core.csv_safe`, `core.authorization` | public-suffix root refusal, formula-safe CSV, immutable authorization records |

`ScopePolicy` refuses public/registry suffixes as roots. It uses an offline PSL subset plus a fail-closed heuristic, or the official list when supplied locally. Its only underscore exception is `require_dns_policy_name`, which accepts `_dmarc.<in-scope host>` for DNS TXT policy queries. Those names are never probed or scanned. Nmap can scan explicitly selected discovered hostnames (`run_nmap_hosts`). Each name is validated, resolved to public IPv4 only, revalidated before execution, and deduplicated by IP by default. Concurrency is bounded, and the per-unit rate is divided so the aggregate rate stays bounded. Before an Nmap resume starts, the files Nmap will append to are copied with exclusive creation and hashed. A resume reports `success` only when its XML parses.
| O | `reporting.unified_report` | partial JSON/CSV/CSP-restricted escaped HTML |

Failures and incomplete collection are represented as `failed`, `unknown`, `unresolved`, `skipped`, or `blocked`; a missing observation is never treated as a removed asset. Change detection classifies every previously seen hostname as `STILL_PRESENT`, `NOT_OBSERVED`, `SOURCE_FAILED`, `INSUFFICIENT_DATA`, or `CONFIRMED_REMOVED`. The last status requires a previous successful resolution and a current DNS query that returned no records. Derived interactive artifacts include schema/project version, target, run ID, stage, module, timestamp, status, source, evidence, and findings. Original passive, DNS, HTTPX, and Nmap artifact schemas remain unchanged for compatibility. Intelligence modules operate on stored evidence except the separately acknowledged DNSx wildcard probe. The Stage 02 module does not fetch NVD data, download exploits, or execute payloads.

## Platform layer

| Layer | Modules |
| --- | --- |
| Core trust and audit | `core.scope` (root, exclusions, authorized IP ranges, IPv4/IPv6 classification, IPv6 tunnel-form blocking), `core.public_suffix` (official list with integrity metadata, or bundled subset), `core.engagement` (configuration-only narrowing), `core.authorization` (per-decision records), `core.ledger` (hash-chained append-only history), `core.redaction`, `core.csv_safe`, `core.simple_yaml` |
| Active collectors (each with its own acknowledgement) | passive, DNSx (+ policy names), DNSSEC query (configured resolvers only), HTTPX (IPv4 and gated IPv6 pinning), TLS handshake collector (`collectors.tls_probe`, pinned IP + SNI), Nmap (root, discovered hosts, opt-in IPv6) |
| Offline analyzers | DNS, HTTP, certificates, technology, cloud, takeover, misconfiguration (+ tool imports), delivery, vulnerability intel/assessment, persistence, AD imports, IOC correlation, impact |
| Correlation and reporting | `intelligence.correlation` (canonical `DRF-` findings, risk, graph, theoretical attack paths), `intelligence.mitre_mapping`, `intelligence.findings_lifecycle`, `reporting.unified_report` (20 sections, redaction, CSV neutralization, CSP HTML) |
| Interfaces | `interactive.InteractiveApp` + `platform_menu.PlatformMenusMixin` (menus 15-25, offline pipeline for the full workflow), `cli` (legacy arguments plus `--engagement`, `--update-psl`, extended `--health`) |

Engagement files can only remove permissions; ScopePolicy and the typed acknowledgement remain mandatory for every network operation. An engagement-disabled operation is refused before any prompt, and the refusal is recorded both in the run's authorization records and in the engagement's operation history.

Report inputs: every session stage result is consumed by `reporting.unified_report`. The wildcard probe is evidence-only (section 5), and the report never consumes itself. The legacy modules `analysis.fingerprint`, `analysis.comparison`, `reports.html_report`, and `collectors.rdap` are retained for import compatibility only and are not on any workflow path (see docs/MODULES.md).

Presentation: `ui.Console` (standard-library renderer with layout, colour, and Unicode capabilities detected independently, plus control-character sanitizing) and `console_views.ConsoleViewsMixin` (dashboard, grouped menu, authorization pre-flight panel, result tables, scope review, guided pilot workflow). Views only read session state; collection, ScopePolicy, engagement gating, acknowledgements, and audit records are unchanged. With injected or piped output the legacy plain line format is kept.
