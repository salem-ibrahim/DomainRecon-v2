# DomainRecon v2

V2 is a separate, additive project. It does not write to `D:\Recon\DomainRecon` or alter v1 results. Passive enumeration preserves the Subfinder + crt.sh workflow and requires `--acknowledge "I AM AUTHORIZED"` in argument mode or the matching interactive confirmation. HTTPX is a separate active stage, disabled unless selected through the menu or `--http-probe` is supplied, and still requires its own exact acknowledgement.

For copy-ready PowerShell setup, health, help, passive enumeration, output inspection, and troubleshooting, see the [Owner CLI Guide](OWNER_CLI_GUIDE.md).

## Setup

```powershell
./setup.ps1
./setup.ps1 -InstallDependencies
./setup.ps1 -InstallDevDependencies
./setup.ps1 -InstallPassiveTools
./setup.ps1 -InstallTools              # HTTPX is refused until a pin-capable release (v1.13.0+) exists
./setup.ps1 -InstallPublicSuffixList    # explicit, typed-YES download of the official PSL
```

Tool installation is opt-in, does not modify PATH, skips working executables, and requires an official GitHub-release SHA-256 checksum. The installer refuses HTTPX older than v1.13.0 because earlier tagged releases predate ProjectDiscovery's pinned target/IP input.

```powershell
python main.py example.com --acknowledge "I AM AUTHORIZED"
```

To also resolve the names discovered by that passive run through DNSx, add `--dns`:

```powershell
python main.py example.com --acknowledge "I AM AUTHORIZED" --dns
```

This creates a new immutable v2 scan directory. The original `passive.json` and `dns.json` payloads remain unchanged; the run also includes an execution summary and readable TXT/CSV exports.

## Interactive terminal mode

Launch the numbered CLI from the project root without arguments:

```powershell
python main.py
```

The application validates the target once, retains successful stage results in the session, and exposes an additive Kill Chain menu. Existing selections 1-9 remain compatible. Stage 01 includes passive enumeration, DNSx, HTTPX, Nmap, database discovery, and a submenu for offline DNS/HTTP intelligence, asset correlation, attack-surface mapping, and reporting. The separate wildcard-DNS action requires its own exact authorization phrase and runs only two generated in-scope labels through DNSx. HTTPX and Nmap retain their existing separate active authorization prompts. Stage 02 normalizes Nmap CPE 2.2 and CPE 2.3 identifiers and matches them against a user-selected local NVD JSON feed (API 2.0 or legacy 1.1). It reports exact-version matches, provable version-range matches, and labelled candidates. It performs no feed download and never downloads or executes exploits. Menu **14** runs the offline Stage 03-07 analyzers (delivery/exposure, safe vulnerability assessment, imported persistence evidence, local IOC correlation, owner-rated impact analysis). Their findings flow into the unified report with Kill Chain stage and source-artifact provenance. Menu **11** shows the actual status and limitations of each stage.

Artifacts are immutable and stored under a session directory, with a numbered subdirectory for each stage, for example `results\example.com\<UTC timestamp>\passive-01\passive.json`. The existing argument-based CLI remains available for scripts and copy-ready commands. No additional Python CLI dependency is required.

## Offline intelligence and unified reports

From the interactive main menu choose **10** for Stage 01 offline analysis. DNS Intelligence consumes the current session's passive and DNSx results, classifies A/AAAA/CNAME outcomes, retains CNAME chains, identifies provider suffixes only when evidence matches, surfaces shared IP/CNAME infrastructure, and records SPF/DMARC/CAA observations with evidence. It never equates an absent optional DNS record with a vulnerability. The optional random-label wildcard probe is a separate opt-in; it preserves names and labels likely wildcard-derived rather than deleting them.

The same submenu can produce a unified asset inventory (hostname identity is stable and is not based on IP alone), an offline attack-surface relationship graph, and normalized HTTP intelligence. Shared CDN/IP relationships remain explicit and do not merge different hostnames. HTTP response headers are marked `not_collected` unless present in the source inventory. An observed HTTP status remains responsive even for 401, 403, or 404; a final URL is not claimed for a request with no observed response. IPv6 answers are probed only when the installed HTTPX binary passes the IPv6 loopback pinning gate; otherwise they are recorded as `IPV6_NOT_PROBED` and only the IPv4 answers are probed.

ProjectDiscovery HTTPX is invoked with its documented `-include-response-header` JSON option. The loopback capability gate verifies the option before any production probe. Cookie and authentication header values are redacted before inventory persistence; ordinary security headers remain available for offline analysis.

The menu also provides conservative historical comparison for observed DNS/IP associations, HTTP responses, open TCP services, identified database services, and exact-CPE CVE findings, plus a partial JSON/CSV/HTML report. Missing or partial stage data is labeled unavailable/unknown rather than used to claim removals. The self-contained HTML is escaped and CSP-restricted. For Stage 02, select option **6** after a successful authorized Nmap run and supply a local NVD-format JSON cache. Matches are typed `exact_cpe_match`, `version_range_match`, or `candidate_match`. Per-service `no_match` and `insufficient_evidence` results are recorded separately. Prioritization displays its inputs and unknown asset criticality. A passive name that is missing from a later run is classified per host as `NOT_OBSERVED`, `SOURCE_FAILED`, or `INSUFFICIENT_DATA`. It is classified `CONFIRMED_REMOVED` only with DNS evidence. No internet query or exploit action occurs.

For the precise menu sequence, artifact locations, wildcard authorization phrase, local NVD feed format, and report inspection commands, see the [Owner CLI Guide](OWNER_CLI_GUIDE.md).

### Interface

On a real terminal the CLI renders an ASCII banner, a SESSION/READINESS dashboard, a grouped menu with type tags (PASSIVE, ACTIVE, OFFLINE, IMPORT, ADMIN, GUIDED) and state badges (READY, NEEDS, BLOCKED), authorization pre-flight panels, and result tables with severity indicators. It adapts to the terminal width (60-140 columns) and never clears the screen.

- **No new dependency.** The renderer is standard-library code. `colorama` (already in `requirements.txt`) is used only to enable ANSI colour on legacy Windows consoles; without it a built-in fallback is tried, and otherwise colour is turned off. Rich is not used.
- **Plain mode** is selected automatically when output is piped or redirected, or with `DOMAINRECON_UI=plain`. It keeps the line-oriented format (`[N] Label - status`) that scripts rely on.
- `NO_COLOR=1` disables colour, `DOMAINRECON_UI=ascii` forces ASCII borders, `DOMAINRECON_UI=styled` forces the layout, and `DOMAINRECON_UI_WIDTH=100` overrides the detected width.
- All text is stripped of control characters before display, so remote values such as page titles cannot inject terminal escape sequences.

Menu numbers are unchanged (1-25); they are grouped under ENGAGEMENT, RECONNAISSANCE, INTELLIGENCE, ANALYSIS, REPORTING, and WORKFLOWS. Two entries were added:

- **26 Scope Review & Target Check** shows the root, exclusions, authorized ranges, and engagement operations, and tests any hostname or IP against the scope.
- **27 Guided Pilot Workflow** walks through engagement, scope confirmation, readiness, stage selection, authorized execution, findings review, and report. Every ACTIVE stage needs a typed `YES` and then its own acknowledgement phrase; selecting a stage never starts it automatically.

Before every network operation a panel shows the operation, its type, the current target, scope limits, rate limits, and the authorization requirement. Typed acknowledgements are never displayed or stored.

Example (styled mode, colour omitted):

```text
── SESSION ───────────────────────────────────────────────────────────────────────
 Engagement             none (root-domain scope only)
 Target                 example.com
 Scope validation       VALID
 Last operation         passive enumeration: success (22:02:51 UTC)
 Findings               HIGH 1  INFO 6  (7 correlated)
── RECONNAISSANCE ────────────────────────────────────────────────────────────────
 [ 1] Passive Subdomain Enumeration             PASSIVE  ● READY
 [ 3] HTTP Services Discovery (HTTPX)           ACTIVE   ○ BLOCKED HTTPX binary missing
 [ 4] Nmap Port Scanning                        ACTIVE   ● READY
```
## Explicit HTTPX inventory

HTTPX can run only after same-run passive collection and DNSx resolution. It accepts only discovered, in-scope names whose answers are all validated public addresses. IPv4 answers are pinned after the IPv4 loopback gate passes; IPv6 answers are pinned only after the separate IPv6 gate passes. If no binary is configured, DomainRecon looks only at local candidates (`tools\httpx`, PATH, Go bin), running nothing but a version query. Run `python main.py --check-httpx` to validate a binary with loopback-only gates. The exact opt-in command is:

```powershell
python main.py example.com `
  --acknowledge "I AM AUTHORIZED" `
  --dns `
  --http-probe `
  --acknowledge-active "I AUTHORIZE ACTIVE PROBING"
```

Use ProjectDiscovery HTTPX v1.13.0 or newer with pinned target/IP JSON input support. Before any active target requests, a loopback-only capability test verifies HTTP connection pinning, the original Host header, HTTPS TLS SNI preservation, and that the supplied hostname is not resolved. The adapter sends `{\"target\":\"https://host/\",\"ip\":\"validated-public-address\"}` inputs, preserving the hostname for Host and TLS SNI while pinning the connection to the checked IP. Older or incompatible binaries are rejected before target requests. The CLI requires the exact active acknowledgement and rejects `--http-probe` without `--dns` or when `--hosts-file` is supplied.

Requests are GET-only, limited to two concurrent threads and two requests per second, with a five-second timeout and no retries. HTTPX automatic redirects, proxy options, HTTP/2, and other unapproved probe modes are not enabled. A response `Location` is recorded and checked against the in-scope discovered host set; it is not followed. `final_url` is set only after a response is observed; failed probes keep it null. Public IPv6 answers are currently blocked because the pinning preflight proves IPv4 transport only. The inventory classifies live responses, authentication requirements, restricted access, not-found responses, redirects, TLS errors, timeouts, refused connections, and unknown errors.

The opt-in run adds `live_web_inventory.json`, `live_web_inventory.csv`, and `live_web_inventory.txt`; it does not change the existing passive or DNS JSON artifact formats. Check `python main.py --health` for the configured HTTPX executable path. If HTTPX is not installed or is older than the pinned-input minimum, the active stage refuses to start.

## Phase 1: Nmap

Nmap is a separately installed dependency. DomainRecon does not install it automatically or change PATH. Place a vetted `nmap.exe` under `tools/nmap/`, or pass `--nmap <absolute-path>`. Nmap scanning is active and requires its own exact acknowledgement:

```powershell
python main.py company.example --nmap-mode common --acknowledge-active "I AUTHORIZE PORT SCANNING"
```

Modes are `common` (top 100 TCP ports), `full` (`1-65535`, explicitly selected), and `custom` with `--nmap-ports 443,8000-8010`. Nmap XML is parsed into `nmap.json`; normal `.nmap` output is retained as Nmap's native resume token. The module uses TCP connect scanning, bounded `--max-rate`, bounded parallelism, a host timeout, and optional light service/version detection. No NSE scripts, UDP, OS detection, brute force, exploitation, or vulnerability scripts are enabled.

Before scanning, V2 requires an in-scope hostname, resolves and validates all IPv4 answers as public addresses, re-resolves immediately before execution, and passes only the validated numeric addresses to Nmap. IPv6 is opt-in (`--nmap-ipv6`, or Nmap menu options 5->3/4 and 6). Public IPv6 answers are validated in the same way and scanned in separate `-6` invocations; resuming IPv6 scans is not supported. Private, loopback, link-local, multicast, and reserved addresses are blocked by default. Resume through the Python API requires the same explicit authorization, scope, and target; it proceeds only when the native log contains a safely parsed pinned-address command matching current DNS. The loopback exception is available only through the explicit `ScopePolicy(..., allow_loopback_for_lab=True)` setting for controlled tests; the CLI never enables it.

Check tool availability without any network activity:

```powershell
python main.py --health
```

## Phase 2: Database Discovery

Database Discovery is offline-first. It reads a completed Phase 1 `nmap.json`, opens no sockets, does not connect to a database, and creates a new immutable v2 result directory.

```powershell
python main.py company.example `
  --database-discovery `
  --nmap-input "D:\Recon\DomainRecon-v2\results\company.example\<scan>\nmap.json" `
  --results "D:\Recon\DomainRecon-v2\results"
```

The result contains `database_inventory.json` and `database-discovery.events.jsonl`. It supports MySQL, MariaDB, PostgreSQL, Microsoft SQL Server, MongoDB, Redis, and Oracle only when Nmap evidence supports a classification. Nmap service name, normalized product, identity, version, and all supplied CPE values remain distinct fields. A database port alone is recorded only as an ambiguous candidate; it does not create a product identity, CPE, vulnerability, or verified finding. See [the versioned schema](schemas/database_inventory_v1.json) and [the Phase 2 proposal](PHASE2_DATABASE_DISCOVERY_PROPOSAL.md).

## Test

```powershell
python -m pytest -p no:cacheprovider -q
```

The optional Nmap lab test starts a local TCP listener and scans only `127.0.0.1`; it is deliberately disabled unless both Nmap is installed and `DOMAINRECON_RUN_NMAP_LAB=1` is set.

The HTML report is static, CSP-restricted, and escapes every record value. It does not embed external assets.

## Platform modules (feature-complete build)

Module-by-module behavior, status, and limitations are documented in [docs/MODULES.md](docs/MODULES.md). A commented configuration example is in [engagement.example.yaml](engagement.example.yaml).

### Interactive menu map

Menu numbers 1-14 keep their legacy meaning. Numbers 15-25 were added for the platform modules:

| Target design | Actual menu |
|---|---|
| Engagement Management | **15** |
| External Asset Discovery | **1** passive, **2** DNS, **10** offline intelligence (assets, attack surface) |
| DNS & Email Security | **2** (apex/_dmarc/DKIM policy records, optional DNSSEC), **10 -> 1** DNS intelligence, **14 -> 1** delivery |
| HTTP & TLS Intelligence | **3** HTTPX, **10 -> 5** HTTP intelligence, **16** TLS & certificates |
| Network & Service Assessment | **4** Nmap (root domain, or **4 -> 5** discovered hosts), **5** database discovery |
| Technology Fingerprinting | **17** |
| Cloud Intelligence | **18** |
| Vulnerability Intelligence | **6** (Stage 02), **14 -> 2** (Stage 04) |
| Security Misconfiguration Assessment | **19** |
| Subdomain Takeover Intelligence | **20** |
| AD Assessment Imports | **21** |
| Threat Intelligence | **14 -> 4** (IOC/STIX), **14 -> 3** (persistence evidence) |
| Attack Path & Risk Correlation | **22** |
| MITRE ATT&CK Mapping | **23** |
| Unified Security Report | **12** |
| Findings & Retesting | **24** |
| Session & Artifact Management | **25** |
| Full Assessment Workflow | **7** (collection with separate authorization prompts, then every offline analysis that needs no operator input and whose prerequisites are met (DNS/HTTP intelligence, asset inventory, technology, takeover, cloud without range files, misconfiguration rules without imports, delivery, correlation, ATT&CK), then generating the unified report. TLS inspection (active) and import-driven stages (AD, persistence, IOC feeds, owner criticality) stay manual) |

### New command-line options

```powershell
python main.py example.com --acknowledge "I AM AUTHORIZED" --dns --engagement engagement.yaml
python main.py --health                                  # adds Public Suffix List status and HTTPX install guidance
python main.py --update-psl --confirm-download           # the only command that downloads the official PSL
python main.py --install-psl .\public_suffix_list.dat    # offline install of a copy obtained through an approved channel
python main.py --check-httpx                             # HTTPX version + loopback-only pinning gates
python main.py example.com --nmap-mode common --acknowledge-active "I AUTHORIZE PORT SCANNING" --nmap-ipv6
```

`--engagement` narrows scope and can refuse operations that the file disables, before any output or network activity. It never replaces `--acknowledge` / `--acknowledge-active`.

### Dependencies

There are no new Python dependencies: YAML (subset), X.509 parsing, DNSSEC queries, and hash-chained ledgers use the standard library only. External binaries are unchanged:
- Subfinder and DNSx are bundled under `tools\`.
- Nmap is optional and installed separately.
- ProjectDiscovery HTTPX v1.13.0+ with pinned target/IP input is required for HTTP probing. **Blocker (checked 2026-11-12):** the newest published release is v1.12.0, and pinning exists only on the dev branch. No vetted binary can be installed, so HTTP probing stays disabled: `--http-probe` and menu 3 refuse to run, and `--check-httpx` explains why. A self-built binary must pass `--check-httpx` before use.
- The official Public Suffix List is not installed by default. Install it with `setup.ps1 -InstallPublicSuffixList`, `python main.py --update-psl --confirm-download`, or `--install-psl FILE`. Until then, the bundled offline subset with a fail-closed heuristic is used.
- Engagement switch `operations.vulnerability_validation` is deprecated: accepted only as `false`, refused as `true` (DomainRecon performs no vulnerability validation).
- Legacy compatibility modules (`analysis/fingerprint`, `analysis/comparison`, `reports/html_report`, `collectors/rdap`) are not used by any workflow; see [docs/MODULES.md](docs/MODULES.md#legacy-compatibility-modules).
