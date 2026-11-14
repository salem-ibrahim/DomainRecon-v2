# DomainRecon V2 Owner CLI Guide

This guide covers the implemented V2 CLI from the project root, including its interactive menu and argument-based mode. The default workflow is passive collection through Subfinder and crt.sh, with optional DNSx resolution. It does not run HTTP probes, Nmap, or exploitation unless an explicit menu selection or active CLI option and the separate authorization are supplied. The `--dns` option makes DNS queries through DNSx; it does not perform TCP/HTTP service scans by itself.

## 1. Prepare Python and dependencies

Open PowerShell and run:

```powershell
$Project = 'D:\Recon\DomainRecon-v2'
Set-Location $Project
python --version
$Venv = Join-Path $env:LOCALAPPDATA 'DomainRecon-v2\venv'
if (-not (Test-Path $Venv)) { python -m venv $Venv }
$Python = Join-Path $Venv 'Scripts\python.exe'
& $Python -m pip install -r .\requirements.txt -r .\requirements-dev.txt
```

DomainRecon setup requires Python 3.12 or newer. The virtual environment is kept under the current Windows user's `%LOCALAPPDATA%`, not inside the project directory. To activate it in the current PowerShell window:

```powershell
. "$Venv\Scripts\Activate.ps1"
```

If PowerShell blocks activation, do not change the execution policy; use `$Python` directly as shown in the remaining commands.

## Interactive menu (recommended first run)

Launch once from the project root:

```powershell
& $Python .\main.py
```

Enter the target domain when prompted. DomainRecon validates it and retains successful stage results for this session. Existing choices 1-9 remain unchanged. Choice 10 opens the Stage 01 offline-intelligence menu: DNS Intelligence, an opt-in wildcard DNS check, unified asset inventory, attack-surface mapping, stored HTTP intelligence, historical comparison, and unified reporting. Choice 6 on the main menu is Stage 02 CVE intelligence; it requires a successful authorized Nmap result and optionally accepts a local NVD-format JSON feed. It does not download feeds or exploit code. Choice 11 shows accurate implementation status for all seven Kill Chain stages; stages 03-06 remain limited or unimplemented and are not active attack modules.

Passive collection requires typing exactly `I AM AUTHORIZED` when first requested. Selecting HTTPX requires the separate exact phrase `I AUTHORIZE ACTIVE PROBING`. Selecting any Nmap scan or resume requires `I AUTHORIZE PORT SCANNING`. The Full Reconnaissance Workflow does not silently start active stages: it asks before HTTPX and Nmap, and then requires their individual authorization prompts. Press `0` in a submenu to go back; `Ctrl+C` cancels the current input/operation and returns to the menu. An invalid menu number does not terminate the application.

Each interactive session uses an immutable directory such as `results\example.com\<UTC timestamp>\`, with numbered stage folders such as `passive-01\` and `dns-01\`. Repeating a stage writes a new folder rather than replacing earlier artifacts. `View Previous Results` is limited to the selected target's V2 results. Offline analyses run only against stored/current-session artifacts and do not launch Nmap or HTTPX. The wildcard DNS check is the exception: it sends two explicitly authorized, random in-scope DNS queries through DNSx.

**Illustrative terminal session only; the sample count is a placeholder and no enumeration is represented as completed here:**

```text
PS> & $Python .\main.py
DomainRecon V2  |  version 2.0.0
Enter Target Domain (blank to exit): example.com
Current target: example.com
Scope validation: VALID
MAIN MENU
[1] Passive Subdomain Enumeration - available
[2] DNS Resolution - unavailable: enumerate first
[3] Live Web Services Discovery (ProjectDiscovery HTTPX) - unavailable: HTTPX binary missing
[4] Nmap Port Scanning - available
...
Select an option: 1
PASSIVE SUBDOMAIN ENUMERATION
[1] Subfinder - available
[2] crt.sh - available (requires internet access)
[3] Both - available
[0] Back
Select a source: 2
Type exactly "I AM AUTHORIZED" to authorize passive collection: I AM AUTHORIZED
[passive] Collecting selected source(s); results are filtered to the validated target scope.
  crt.sh: [sample count] names; complete
```

Subfinder and DNSx are optional executable dependencies. Check their status in the health command below. To install only the passive tools with the project's checksum-verifying setup script, run:

```powershell
.\setup.ps1 -InstallPassiveTools
```

At the prompt, type `YES` to confirm. This installs Subfinder and DNSx only; it does not install HTTPX. The script places those executables under `tools\subfinder` and `tools\dnsx`, does not modify PATH, and requires a Python 3.12+ installation under `%LOCALAPPDATA%\Programs\Python`. `-InstallTools` also requests HTTPX, but the installer rejects versions older than 1.13.0 because they predate pinned target/IP input.

## 2. Health check

```powershell
& $Python .\main.py --health
```

This prints JSON status for Nmap, Subfinder, DNSx, and HTTPX. Nmap and HTTPX are not required for passive subdomain enumeration. `not installed` for Subfinder or DNSx means the corresponding source/tool will be incomplete if requested; crt.sh is accessed by the Python program and needs network access.

## 3. Help

```powershell
& $Python .\main.py --help
```

The actual passive command takes the authorized root domain as the positional argument. It requires the exact acknowledgement string `I AM AUTHORIZED`.

## 4. Passive subdomain enumeration

To collect from Subfinder and crt.sh without DNSx resolution:

```powershell
& $Python .\main.py example.com --acknowledge "I AM AUTHORIZED" --results .\results
```

To resolve the names discovered in that same run with DNSx, add `--dns`:

```powershell
$RunDir = & $Python .\main.py example.com `
    --acknowledge "I AM AUTHORIZED" `
    --dns `
    --results .\results
$EnumerationExitCode = $LASTEXITCODE
"Run directory: $RunDir"
"Exit code: $EnumerationExitCode"
```

The CLI prints the newly created result directory. `--hosts-file <path>` is also supported with `--dns`; when supplied, DNSx resolves the in-scope names in that UTF-8 text file instead of using this run's discovered names. Subfinder and crt.sh still run in that command. Out-of-scope hostnames in the file are filtered.

The passive source collection contacts Subfinder locally and crt.sh over HTTPS; `--dns` also sends DNS queries through DNSx. This guide's automated tests mock these data sources and do not run a real enumeration.

## 5. Inspect results

Each run writes to a new immutable folder shaped like `results\<root-domain>\<UTC timestamp>`. The exact path is printed by the CLI. The passive run writes:

- `scan_manifest.json` — root domain and whether DNSx was requested.
- `passive.json` — existing passive artifact format: status, source errors, deduplicated hostname records, and each hostname's `subfinder` / `crtsh` attribution (`crtsh` is the artifact label for crt.sh).
- `dns.json` — existing DNS artifact format when `--dns` is requested; each hostname has `success`, `unresolved`, or `failed` status.
- `enumeration_summary.json` — source counts/timings/errors, total timing, and separate resolved, unresolved, and failed DNS hostname lists.
- `subdomains.csv` and `subdomains.txt` — readable exports with source attribution and DNS status.

Example PowerShell inspection commands (set `$RunDir` to the printed path if it was not captured):

```powershell
Get-Content (Join-Path $RunDir 'enumeration_summary.json') -Raw | ConvertFrom-Json | Format-List
Import-Csv (Join-Path $RunDir 'subdomains.csv') | Format-Table -AutoSize
Get-Content (Join-Path $RunDir 'subdomains.txt')
Get-Content (Join-Path $RunDir 'passive.json') -Raw
Get-Content (Join-Path $RunDir 'dns.json') -Raw
```

An `unresolved` hostname means DNSx did not return a parsed DNS result for that name during this run; it does not by itself prove the hostname never existed. A `failed` record means the DNSx operation failed for that hostname (for example, DNSx missing or a timeout); inspect its `error` in `dns.json`. An unresolved result is distinct from a tool/source failure.

## 6. Explicit HTTPX live web inventory

HTTPX is active. It is opt-in and requires both the passive acknowledgement and the separate active phrase. It also requires `--dns`; it uses only the in-scope hostnames discovered in this run and their successful DNSx answers. `--hosts-file` is intentionally incompatible with HTTPX.

```powershell
$RunDir = & $Python .\main.py example.com `
    --acknowledge "I AM AUTHORIZED" `
    --dns `
    --http-probe `
    --acknowledge-active "I AUTHORIZE ACTIVE PROBING" `
    --results .\results
$HttpxExitCode = $LASTEXITCODE
"Run directory: $RunDir"
"Exit code: $HttpxExitCode"
```

Use a ProjectDiscovery HTTPX binary v1.13.0 or newer that supports pinned target/IP JSON input. Before active targets are requested, a loopback-only capability test verifies HTTP IP pinning, the Host header, HTTPS TLS SNI, response-header JSON output, and that the hostname is not resolved. The adapter passes each target as a hostname URL plus the previously validated public IP, so the connection is pinned without losing the hostname used for Host and TLS SNI. It invokes HTTPX's documented `-include-response-header` option and redacts cookie/authentication header values before saving observations. The version and capability checks run before passive sources or target requests; an old, missing, unparseable, or incompatible binary is rejected. A custom executable can be supplied with `--httpx <path>`.

The probe is GET-only, at most two concurrent requests and two requests per second, with a five-second timeout and no retries. Automatic redirects are disabled. The `Location` value is recorded and checked against discovered in-scope hosts; it is not followed. `final_url` is only set when a response is observed; failed probes leave it null. Private, loopback, link-local, multicast, reserved, or otherwise non-public DNS answers are rejected before the HTTPX process starts. IPv6 targets remain blocked until the runtime self-test proves IPv6 connection pinning.

The run creates `live_web_inventory.json`, `.csv`, and `.txt` beside the passive/DNS artifacts. Each observation includes URL, classification, status code, title, web server, technologies, response time, response headers when returned, redirect details, pinned IP, TLS certificate metadata, and a final URL only when a response was observed. Cookie/authentication header values are redacted. Classifications include `LIVE`, `AUTH_REQUIRED`, `ACCESS_RESTRICTED`, `NOT_FOUND`, `REDIRECT`, `TLS_ERROR`, `TIMEOUT`, `CONNECTION_REFUSED`, and `UNKNOWN_ERROR`.

Inspect the inventory with:

```powershell
Get-Content (Join-Path $RunDir 'live_web_inventory.json') -Raw | ConvertFrom-Json | Format-List
Import-Csv (Join-Path $RunDir 'live_web_inventory.csv') | Format-Table -AutoSize
Get-Content (Join-Path $RunDir 'live_web_inventory.txt')
```

## 7. Interactive intelligence and reports

Start the interactive app from the project root. To generate current-session artifacts, run passive discovery and DNS first:

```powershell
& $Python .\main.py
```

Select **1** (Passive Subdomain Enumeration), choose a source, and authorize with `I AM AUTHORIZED`. Then select **2** (DNS Resolution). Choose **10** (Stage 01 Offline Intelligence) for derived analysis. The submenu options are:

1. DNS Intelligence: record classification, CNAME chains, shared infrastructure and evidence-based SPF/DMARC/CAA observations. Requires successful passive and same-session DNS results.
2. Controlled Wildcard DNS Probe: optional, exactly two generated in-scope labels through DNSx. It asks for the separate exact phrase `I AUTHORIZE DNS WILDCARD PROBING`; decline or enter anything else and no DNSx process is run for this operation. Wildcard results are evidence and do not delete discovered names.
3. Unified Asset Inventory: stable hostname identities, source attribution, observed addresses, services, and evidence references.
4. Attack Surface Map: offline JSON nodes and typed relations from the stored evidence.
5. HTTP Intelligence: reads stored HTTPX observations only; it makes no request. The normal HTTPX run requests response-header JSON output; an absent header collection is labeled `not_collected` rather than interpreted as headers missing from the server.
6. Historical Change Detection: choose a previous run for the same target. It compares observed DNS/IP, HTTP, open TCP, identified database-service, and CVE changes. Unavailable or partial stages are marked unknown; they do not prove removals.
7. Unified Report: writes a partial JSON/CSV/HTML report under a new immutable `report-NN` folder.

For Stage 02, select **6** from the main menu after a successful authorized Nmap run. Provide a path to a local NVD-format JSON feed/cache, or leave blank to save an offline/no-feed status report. Only exact explicit CPE matches are emitted. Candidate matches are not confirmed exploitability; the risk-priority inputs display CVSS, match confidence, whether the Nmap state is open, evidence quality and unknown asset criticality. NVD reference tags may be recorded as references only; no exploit is downloaded or run.

Other main-menu options: **11** shows the actual implementation status of all seven Kill Chain stages; **12** creates a unified JSON/CSV/HTML report from every stage that has run; **13** compares historical runs; **14** opens the Stages 03-07 offline defensive analysis menu. The numeric menu choices 1-9 remain unchanged.

Menu **14** (all offline; no network activity, scanning, exploitation, or endpoint access):

- **[1] Stage 03 Delivery & Exposure** - needs current-session DNS, HTTPX, or Nmap evidence. Exposure is classified only from HTTPX/Nmap observations; MX/SPF/DMARC come from the apex and `_dmarc.<domain>` TXT/MX records that the DNS stage now collects into `dns_policy.json`.
- **[2] Stage 04 Safe Vulnerability Assessment** - needs a Stage 02 run with a local NVD feed. Classifies matches as `CONFIRMED_VERSION_MATCH`, `VERSION_RANGE_MATCH`, or `POSSIBLE_VERSION_MATCH`.
- **[3] Stage 05 Persistence Evidence Import** - prompts for a local `.json`, `.jsonl`, `.ndjson`, or `.csv` export (max 10 MB) and a source label. Invalid JSONL lines are isolated and reported.
- **[4] Stage 06 IOC / C2 Correlation** - prompts for a local JSON, CSV, or STIX 2.x bundle (max 25 MB). Matching is exact and normalized; matches are leads, not proof of compromise.
- **[5] Stage 07 Impact Analysis** - optional owner criticality JSON (`{"schema_version": 1, "assets": [{"asset_id": "...", "criticality": "HIGH", "source": "...", "cia": {"confidentiality": 4}}]}`). Without it, impact is `not_assessed`.

Nmap menu option **[5] Discovered in-scope hosts** scans only hostnames that DNSx resolved successfully in the current session. Each name is scope-validated, resolved to public IPv4 addresses, and re-resolved before execution. By default each unique IP is scanned once and mapped back to its hostnames. Separate per-hostname scanning must be chosen explicitly. It requires its own `I AUTHORIZE PORT SCANNING` acknowledgement. The grouping prompt offers `[3]`/`[4]` to also scan validated public IPv6 answers (separate `-6` invocations). Option **[6]** scans the root domain dual-stack. The argument-mode equivalent is `--nmap-mode common --nmap-hosts-file hosts.txt [--nmap-per-hostname] [--nmap-ipv6]`; `--nmap-ipv6` without a hosts file scans the root domain dual-stack.

Every authorization decision (granted or denied) is written as an immutable `authorization-NNN-<operation>.json` record in the run folder before any network operation starts. The typed text is never stored. Root targets that are public/registry suffixes (for example `co.uk`, `com.sa`, `github.io`) are refused; place the official `public_suffix_list.dat` in `domainrecon\data\` or set `DOMAINRECON_PSL_FILE` to use the complete list instead of the bundled offline subset.

After a report is created, inspect it with the printed path, for example:

```powershell
$ReportDir = 'D:\Recon\DomainRecon-v2\results\example.com\<run-id>\report-01'
Get-Content (Join-Path $ReportDir 'unified_report.json') -Raw | ConvertFrom-Json | Format-List
Import-Csv (Join-Path $ReportDir 'unified_report.csv') | Format-Table -AutoSize
Invoke-Item (Join-Path $ReportDir 'unified_report.html')
```

## 8. Exit codes and common troubleshooting

- **0** — requested passive sources completed without tool/source failures. Individual names may still be unresolved.
- **1** — partial results were saved, but at least one requested source or DNSx record failed. Read `enumeration_summary.json` and the relevant `errors` in the JSON artifacts.
- **2** — CLI usage/argument error. Check the root domain, exact acknowledgement, and that `--hosts-file` exists when supplied. Argument errors are rejected before a result directory is created or collection begins.

Common cases:

- **Subfinder/DNSx shows `not installed`:** run the opt-in `setup.ps1 -InstallPassiveTools` command above, or install the binaries at the paths shown by `--health`. Subfinder/DNSx are not Python packages.
- **HTTPX missing or rejected as too old:** active HTTPX requires a compatible pinned-input build (v1.13.0+). Do not bypass the gate or use an older binary; use the `--httpx` path override only for a compatible ProjectDiscovery executable.
- **crt.sh timeout or HTTP error:** the source retries boundedly; its source status and error are recorded in `enumeration_summary.json`. If Subfinder succeeds, its results are still retained.
- **Exit code 1 but files exist:** this is intentional partial-result handling, not a lost run. Check each source's status and error in `enumeration_summary.json`.
- **PowerShell activation is blocked:** use `& $Python ...` rather than changing execution policy.
- **Nmap is missing:** it is not needed for this passive workflow. Do not add `--nmap-mode` to the passive command.

Run the offline automated suite from the project root with:

```powershell
& $Python -m pytest -p no:cacheprovider -q
```

The tests use mocked Subfinder, crt.sh, and DNSx responses for passive-source behavior. The opt-in real Nmap lab test is separate and is not part of this passive first-run workflow.

## Platform menus (15-25)

- **15 Engagement Management:** load `engagement.yaml`/`.json` (see `engagement.example.yaml`), create one interactively, show scope/operations/limits, and verify the hash-chained operation history. Loading an engagement for a different domain requires typing `SWITCH`, which resets the session.
- **16 TLS & Certificate Intelligence:** `[1]` analyzes certificates already returned by HTTPX (offline). `[2]` performs pinned TLS handshakes to current-session DNS answers and TLS-like Nmap ports after `I AUTHORIZE TLS INSPECTION`.
- **17 Technology**, **18 Cloud** (optional provider range files and an ASN CSV), **19 Misconfiguration** (optional Nuclei/testssl/generic import), **20 Takeover**, **21 AD imports** (PingCastle XML, Certipy JSON, generic): all offline. Each one states the prerequisite that is missing instead of running.
- **22 Correlation** builds canonical findings, risk priorities (P1-P4), and theoretical attack paths. **23** prints the ATT&CK tactic/technique matrix.
- **20 Takeover** optionally accepts an operator signature file (same schema as `domainrecon\data\takeover_signatures.json`). **25 -> 4** and `python main.py --check-httpx` validate the HTTPX binary (version plus loopback-only pinning gates). `python main.py --install-psl <file>` installs the official Public Suffix List from a local copy with the same validation as `--update-psl --confirm-download`.
- Each entry in menus 15-25 shows `available` or the prerequisite it still needs.
- **24 Findings & Retesting:** sync correlated findings, change status (a note is required), record retest results, add notes, and export a lifecycle snapshot for the report.
- **25 Session & Artifacts:** registered stage artifacts, SHA-256 integrity manifest write/verify, and the run's authorization records.
- **7 Full workflow** now ends by running every offline analysis that needs no operator input and whose prerequisites are met (DNS/HTTP intelligence, asset inventory, technology, takeover, cloud without range files, misconfiguration rules without imports, delivery, correlation, ATT&CK), then generating the unified report. TLS inspection (active) and import-driven stages (AD, persistence, IOC feeds, owner criticality) stay manual.

## Command-line reference (all options)

| Option | Purpose | Constraints / prerequisites |
|---|---|---|
| `domain` | Authorized root domain | Required except for `--health`, `--check-httpx`, `--update-psl`, `--install-psl`. Public suffixes are refused. |
| `--health` | Local tool, PSL, and HTTPX-discovery status | No network activity |
| `--check-httpx` | HTTPX version plus loopback-only IPv4/IPv6 pinning gates | Exit 0 only when ready; no external traffic |
| `--update-psl` / `--confirm-download` | Download the official Public Suffix List | Both flags are required; the final URL must be HTTPS on publicsuffix.org |
| `--install-psl FILE` | Install the official PSL from a local copy | Same validation and integrity metadata as `--update-psl` |
| `--engagement FILE` | Apply an engagement file (YAML subset or JSON) | Target must match `domain`; can only narrow scope or refuse operations |
| `--acknowledge "I AM AUTHORIZED"` | Passive authorization | Required for passive, DNS, and HTTPX runs |
| `--subfinder PATH` | Subfinder executable | Default `tools\subfinder\subfinder.exe` |
| `--dns` | Resolve discovered names with DNSx (plus apex/_dmarc/DKIM policy records) | Passive mode only |
| `--hosts-file FILE` | Resolve these in-scope names instead of passive results | Requires `--dns`; not allowed with `--http-probe` |
| `--dnsx PATH` | DNSx executable | Default `tools\dnsx\dnsx.exe` |
| `--http-probe` | HTTPX against same-run discovered hosts | Requires `--dns` and `--acknowledge-active "I AUTHORIZE ACTIVE PROBING"`; runs the loopback gate before collection |
| `--httpx PATH` | HTTPX executable | Default `tools\httpx\httpx.exe`; if it is missing, local discovery (PATH, Go bin) is used. A custom path requires `--http-probe` or `--check-httpx` |
| `--acknowledge-active PHRASE` | Active authorization | `I AUTHORIZE ACTIVE PROBING` (HTTPX) or `I AUTHORIZE PORT SCANNING` (Nmap) |
| `--nmap-mode common\|full\|custom` | Nmap TCP connect scan | Requires the port-scanning acknowledgement; cannot be combined with passive/DNS/HTTPX options |
| `--nmap-ports LIST` | Custom ports, e.g. `443,8000-8010` | `custom` mode only |
| `--nmap-hosts-file FILE` | Scan these in-scope hostnames (deduplicated by IP) | With `--nmap-mode`; at most 256 hosts |
| `--nmap-per-hostname` | One scan per hostname instead of per unique IP | Requires `--nmap-hosts-file` |
| `--nmap-ipv6` | Also scan validated public IPv6 answers (separate `-6` runs) | With `--nmap-mode`; without a hosts file it scans the root domain dual-stack; resume is IPv4 only |
| `--nmap-no-service-detection` | Disable `-sV --version-light` | With `--nmap-mode` |
| `--nmap-max-rate N` | Nmap `--max-rate` | 1-1000 (default 100); split across concurrent host units |
| `--nmap-max-parallelism N` | Nmap `--max-parallelism` | 1-10 (default 2) |
| `--nmap-timeout SECONDS` | Nmap `--host-timeout` | 30-7200 (default 900) |
| `--nmap PATH` | Nmap executable | Default `tools\nmap\nmap.exe`, then PATH, then Program Files |
| `--database-discovery` / `--nmap-input FILE` | Offline database classification of an `nmap.json` | No network; cannot be combined with scan options |
| `--results DIR` | Results root | Default `results`; every run gets a new immutable folder |

### setup.ps1 switches

`-InstallDependencies`, `-InstallDevDependencies`, `-InstallPassiveTools` (Subfinder and DNSx), `-InstallTools` (Subfinder, DNSx, and HTTPX; then runs `main.py --check-httpx` locally), and `-InstallPublicSuffixList` (typed YES, then `main.py --update-psl --confirm-download`). Every switch asks for a typed `YES`.

**HTTPX blocker (checked 2026-11-12):** the newest published ProjectDiscovery HTTPX release is v1.12.0, and pinned target/IP input exists only on the dev branch. `-InstallTools` therefore refuses HTTPX, and HTTP probing stays disabled until a release of v1.13.0 or newer is published. A self-built binary may be supplied with `--httpx`, but it must pass `--check-httpx`.

**Deprecated engagement switch:** `operations.vulnerability_validation` is accepted only as `false` (older files) and reported as a deprecation; `true` is refused because DomainRecon performs no vulnerability validation or exploitation.

## Interface, navigation, and guided workflow

- **Dashboard:** version, engagement, target, scope status, short session ID, run ID, passive/active authorization state, last operation, findings by severity, HTTPX readiness, Public Suffix List status, tool status, and module readiness counts. No acknowledgement text, credential, or token is ever shown.
- **Menu groups:** ENGAGEMENT (15, 26, 9, 25), RECONNAISSANCE (1, 2, 10, 3, 16, 4, 5), INTELLIGENCE (17, 18, 6, 19, 20, 14, 21), ANALYSIS (22, 23, 13, 11), REPORTING (12, 24, 8), WORKFLOWS (27, 7), and 0 to exit. Every submenu has `[0] Back`; an unknown selection is rejected with a message and nothing runs. Ctrl+C returns to the main menu.
- **26 Scope Review & Target Check:** lists exclusions and authorized ranges, then reports `IN SCOPE` or `OUT OF SCOPE - scope violation` (with the reason) for any hostname or IP you enter. A blank answer goes back.
- **27 Guided Pilot Workflow:**
  1. Choose the engagement: keep the current one, load a file, or create one.
  2. Type `YES` to confirm the scope.
  3. Review the readiness table.
  4. Select stages, for example `1,2,6,7`.
  5. Execution. Each ACTIVE stage (HTTPX, TLS, Nmap) asks for `YES` and then its normal typed acknowledgement; declining skips it and sends nothing. Stages that are blocked by a missing tool or disabled by the engagement are skipped with the reason.
  6. Review correlated findings.
  7. Read the summary table and the report location.
- **Display modes:** styled on a terminal; plain when piped or with `DOMAINRECON_UI=plain`; `NO_COLOR=1`, `DOMAINRECON_UI=ascii`, and `DOMAINRECON_UI_WIDTH=<columns>` are honoured.
