"""Menu-driven orchestration for DomainRecon V2; scanner logic remains in its existing modules."""
from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from domainrecon import __version__
from domainrecon.active.httpx_probe import HTTPX_INSTALL_GUIDANCE, discover_httpx, export_live_inventory, probe_httpx
from domainrecon.analysis.database_discovery import load_and_analyze_nmap
from domainrecon.intelligence.asset_correlation import correlate_assets
from domainrecon.intelligence.attack_surface import build_attack_surface
from domainrecon.intelligence.change_detection import compare_runs
from domainrecon.intelligence.dns_intelligence import analyze_dns_artifacts, probe_wildcard_dns
from domainrecon.intelligence.http_intelligence import analyze_http_inventory
from domainrecon.intelligence.c2_intelligence import correlate_iocs, load_ioc_feed
from domainrecon.intelligence.correlation import FINDING_STAGES
from domainrecon.intelligence.delivery_intelligence import analyze_delivery_exposure
from domainrecon.intelligence.impact_analysis import analyze_impact
from domainrecon.intelligence.persistence_intelligence import analyze_persistence_evidence
from domainrecon.intelligence.vulnerability_assessment import assess_vulnerabilities
from domainrecon.intelligence.vulnerability_intel import analyze_vulnerabilities, load_nvd_feed
from domainrecon.reporting.unified_report import build_unified_report, write_report_artifacts
from domainrecon.platform_menu import PLATFORM_MENU, PlatformMenusMixin
from domainrecon.console_views import ConsoleViewsMixin
from domainrecon.ui import Console, detect_capabilities
from domainrecon.collectors.dnssec_probe import query_dnssec
from domainrecon.collectors.dns_intelligence import collect_dns, collect_dns_policy
from domainrecon.collectors.passive import collect_crtsh, collect_subfinder
from domainrecon.core.authorization import DENIED, GRANTED, METHOD_SESSION_PASSIVE, METHOD_TYPED_PHRASE, AuthorizationLedger
from domainrecon.core.errors import AuthorizationRequired, DomainReconError, ScopeViolation
from domainrecon.core.models import ActiveAuthorization
from domainrecon.core.scope import ScopePolicy
from domainrecon.core.storage import create_scan_directory, write_json_artifact, write_text_artifact
from domainrecon.scanners.nmap import (
    NmapScanOptions,
    TcpScanMode,
    discover_nmap,
    nmap_version,
    resume_nmap,
    run_nmap,
    run_nmap_hosts,
)

PASSIVE_ACK = "I AM AUTHORIZED"
HTTPX_ACK = "I AUTHORIZE ACTIVE PROBING"
NMAP_ACK = "I AUTHORIZE PORT SCANNING"
DNS_WILDCARD_ACK = "I AUTHORIZE DNS WILDCARD PROBING"
DEFAULT_SUBFINDER = Path("tools/subfinder/subfinder.exe")
DEFAULT_DNSX = Path("tools/dnsx/dnsx.exe")
DEFAULT_HTTPX = Path("tools/httpx/httpx.exe")
DEFAULT_NMAP = Path("tools/nmap/nmap.exe")
DEFAULT_RESULTS = Path("results")

# Displayed by menu option 11; each entry is backed by integrated, tested code paths.
KILL_CHAIN_STATUS: tuple[tuple[str, str], ...] = (
    ("01 Reconnaissance", "Implemented: passive discovery (Subfinder, crt.sh), DNSx with apex/_dmarc/DKIM policy records and opt-in DNSSEC indicators, HTTPX with IPv4/IPv6 pinned-IP gates, pinned TLS/certificate inspection, Nmap for the root domain or selected discovered hosts (IPv6 opt-in), database discovery, offline DNS/HTTP intelligence, technology fingerprinting, cloud attribution, takeover indicators, asset correlation, attack-surface graph, historical change detection."),
    ("02 Threat Intelligence", "Implemented: CPE 2.2/2.3 normalization with exact and NVD version-range matching against a user-provided local NVD JSON feed (API 2.0 or legacy 1.1); unprovable matches are labelled candidates; no feed download or exploit execution."),
    ("03 Delivery Exposure", "Implemented (offline): exposure classified only from HTTPX/Nmap evidence; MX/SPF/DMARC policy observations; externally observable misconfiguration rules plus authorized-tool evidence import; no delivery or email testing."),
    ("04 Vulnerability Assessment", "Implemented (offline): Stage 02 matches classified as confirmed, version-range, or possible matches with separate contextual risk; no scanning or exploitation."),
    ("05 Persistence Indicators", "Implemented (offline): imported Windows/Sysmon/Wazuh/Linux audit evidence and imported Active Directory assessment findings (PingCastle, Certipy, generic) mapped to ATT&CK; no endpoint access."),
    ("06 Command and Control Intelligence", "Implemented (offline): exact IOC correlation against a local JSON/CSV/STIX feed; DNS behavioral (tunneling) analysis is not supported without resolver telemetry."),
    ("07 Actions on Objectives", "Implemented (offline): owner-rated criticality/CIA impact estimates, risk correlation with theoretical attack-path hypotheses, ATT&CK mapping, findings lifecycle/retesting, and 20-section JSON/CSV/HTML reporting; no financial-loss estimation."),
)


class InteractiveApp(ConsoleViewsMixin, PlatformMenusMixin):
    """Stateful terminal UI over the existing DomainRecon V2 operations."""

    def __init__(
        self,
        *,
        input_fn: Callable[[str], str] | None = None,
        output_fn: Callable[[str], object] | None = None,
        results_root: Path = DEFAULT_RESULTS,
        subfinder: Path = DEFAULT_SUBFINDER,
        dnsx: Path = DEFAULT_DNSX,
        httpx: Path = DEFAULT_HTTPX,
        nmap: Path = DEFAULT_NMAP,
    ) -> None:
        capabilities = detect_capabilities(injected_output=output_fn is not None)
        # Injected output (tests, embedding) receives raw legacy lines; a real console goes through the UI layer.
        self.ui = Console((lambda line: self.output(line)) if output_fn is not None else print, **capabilities)
        self.output = output_fn or self.ui.emit
        self.input = input_fn or (lambda prompt: (self.ui.stop_task(), input(self.ui.prompt(prompt)))[1])
        self.last_operation: dict | None = None
        self._httpx_inspection: dict | None = None
        self._httpx_ready = False
        self._banner_shown = False
        self.results_root = results_root
        self.subfinder = subfinder
        self.dnsx = dnsx
        self.httpx = httpx
        if httpx == DEFAULT_HTTPX and not httpx.is_file():
            selected = discover_httpx(None)["selected"]  # local candidates only; version query, no network
            if selected:
                self.httpx = Path(selected)
        self.nmap = nmap
        self.scope: ScopePolicy | None = None
        self.passive_authorized = False
        self.passive_records: list[dict] | None = None
        self.passive_payload: dict | None = None
        self.source_stats: dict | None = None
        self.passive_session_directory: Path | None = None
        self.dns_records: list[dict] | None = None
        self.dns_session_directory: Path | None = None
        self.dns_policy_records: list[dict] | None = None
        self.httpx_records: list[dict] | None = None
        self.nmap_records: dict | None = None
        self.last_nmap_artifact: Path | None = None
        self.database_inventory: dict | None = None
        self._intelligence_payloads: dict[str, dict] = {}
        self.session_directory: Path | None = None
        self._operation_counts: dict[str, int] = {}
        self._health: dict[str, str] | None = None
        self._nmap_executable: Path | None = None
        self.authorization = AuthorizationLedger()
        self.engagement = None
        self.dns_dnssec: dict | None = None

    def run(self) -> int:
        self._show_dashboard()
        if not self._choose_initial_target():
            self.output("No target selected. Exiting DomainRecon V2.")
            return 0
        while True:
            try:
                self._show_dashboard()
                self._show_main_menu()
                choice = self.input("Select an option: ").strip()
                if choice == "0":
                    self.output("DomainRecon V2 session ended.")
                    return 0
                if choice == "1":
                    self._passive_menu()
                elif choice == "2":
                    self._run_dns()
                elif choice == "3":
                    self._run_httpx()
                elif choice == "4":
                    self._nmap_menu()
                elif choice == "5":
                    self._run_database_discovery()
                elif choice == "6":
                    self._run_vulnerability_intelligence()
                elif choice == "7":
                    self._run_full_workflow()
                elif choice == "8":
                    self._view_previous_results()
                elif choice == "9":
                    self._change_target()
                elif choice == "10":
                    self._intelligence_menu()
                elif choice == "11":
                    self._show_kill_chain_status()
                elif choice == "12":
                    self._run_unified_report()
                elif choice == "13":
                    self._run_historical_changes()
                elif choice == "14":
                    self._defensive_menu()
                elif choice == "26":
                    self._scope_review()
                elif choice == "27":
                    self._guided_workflow()
                elif choice in {number for number, _label, _method in PLATFORM_MENU}:
                    getattr(self, next(method for number, _label, method in PLATFORM_MENU if number == choice))()
                else:
                    self.output("Invalid selection. Choose one of the numbered options shown (0 exits).")
            except EOFError:
                self.output("Input stream closed. DomainRecon V2 session ended.")
                return 0
            except KeyboardInterrupt:
                self.ui.stop_task()
                self.output("\nCancelled. Returning to the main menu; no additional stage was started.")
                self._note_operation("operation", "cancelled by operator (Ctrl+C)")
                if self.scope is None:
                    self.output("DomainRecon V2 session ended.")
                    return 0
            except subprocess.SubprocessError as exc:
                self.ui.stop_task()
                self.output(f"External tool did not complete ({type(exc).__name__}): {exc}. No result was recorded as successful.")
                self._note_operation("operation", "error", str(exc)[:120])
            except (OSError, RuntimeError, ValueError, KeyError, TypeError, DomainReconError) as exc:
                self.ui.stop_task()
                self.output(f"Operation could not be completed: {exc}")
                self._note_operation("operation", "error", str(exc)[:120])

    def _dependency_status(self) -> dict[str, str]:
        if self._health is None:
            nmap_path = discover_nmap(self.nmap)
            self._nmap_executable = nmap_path  # cached with the health status; refreshed when it is
            nmap_status = nmap_version(self.nmap) if nmap_path else "not installed"
            if nmap_path and not nmap_status.casefold().startswith(("failed", "unavailable", "not installed")):
                nmap_status = f"{nmap_status} ({nmap_path})"
            self._health = {
                "Subfinder": f"available: {self.subfinder}" if self.subfinder.is_file() else f"not installed: {self.subfinder}",
                "crt.sh": "available via HTTPS (internet access required)",
                "DNSx": f"available: {self.dnsx}" if self.dnsx.is_file() else f"not installed: {self.dnsx}",
                "HTTPX": f"available: {self.httpx} (pinned-IP check required)" if self.httpx.is_file() else f"not installed: {self.httpx}",
                "Nmap": nmap_status,
            }
        return self._health

    def _available_nmap(self) -> Path | None:
        status = self._dependency_status()["Nmap"].casefold()
        executable = self._nmap_executable
        if executable is None or status.startswith(("failed", "unavailable", "not installed")):
            return None
        return executable

    def _choose_initial_target(self) -> bool:
        while self.scope is None:
            try:
                value = self.input("Enter Target Domain (blank to exit): ").strip()
            except (EOFError, KeyboardInterrupt):
                return False
            if not value:
                return False
            try:
                self._set_target(value)
            except ScopeViolation as exc:
                self.output(f"Invalid target domain: {exc}")
        return True

    def _set_target(self, value: str) -> None:
        self.scope = ScopePolicy(value)
        self.passive_authorized = False
        self.passive_records = None
        self.passive_payload = None
        self.source_stats = None
        self.passive_session_directory = None
        self.dns_records = None
        self.dns_session_directory = None
        self.dns_policy_records = None
        self.httpx_records = None
        self.nmap_records = None
        self.last_nmap_artifact = None
        self.database_inventory = None
        self._intelligence_payloads = {}
        self.session_directory = None
        self._operation_counts = {}
        self.authorization.reset_pending()
        self.last_operation = None
        self.engagement = None
        self.dns_dnssec = None

    def _change_target(self) -> None:
        while True:
            value = self.input("Enter new Target Domain (blank to cancel): ").strip()
            if not value:
                self.output("Target unchanged.")
                return
            try:
                self._set_target(value)
                self.output(f"Target changed to {self.scope.root_domain}; session results and authorization state were reset.")
                return
            except ScopeViolation as exc:
                self.output(f"Invalid target domain: {exc}")

    def _record_authorization(
        self, operation: str, result: str, *, method: str = METHOD_TYPED_PHRASE,
        acknowledgement_id: str | None = None, details: dict | None = None,
    ) -> None:
        """Persist an authorization decision before any network operation starts."""
        assert self.scope is not None
        run_directory = self._ensure_session_directory() if result == GRANTED else self.session_directory
        record = self.authorization.record(
            target=self.scope.root_domain, operation=operation, method=method, result=result,
            run_directory=run_directory, acknowledgement_id=acknowledgement_id, details=details,
        )
        if self.engagement is not None:
            from domainrecon.core.engagement import operation_history
            operation_history(self.results_root, self.engagement).append({"event": "authorization", "operation": operation, "result": result, "record_id": record["record_id"], "run_id": record["run_id"], "session_id": record["session_id"]})

    def _request_phrase(self, operation: str, prompt: str, expected: str, acknowledgement_id: str, details: dict | None = None) -> str | None:
        """Ask for one operation-specific phrase; return it only when it matches exactly."""
        if self._engagement_blocks(operation, details):
            return None
        self._show_preflight(operation, details)
        phrase = self.input(prompt)
        granted = phrase == expected
        self._record_authorization(operation, GRANTED if granted else DENIED, acknowledgement_id=acknowledgement_id, details=details)
        if not granted:
            self._note_operation(operation, "not authorized", "acknowledgement did not match; nothing was started")
        return phrase if granted else None

    def _engagement_blocks(self, operation: str, details: dict | None = None) -> bool:
        """Engagement files can only disable operations; a disabled operation is refused and recorded."""
        if self.engagement is None:
            return False
        allowed, reason = self.engagement.operation_allowed(operation)
        if allowed:
            return False
        self.output(f"Operation refused: {reason}. Update the engagement configuration if this operation is authorized.")
        self._record_authorization(operation, DENIED, details={**(details or {}), "engagement_block": reason})
        return True

    def _ensure_passive_authorization(self, operation: str = "passive_enumeration") -> bool:
        if self._engagement_blocks(operation):
            return False
        if self.passive_authorized:
            self._record_authorization(operation, GRANTED, method=METHOD_SESSION_PASSIVE, acknowledgement_id="PASSIVE_ACK")
            return True
        if self._request_phrase(operation, f'Type exactly "{PASSIVE_ACK}" to authorize passive collection: ', PASSIVE_ACK, "PASSIVE_ACK") is None:
            self.output("Passive collection not authorized; no source was queried.")
            return False
        self.passive_authorized = True
        return True

    def _passive_stage_is_current_success(self) -> bool:
        return (
            self.passive_payload is not None
            and self.passive_payload.get("status") == "success"
            and self.passive_records is not None
            and self.source_stats is not None
            and self.session_directory is not None
            and self.passive_session_directory == self.session_directory
        )

    def _dns_stage_is_current(self) -> bool:
        return (
            self._passive_stage_is_current_success()
            and self.dns_records is not None
            and self.dns_session_directory == self.session_directory
        )

    def _ensure_session_directory(self) -> Path:
        assert self.scope is not None
        if self.session_directory is None:
            self.session_directory = create_scan_directory(self.results_root, self.scope.root_domain)
            write_json_artifact(self.session_directory, "interactive_session.json", {
                "schema_version": 1,
                "application": "DomainRecon V2",
                "version": __version__,
                "root_domain": self.scope.root_domain,
                "session_id": self.authorization.session_id,
                "started_at_utc": datetime.now(timezone.utc).isoformat(),
            })
            self.authorization.attach(self.session_directory)
        return self.session_directory

    def _operation_directory(self, stage: str) -> Path:
        run_directory = self._ensure_session_directory()
        count = self._operation_counts.get(stage, 0) + 1
        self._operation_counts[stage] = count
        directory = run_directory / f"{stage}-{count:02d}"
        directory.mkdir(parents=False, exist_ok=False)
        return directory

    def _passive_menu(self) -> None:
        assert self.scope is not None
        subfinder_available = self.subfinder.is_file()
        self.output("\nPASSIVE SUBDOMAIN ENUMERATION")
        self.output(f"[1] Subfinder - {'available' if subfinder_available else 'unavailable: binary missing'}")
        self.output("[2] crt.sh - available (requires internet access)")
        self.output(f"[3] Both - {'available' if subfinder_available else 'unavailable: Subfinder binary missing'}")
        self.output("[0] Back")
        choice = self.input("Select a source: ").strip()
        if choice == "0":
            return
        if choice == "1":
            if not subfinder_available:
                self.output("Subfinder is not installed; this source was not started.")
                return
            selected = ["subfinder"]
        elif choice == "2":
            selected = ["crt.sh"]
        elif choice == "3":
            if not subfinder_available:
                self.output("Both sources cannot be selected because Subfinder is not installed.")
                return
            selected = ["subfinder", "crt.sh"]
        else:
            self.output("Invalid source selection. Returning to the main menu.")
            return
        if self._ensure_passive_authorization():
            self._run_passive(selected)

    def _run_passive(self, selected_sources: list[str]) -> None:
        assert self.scope is not None
        self.passive_records = None
        self.passive_payload = None
        self.source_stats = None
        self.passive_session_directory = None
        self.dns_records = None
        self.dns_session_directory = None
        self.dns_policy_records = None
        self.httpx_records = None
        self.output("\n[passive] Collecting selected source(s); results are filtered to the validated target scope.")
        started = time.perf_counter()
        source_stats: dict[str, dict] = {}
        names_by_source: dict[str, list[str]] = {}
        for source in selected_sources:
            source_started = time.perf_counter()
            self.ui.start_task(f"Querying passive source {source}")
            try:
                if source == "subfinder":
                    names, error = collect_subfinder(self.subfinder, self.scope)
                else:
                    names, error = collect_crtsh(self.scope)
            except (OSError, RuntimeError, ValueError) as exc:
                names, error = [], str(exc)
            names = self.scope.filter_hostnames(names)
            names_by_source[source] = names
            source_stats[source] = {
                "status": "failed" if error else "success",
                "discovered_count": len(names),
                "elapsed_seconds": round(time.perf_counter() - source_started, 6),
                "error": error,
            }
            self.output(f"  {source}: {len(names)} names; {'error: ' + error if error else 'complete'}")
        sources_by_host: dict[str, set[str]] = {}
        for source, names in names_by_source.items():
            source_label = "crtsh" if source == "crt.sh" else source
            for hostname in names:
                sources_by_host.setdefault(hostname, set()).add(source_label)
        records = [{"hostname": host, "sources": sorted(sources)} for host, sources in sorted(sources_by_host.items())]
        errors = [str(source_stats[source]["error"]) for source in selected_sources if source_stats[source]["error"]]
        payload = {
            "root_domain": self.scope.root_domain,
            "status": "failed" if errors and len(errors) == len(selected_sources) else "success",
            "errors": errors,
            "records": records,
        }
        stats = {
            "elapsed_seconds": round(time.perf_counter() - started, 6),
            "unique_subdomains": len(records),
            "sources": source_stats,
        }
        self.passive_records = records
        self.passive_payload = payload
        self.source_stats = stats
        self.dns_records = None
        self.httpx_records = None
        operation_dir = self._operation_directory("passive")
        write_json_artifact(operation_dir, "passive.json", payload)
        write_json_artifact(operation_dir, "enumeration_summary.json", {
            "schema_version": 1,
            "root_domain": self.scope.root_domain,
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "elapsed_seconds": stats["elapsed_seconds"],
            "passive": {"status": payload["status"], **stats},
            "dns": {"requested": False, "input_source": None, "status": "not_requested", "elapsed_seconds": 0.0, "resolved": [], "unresolved": [], "failed": []},
        })
        from domainrecon.cli import _subdomain_exports
        csv_text, text = _subdomain_exports(records, [], dns_requested=False)
        write_text_artifact(operation_dir, "subdomains.csv", csv_text)
        write_text_artifact(operation_dir, "subdomains.txt", text)
        self.passive_session_directory = self.session_directory
        self.output(f"Passive results saved to: {operation_dir}")
        self._view_assets(records)
        self._note_operation("passive enumeration", payload["status"], str(operation_dir))
        self.output(f"Unique in-scope subdomains: {len(records)}")
        if payload["status"] == "failed":
            self.output("Passive collection failed: all selected sources returned errors; DNS and HTTPX are blocked until a successful retry.")
        elif not records:
            self.output("Passive collection completed successfully with zero in-scope subdomains.")

    def _run_dns(self) -> None:
        assert self.scope is not None
        if self.passive_payload is None:
            self.output("DNS skipped: no passive collection result exists in this session. Run Passive Subdomain Enumeration first.")
            return
        if self.passive_payload.get("status") != "success":
            self.output("DNS skipped: passive collection failed; retry enumeration before DNS resolution.")
            return
        if not self._passive_stage_is_current_success():
            self.output("DNS skipped: successful passive results are not complete for the current session.")
            return
        if not self.dnsx.is_file():
            self.output("DNS Resolution is unavailable because DNSx is not installed.")
            return
        if not self._ensure_passive_authorization("dns_resolution"):
            return
        self.output("\n[dns] Resolving session-discovered hostnames with DNSx.")
        self.dns_records = None
        self.dns_session_directory = None
        self.dns_policy_records = None
        self.httpx_records = None
        started = time.perf_counter()
        self.ui.start_task(f"Resolving {len(self.passive_records)} hostname(s) and policy records with DNSx")
        records = collect_dns(self.dnsx, self.scope, [item["hostname"] for item in self.passive_records])
        # Apex and _dmarc.<apex> policy records (TXT/MX/CAA) for email/CA intelligence; stored separately.
        policy_records = collect_dns_policy(self.dnsx, self.scope, self.engagement.dkim_selectors if self.engagement else ())
        self.dns_dnssec = None
        if self.engagement is not None and self.engagement.dns_resolvers and self._ensure_passive_authorization("dns_dnssec_query"):
            self.dns_dnssec = query_dnssec(self.scope, self.engagement.dns_resolvers[0])
        elapsed = round(time.perf_counter() - started, 6)
        self.dns_records = records
        self.dns_policy_records = policy_records
        self.httpx_records = None
        operation_dir = self._operation_directory("dns")
        write_json_artifact(operation_dir, "dns.json", {"root_domain": self.scope.root_domain, "records": records})
        write_json_artifact(operation_dir, "dns_policy.json", {"root_domain": self.scope.root_domain, "records": policy_records, "dnssec": self.dns_dnssec})
        from domainrecon.cli import _dns_summary, _subdomain_exports
        dns_summary = _dns_summary(records, requested=True, input_source="passive_results", elapsed_seconds=elapsed)
        write_json_artifact(operation_dir, "enumeration_summary.json", {
            "schema_version": 1,
            "root_domain": self.scope.root_domain,
            "elapsed_seconds": elapsed,
            "passive": {"status": self.passive_payload["status"], "unique_subdomains": len(self.passive_records), "sources": self.source_stats["sources"]},
            "dns": dns_summary,
        })
        csv_text, text = _subdomain_exports(self.passive_records, records, dns_requested=True)
        write_text_artifact(operation_dir, "subdomains.csv", csv_text)
        write_text_artifact(operation_dir, "subdomains.txt", text)
        self.dns_session_directory = self.session_directory
        self.output(f"DNS results saved to: {operation_dir}")
        self._view_dns(records)
        self._note_operation("DNS resolution", "completed", str(operation_dir))
        self.output(f"Resolved: {len(dns_summary['resolved'])} | unresolved: {len(dns_summary['unresolved'])} | failed: {len(dns_summary['failed'])}")

    def _run_httpx(self) -> None:
        assert self.scope is not None
        if self.passive_payload is None:
            self.output("HTTPX blocked: passive enumeration has not completed in this session.")
            return
        if self.passive_payload.get("status") != "success":
            self.output("HTTPX blocked: passive collection failed; retry enumeration before probing.")
            return
        if not self._passive_stage_is_current_success():
            self.output("HTTPX blocked: successful passive results are not complete for the current session.")
            return
        if not self._dns_stage_is_current():
            self.output("HTTPX blocked: DNS results from the current successful passive session are required.")
            return
        if not self.httpx.is_file():
            self.output("HTTPX is unavailable because a compatible ProjectDiscovery binary is not installed.")
            self.output(HTTPX_INSTALL_GUIDANCE)
            return
        phrase = self._request_phrase(
            "httpx_active_probe", f'Type exactly "{HTTPX_ACK}" to authorize active HTTPX probing: ', HTTPX_ACK, "HTTPX_ACK",
            details={"eligible_passive_hosts": len(self.passive_records or [])},
        )
        if phrase is None:
            self.output("HTTPX probing not authorized; no HTTPX process was started.")
            return
        self.output("\n[httpx] Running the loopback pinning/Host/SNI capability gate, then probing only eligible session hosts.")
        authorization = ActiveAuthorization(self.scope.root_domain, True, phrase)
        try:
            self.ui.start_task("Running HTTPX against validated, pinned addresses")
            records = probe_httpx(self.httpx, self.scope, authorization, self.passive_records, self.dns_records, threads=int(self._limit("max_concurrency", 2)), rate_limit=int(self._limit("requests_per_second", 2)))
        except (OSError, RuntimeError) as exc:
            # Version or loopback pinning gate failed: fail closed, keep no partial HTTP state, probe nothing.
            self.output(f"HTTPX preflight failed safely; no target was probed: {exc}")
            self.output(HTTPX_INSTALL_GUIDANCE)
            return
        self.httpx_records = records
        operation_dir = self._operation_directory("httpx")
        status_counts: dict[str, int] = {}
        for record in records:
            classification = str(record.get("classification", "UNKNOWN"))
            status_counts[classification] = status_counts.get(classification, 0) + 1
        inventory = {"schema_version": 1, "root_domain": self.scope.root_domain, "status_counts": status_counts, "records": records}
        write_json_artifact(operation_dir, "live_web_inventory.json", inventory)
        csv_text, text = export_live_inventory(records)
        write_text_artifact(operation_dir, "live_web_inventory.csv", csv_text)
        write_text_artifact(operation_dir, "live_web_inventory.txt", text)
        self.output(f"HTTPX inventory saved to: {operation_dir}")
        self._view_http(records)
        self._note_operation("HTTPX probing", "completed", str(operation_dir))
        self._show_httpx_results(records)

    def _show_httpx_results(self, records: list[dict]) -> None:
        completed = [record for record in records if record.get("status") == "success" and record.get("status_code")]
        failed = [record for record in records if record not in completed]
        self.output("Responding web services:")
        if not completed:
            self.output("  None")
        for record in completed:
            self.output(
                f"  {record.get('classification')} {record.get('url')} | HTTP {record.get('status_code')}"
                f" | title={record.get('title') or '-'} | time={record.get('response_time') or '-'}"
            )
        self.output("Failed, unreachable, or ineligible hosts:")
        if not failed:
            self.output("  None")
        for record in failed:
            self.output(f"  {record.get('hostname', '-')} | {record.get('classification', record.get('status', 'unknown'))} | {record.get('error') or record.get('status') or 'no response'}")

    def _nmap_menu(self) -> None:
        assert self.scope is not None
        executable = self._available_nmap()
        if executable is None:
            self.output("Nmap Port Scanning is unavailable because Nmap is not installed.")
            return
        self.output("\nNMAP PORT SCANNING")
        self.output("[1] Common TCP ports (top 100)")
        self.output("[2] Full TCP ports (1-65535)")
        self.output("[3] Custom TCP ports")
        self.output("[4] Resume Previous Scan")
        hosts_note = "available" if self._nmap_candidate_hostnames() else "unavailable: current-session DNS results required"
        self.output(f"[5] Discovered in-scope hosts from current-session DNS (IPv4, optional IPv6) - {hosts_note}")
        self.output("[6] Root domain, dual-stack (IPv4 + public IPv6 answers, separate -6 invocation)")
        self.output("[0] Back")
        choice = self.input("Select an Nmap operation: ").strip()
        if choice == "0":
            return
        if choice == "4":
            self._resume_nmap(executable)
            return
        if choice == "5":
            self._nmap_discovered_hosts()
            return
        if choice == "6":
            options = self._select_port_options()
            if options is None:
                self.output("Nmap dual-stack scan cancelled; nothing was started.")
                return
            self._launch_host_scan([self.scope.root_domain], options, per_hostname=False, ipv6=True, operation="nmap_tcp_scan")
            return
        if choice == "1":
            options = NmapScanOptions(TcpScanMode.COMMON)
        elif choice == "2":
            options = NmapScanOptions(TcpScanMode.FULL)
        elif choice == "3":
            while True:
                ports = self.input("Custom TCP ports (for example 443,8000-8010; 0 to back): ").strip()
                if ports == "0":
                    return
                options = NmapScanOptions(TcpScanMode.CUSTOM, ports=ports)
                try:
                    options.validate()
                    break
                except ValueError as exc:
                    self.output(f"Invalid port selection: {exc}")
        else:
            self.output("Invalid Nmap selection. Returning to the main menu.")
            return
        self._run_nmap(options)

    def _nmap_candidate_hostnames(self) -> list[str]:
        """Hostnames DNSx resolved successfully in this session; nothing outside scope is added."""
        if self.scope is None or not self._dns_stage_is_current():
            return []
        names = {
            row["hostname"] for row in self.dns_records or []
            if isinstance(row, dict) and isinstance(row.get("hostname"), str) and str(row.get("status")) == "success"
            and self.scope.permits_hostname(row["hostname"])
        }
        return sorted(names)

    def _select_port_options(self) -> NmapScanOptions | None:
        self.output("[1] Common TCP ports (top 100)  [2] Full TCP ports (1-65535)  [3] Custom TCP ports  [0] Back")
        choice = self.input("Port selection: ").strip()
        if choice == "1":
            return NmapScanOptions(TcpScanMode.COMMON)
        if choice == "2":
            return NmapScanOptions(TcpScanMode.FULL)
        if choice == "3":
            ports = self.input("Custom TCP ports (for example 443,8000-8010; 0 to back): ").strip()
            if ports == "0":
                return None
            options = NmapScanOptions(TcpScanMode.CUSTOM, ports=ports)
            try:
                options.validate()
            except ValueError as exc:
                self.output(f"Invalid port selection: {exc}")
                return None
            return options
        return None

    def _nmap_discovered_hosts(self) -> None:
        assert self.scope is not None
        hostnames = self._nmap_candidate_hostnames()
        if not hostnames:
            self.output("Discovered-host scanning requires successful DNS results from the current passive session; no scan was started.")
            return
        self.output(f"{len(hostnames)} in-scope hostname(s) resolved in this session. Only these explicitly listed names can be scanned:")
        for name in hostnames[:50]:
            self.output(f"  {name}")
        if len(hostnames) > 50:
            self.output(f"  ... and {len(hostnames) - 50} more")
        options = self._select_port_options()
        if options is None:
            self.output("Nmap host scan cancelled; nothing was started.")
            return
        grouping = self.input("[1] Scan each unique IP once (recommended)  [2] Scan each hostname separately (may repeat IPs)  [3] Unique IPs, IPv4 + IPv6  [4] Per hostname, IPv4 + IPv6: ").strip()
        if grouping not in {"1", "2", "3", "4"}:
            self.output("Invalid grouping selection; nothing was started.")
            return
        self._launch_host_scan(hostnames, options, per_hostname=grouping in {"2", "4"}, ipv6=grouping in {"3", "4"}, operation="nmap_host_scan")

    def _launch_host_scan(self, hostnames: list[str], options: NmapScanOptions, *, per_hostname: bool, ipv6: bool, operation: str) -> None:
        """Authorize and run a pinned multi-host scan; IPv6 targets are scanned only when explicitly selected."""
        assert self.scope is not None
        family = "IPv4 + IPv6" if ipv6 else "IPv4"
        phrase = self._request_phrase(
            operation, f'Type exactly "{NMAP_ACK}" to authorize {family} TCP scanning of {len(hostnames)} hostname(s): ', NMAP_ACK, "NMAP_ACK",
            details={"mode": str(options.mode), "ports": options.ports, "hostnames": hostnames, "per_hostname": per_hostname, "ipv6": ipv6},
        )
        if phrase is None:
            self.output("Nmap not authorized; no Nmap scan was started.")
            return
        operation_dir = self._operation_directory("nmap")
        self.output(f"\n[nmap] Scanning {len(hostnames)} hostname(s) with pinned, revalidated public {family} targets.")
        try:
            result = run_nmap_hosts(
                self.nmap, self.scope, hostnames, options, operation_dir, active_acknowledgement=phrase,
                per_hostname=per_hostname, progress=lambda stage: self.output(f"  Nmap unit: {stage}"), max_concurrency=max(1, int(self._limit("max_concurrency", 2))), ipv6=ipv6,
            )
        except (AuthorizationRequired, ScopeViolation, OSError, ValueError) as exc:
            self.output(f"Nmap host scan blocked or failed: {exc}")
            return
        self._store_nmap_result(operation_dir, result)
        for rejected in result.get("rejected_hostnames", []):
            self.output(f"  skipped {rejected.get('hostname')}: {rejected.get('reason')}")

    def _store_nmap_result(self, operation_dir: Path, result: dict) -> None:
        self.nmap_records = result
        write_json_artifact(operation_dir, "nmap.json", result)
        if result.get("status") in {"success", "partial"} and result.get("hosts") is not None:
            self.last_nmap_artifact = operation_dir / "nmap.json"
        self.output(f"Nmap result: {result.get('status', 'unknown')} | saved to: {operation_dir}")
        self._view_services(result)
        self._note_operation("Nmap scan", str(result.get('status', 'unknown')), str(operation_dir))
        if result.get("status") not in {"success", "partial"} and result.get("error"):
            self.output(f"  {result['error']}")
        for host in result.get("hosts", []):
            open_ports = [port for port in host.get("ports", []) if port.get("state") == "open"]
            names = f" ({', '.join(host.get('hostnames', []))})" if host.get("hostnames") else ""
            self.output(f"  {host.get('address')}{names}: {len(open_ports)} open TCP port(s)")

    def _run_nmap(self, options: NmapScanOptions) -> None:
        assert self.scope is not None
        phrase = self._request_phrase(
            "nmap_tcp_scan", f'Type exactly "{NMAP_ACK}" to authorize this TCP scan: ', NMAP_ACK, "NMAP_ACK",
            details={"mode": str(options.mode), "ports": options.ports, "scan_scope": "root_domain"},
        )
        if phrase is None:
            self.output("Nmap not authorized; no Nmap scan was started.")
            return
        operation_dir = self._operation_directory("nmap")
        self.output(f"\n[nmap] Starting explicitly selected {options.mode.value} TCP scan for {self.scope.root_domain}.")
        try:
            result = run_nmap(
                self.nmap,
                self.scope,
                self.scope.root_domain,
                options,
                operation_dir,
                active_acknowledgement=phrase,
                progress=lambda stage: self.output(f"  Nmap stage: {stage}"),
            )
        except (AuthorizationRequired, ScopeViolation, OSError, ValueError) as exc:
            self.output(f"Nmap scan blocked or failed: {exc}")
            return
        self._store_nmap_result(operation_dir, result)

    def _resume_nmap(self, executable: Path) -> None:
        assert self.scope is not None
        phrase = self._request_phrase("nmap_resume", f'Type exactly "{NMAP_ACK}" to authorize resuming a scan: ', NMAP_ACK, "NMAP_ACK")
        if phrase is None:
            self.output("Nmap resume not authorized; no subprocess was started.")
            return
        candidates = self._resume_candidates()
        if not candidates:
            self.output("No prior .nmap or .gnmap resume files were found under this target's V2 results folder.")
            return
        self.output("Available resume files:")
        for index, path in enumerate(candidates, 1):
            self.output(f"[{index}] {path}")
        choice = self.input("Select a resume file (0 to cancel): ").strip()
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(candidates):
            self.output("Invalid resume-file selection.")
            return
        resume_file = candidates[int(choice) - 1]
        operation_dir = self._operation_directory("nmap-resume")
        try:
            result = resume_nmap(
                executable,
                resume_file,
                scope=self.scope,
                target=self.scope.root_domain,
                active_acknowledgement=phrase,
                evidence_directory=operation_dir,
            )
        except subprocess.SubprocessError as exc:
            result = {"schema_version": 1, "scanner": "nmap", "target": self.scope.root_domain, "status": "failed", "resume_file": str(resume_file), "error": f"Nmap resume subprocess error: {exc}"}
        except (AuthorizationRequired, ScopeViolation, OSError, ValueError, RuntimeError) as exc:
            self.output(f"Nmap resume blocked or failed: {exc}")
            return
        write_json_artifact(operation_dir, "nmap_resume.json", result)
        self.output(f"Resume result: {result.get('status', 'unknown')} | saved to: {operation_dir}")
        if result.get("error"):
            self.output(f"  {result['error']}")
        if result.get("status") == "success":
            # A resumed scan is only usable downstream once its XML parsed successfully.
            write_json_artifact(operation_dir, "nmap.json", {key: value for key, value in result.items() if key != "error"})
            self.nmap_records = result
            self.last_nmap_artifact = operation_dir / "nmap.json"

    def _resume_candidates(self) -> list[Path]:
        assert self.scope is not None
        domain_directory = self.results_root / self.scope.root_domain
        if not domain_directory.is_dir():
            return []
        root = domain_directory.resolve()
        candidates: list[Path] = []
        for path in domain_directory.rglob("*"):
            if path.is_file() and path.suffix in {".nmap", ".gnmap"}:
                resolved = path.resolve()
                if resolved.is_relative_to(root):
                    candidates.append(resolved)
        return sorted(candidates, key=lambda path: str(path), reverse=True)

    def _run_database_discovery(self) -> None:
        assert self.scope is not None
        if not self.last_nmap_artifact or not self.last_nmap_artifact.is_file():
            self.output("Database Service Discovery is unavailable until this session has a successful Nmap result.")
            return
        operation_dir = self._operation_directory("database")
        inventory = load_and_analyze_nmap(self.last_nmap_artifact, self.scope)
        self.database_inventory = inventory
        write_json_artifact(operation_dir, "database_inventory.json", inventory)
        self.output(f"Offline database inventory saved to: {operation_dir}")
        self.output(f"Identified services: {len(inventory['inventory'])} | ambiguous candidates: {len(inventory['candidates'])}")

    def _intelligence_menu(self) -> None:
        self.output("\nSTAGE 01 - OFFLINE INTELLIGENCE")
        self.output("[1] DNS Intelligence (requires current passive + DNS results)")
        self.output("[2] Controlled Wildcard DNS Probe (explicit opt-in; two random in-scope labels)")
        self.output("[3] Unified Asset Inventory")
        self.output("[4] Attack Surface Map")
        self.output("[5] HTTP Intelligence (stored HTTPX result only)")
        self.output("[6] Historical Change Detection")
        self.output("[7] Generate Unified Report")
        self.output("[0] Back")
        choice = self.input("Select an offline analysis: ").strip()
        actions = {
            "1": self._run_dns_intelligence,
            "2": self._run_wildcard_dns,
            "3": self._run_asset_inventory,
            "4": self._run_attack_surface,
            "5": self._run_http_intelligence,
            "6": self._run_historical_changes,
            "7": self._run_unified_report,
        }
        if choice == "0":
            return
        action = actions.get(choice)
        if action is None:
            self.output("Invalid intelligence selection.")
            return
        action()

    def _show_kill_chain_status(self) -> None:
        self.output("\nCYBER KILL CHAIN IMPLEMENTATION STATUS")
        httpx_note = "" if self.httpx.is_file() else " HTTPX is unavailable in this installation (binary missing)."
        for stage, status in KILL_CHAIN_STATUS:
            suffix = httpx_note if stage.startswith("01") else ""
            self.output(f"Stage {stage}: {status}{suffix}")
        self.output("Stages 03-07 are offline analyzers over stored or imported evidence; none performs scanning, exploitation, or endpoint access.")

    # ------------------------------------------------------------------ Stages 03-07 (offline)

    def _defensive_prerequisites(self) -> dict[str, str | None]:
        """Return None when a stage can run, otherwise the reason it is unavailable."""
        has_recon = self._dns_stage_is_current() or self.httpx_records is not None or (self.nmap_records or {}).get("status") in {"success", "partial"}
        vuln = self._intelligence_payloads.get("vulnerability")
        has_findings = any(key in self._intelligence_payloads for key in FINDING_STAGES)
        return {
            "delivery": None if has_recon else "current-session DNS, HTTPX, or Nmap evidence required",
            "vulnerability_assessment": None if isinstance(vuln, dict) and vuln.get("status") == "success" else "run Stage 02 with a local NVD feed first",
            "persistence": None,
            "c2": None if has_recon or "asset_inventory" in self._intelligence_payloads else "asset inventory, DNS, or HTTPX evidence required",
            "impact": None if has_findings else "run at least one findings-producing stage first (DNS/HTTP intelligence, certificates, takeover, misconfiguration, Stages 02-06, or AD imports)",
        }

    def _defensive_menu(self) -> None:
        assert self.scope is not None
        reasons = self._defensive_prerequisites()
        entries = (
            ("1", "delivery", "Stage 03 Delivery & Exposure Intelligence", self._run_delivery_intelligence),
            ("2", "vulnerability_assessment", "Stage 04 Safe Vulnerability Assessment", self._run_vulnerability_assessment),
            ("3", "persistence", "Stage 05 Persistence Evidence Import (local Windows/Sysmon/Wazuh/Linux audit export)", self._run_persistence_import),
            ("4", "c2", "Stage 06 IOC / C2 Correlation (local JSON/CSV/STIX feed)", self._run_c2_correlation),
            ("5", "impact", "Stage 07 Impact Analysis (optional owner criticality file)", self._run_impact_analysis),
        )
        self.output("\nSTAGES 03-07 - OFFLINE DEFENSIVE ANALYSIS (no network activity)")
        for number, key, label, _action in entries:
            self.output(f"[{number}] {label} - {'available' if reasons[key] is None else 'unavailable: ' + str(reasons[key])}")
        self.output("[0] Back")
        choice = self.input("Select an offline analysis: ").strip()
        if choice == "0":
            return
        selected = next((entry for entry in entries if entry[0] == choice), None)
        if selected is None:
            self.output("Invalid selection.")
            return
        if reasons[selected[1]] is not None:
            self.output(f"{selected[2]} is unavailable: {reasons[selected[1]]}. Nothing was run.")
            return
        selected[3]()

    def _local_file(self, prompt: str, *, required: bool = True, max_bytes: int = 50_000_000) -> Path | None | bool:
        """Ask for a local file path. Returns a Path, None for an allowed blank answer, or False on error."""
        raw = self.input(prompt).strip().strip('"')
        if not raw:
            if required:
                self.output("A local file path is required; nothing was run.")
                return False
            return None
        path = Path(raw)
        if not path.is_file():
            self.output("Local file not found; nothing was run and no network request was attempted.")
            return False
        if path.stat().st_size > max_bytes:
            self.output(f"Local file exceeds the {max_bytes} byte limit; nothing was run.")
            return False
        return path

    def _current_http_payload(self) -> dict | None:
        assert self.scope is not None
        return {"root_domain": self.scope.root_domain, "records": self.httpx_records} if self.httpx_records is not None else None

    def _run_delivery_intelligence(self) -> None:
        assert self.scope is not None
        nmap = self.nmap_records if (self.nmap_records or {}).get("status") in {"success", "partial"} else None
        payload = analyze_delivery_exposure(
            self.scope, dns=self._dns_payload_with_policy() if self._dns_stage_is_current() else None,
            http=self._current_http_payload(), nmap=nmap, database=self.database_inventory,
            asset_inventory=self._intelligence_payloads.get("asset_inventory"),
        )
        inputs = [name for name, value in (("dns", self._dns_stage_is_current()), ("http", self.httpx_records is not None), ("nmap", nmap is not None), ("database", self.database_inventory is not None)) if value]
        operation_dir = self._save_intelligence_payload("delivery", "delivery_intelligence.json", payload, inputs=inputs)
        email = ", ".join(f"{row['policy']}={row['classification']}" for row in payload["email_observations"])
        self.output(f"Stage 03 delivery/exposure intelligence saved to {operation_dir}; {len(payload['exposures'])} exposure record(s), {len(payload['findings'])} finding(s). Email policy: {email}.")
        self._view_findings(payload["findings"], "DELIVERY / EXPOSURE FINDINGS")

    def _run_vulnerability_assessment(self) -> None:
        assert self.scope is not None
        public_assets: set[str] = set()
        delivery = self._intelligence_payloads.get("delivery")
        for row in (delivery or {}).get("exposures", []):
            if isinstance(row, dict) and any(str(c).startswith(("PUBLIC_", "DATABASE_")) for c in row.get("categories", [])):
                public_assets.add(str(row.get("asset")))
                public_assets.update(str(ev.get("ip")) for ev in row.get("evidence", []) if isinstance(ev, dict) and ev.get("ip"))
        for host in (self.nmap_records or {}).get("hosts", []) if isinstance(self.nmap_records, dict) else []:
            if isinstance(host, dict) and isinstance(host.get("address"), str):
                public_assets.add(host["address"])  # Nmap targets are validated public addresses
        payload = assess_vulnerabilities(self._intelligence_payloads.get("vulnerability"), self.database_inventory, public_assets=public_assets)
        operation_dir = self._save_intelligence_payload("vulnerability_assessment", "vulnerability_assessment.json", payload, inputs=["vulnerability"] + (["delivery"] if delivery else []))
        counts: dict[str, int] = {}
        for row in payload["findings"]:
            counts[row["classification"]] = counts.get(row["classification"], 0) + 1
        self.output(f"Stage 04 assessment saved to {operation_dir}; classifications: {counts}. These are applicability assessments, not exploitability confirmation.")
        self._view_vulnerabilities(payload["findings"])

    def _run_persistence_import(self) -> None:
        path = self._local_file("Local evidence export path (.json, .jsonl, .ndjson, or .csv; max 10 MB): ", max_bytes=10_000_000)
        if not isinstance(path, Path):
            return
        label = self.input("Evidence source label (for example 'WS01 Security log export 2026-11-12'): ").strip()
        if not label:
            self.output("An evidence source label is required for provenance; nothing was run.")
            return
        payload = analyze_persistence_evidence(path, source_label=label)
        operation_dir = self._save_intelligence_payload("persistence", "persistence_evidence.json", payload, inputs=[f"imported:{path.name}"])
        self.output(f"Stage 05 persistence evidence saved to {operation_dir}; {payload['events_reviewed']} event(s) reviewed, {len(payload['findings'])} indicator(s), {payload['invalid_records']} invalid record(s) isolated.")
        self._view_findings(payload["findings"], "PERSISTENCE INDICATORS (imported evidence)")

    def _run_c2_correlation(self) -> None:
        assert self.scope is not None
        path = self._local_file("Local IOC feed path (JSON, CSV, or STIX 2.x bundle; max 25 MB): ", max_bytes=25_000_000)
        if not isinstance(path, Path):
            return
        feed = load_ioc_feed(path)
        payload = correlate_iocs(
            feed, assets=self._intelligence_payloads.get("asset_inventory"),
            dns={"records": self.dns_records} if self._dns_stage_is_current() else None, http=self._current_http_payload(),
        )
        operation_dir = self._save_intelligence_payload("c2", "c2_intelligence.json", payload, inputs=[f"feed:{path.name}"])
        self.output(f"Stage 06 IOC correlation saved to {operation_dir}; {payload['indicators_loaded']} indicator(s) loaded, {len(payload['matches'])} exact match(es), {len(payload['feed_errors'])} feed error(s). Matches are leads, not proof of compromise.")
        self._view_findings(payload["matches"], "IOC MATCHES (leads, not proof of compromise)")

    def _run_impact_analysis(self) -> None:
        assert self.scope is not None
        path = self._local_file("Owner asset-criticality JSON path (blank = no owner ratings; impact will be 'not_assessed'): ", required=False, max_bytes=5_000_000)
        if path is False:
            return
        config = None
        if isinstance(path, Path):
            try:
                config = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                self.output(f"Criticality file could not be read as JSON ({exc}); nothing was run.")
                return
        base = {key: value for key, value in self._stage_artifacts().items() if key in {"passive", "dns", "http", "nmap", "database"}}
        stages = {key: self._intelligence_payloads[key] for key in FINDING_STAGES if key in self._intelligence_payloads}
        run_dir = self._ensure_session_directory()
        payload = analyze_impact({**base, **stages}, config, run_id=run_dir.name)
        operation_dir = self._save_intelligence_payload("impact", "impact_analysis.json", payload, inputs=sorted(stages))
        summary = payload["executive_summary"]
        self.output(f"Stage 07 impact analysis saved to {operation_dir}; {summary['observed_findings']} finding(s), {summary['estimated_impact_findings']} with owner-based estimates, {summary['unknown_criticality']} with unknown criticality.")

    def _stage_artifacts(self) -> dict[str, dict]:
        assert self.scope is not None
        artifacts: dict[str, dict] = {}
        if self.passive_payload is not None and self._passive_stage_is_current_success():
            artifacts["passive"] = self.passive_payload
        if self.dns_records is not None and self._dns_stage_is_current():
            dns_status = "success"
            statuses = [str(row.get("status", "")) for row in self.dns_records if isinstance(row, dict)]
            if statuses and all(value in {"failed", "timeout"} for value in statuses):
                dns_status = "failed"
            elif any(value in {"failed", "timeout"} for value in statuses):
                dns_status = "partial"
            artifacts["dns"] = {"root_domain": self.scope.root_domain, "status": dns_status, "records": self.dns_records}
        if self.httpx_records is not None and self.session_directory is not None:
            failed = any(isinstance(row, dict) and str(row.get("status", "")) in {"failed", "timeout", "blocked"} for row in self.httpx_records)
            artifacts["http"] = {"root_domain": self.scope.root_domain, "status": "partial" if failed else "success", "records": self.httpx_records}
        if self.nmap_records is not None and self.session_directory is not None:
            artifacts["nmap"] = self.nmap_records
        if self.database_inventory is not None:
            artifacts["database"] = self.database_inventory
        artifacts.update(self._intelligence_payloads)
        if self.engagement is not None:
            artifacts["engagement"] = {**self.engagement.to_dict(), "status": "success", "root_domain": self.scope.root_domain}
        return artifacts

    def _save_intelligence_payload(self, stage: str, filename: str, payload: dict, *, inputs: list[str] | None = None) -> Path:
        assert self.scope is not None
        envelope = dict(payload)
        if inputs is not None:
            envelope.setdefault("input_stages", list(inputs))
        envelope.setdefault("project_version", __version__)
        envelope.setdefault("target", self.scope.root_domain)
        envelope.setdefault("run_id", self.session_directory.name if self.session_directory else "pending")
        envelope.setdefault("stage", stage)
        envelope.setdefault("module", stage)
        envelope.setdefault("timestamp", envelope.get("generated_at", datetime.now(timezone.utc).isoformat()))
        envelope.setdefault("status", "success")
        envelope.setdefault("source", "offline_analysis_of_stored_v2_artifacts")
        envelope.setdefault("findings", [])
        if "evidence" not in envelope:
            evidence_rows: list[dict] = []
            for row in envelope.get("hosts", []) if isinstance(envelope.get("hosts"), list) else []:
                if isinstance(row, dict) and isinstance(row.get("evidence"), list):
                    evidence_rows.extend(item for item in row["evidence"] if isinstance(item, dict))
            envelope["evidence"] = evidence_rows
        operation_dir = self._operation_directory(stage)
        # Provenance: every derived artifact records the run-relative path it was saved under.
        envelope["artifact_path"] = f"{operation_dir.name}/{filename}"
        write_json_artifact(operation_dir, filename, envelope)
        self._intelligence_payloads[stage] = envelope
        self._note_operation(stage, str(envelope.get("status", "success")), envelope["artifact_path"])
        return operation_dir

    def _dns_payload_with_policy(self) -> dict:
        """Current DNS rows plus apex/_dmarc policy rows not already observed (offline analyzers only)."""
        assert self.scope is not None
        rows = list(self.dns_records or [])
        present = {row.get("hostname") for row in rows if isinstance(row, dict)}
        for row in self.dns_policy_records or []:
            if isinstance(row, dict) and row.get("hostname") not in present:
                rows.append(row)
        status = "success"
        statuses = [str(row.get("status", "")) for row in rows if isinstance(row, dict)]
        if statuses and all(value in {"failed", "timeout"} for value in statuses):
            status = "failed"
        elif any(value in {"failed", "timeout"} for value in statuses):
            status = "partial"
        return {"root_domain": self.scope.root_domain, "status": status, "records": rows}

    def _run_dns_intelligence(self) -> None:
        assert self.scope is not None
        if not self._passive_stage_is_current_success():
            self.output("DNS Intelligence blocked: a successful passive result from the current session is required.")
            return
        if not self._dns_stage_is_current():
            self.output("DNS Intelligence blocked: DNS results from the same successful passive session are required.")
            return
        payload = analyze_dns_artifacts(
            self.passive_payload,
            self._dns_payload_with_policy(),
            self.scope,
            wildcard_probe=self._intelligence_payloads.get("wildcard_probe"),
            dnssec=self.dns_dnssec,
        )
        operation_dir = self._save_intelligence_payload("dns_intelligence", "dns_intelligence.json", payload)
        counts: dict[str, int] = {}
        for row in payload["hosts"]:
            counts[row["category"]] = counts.get(row["category"], 0) + 1
        self.output(f"DNS Intelligence saved to {operation_dir}; host categories: {counts or 'no discovered hosts'}")

    def _run_wildcard_dns(self) -> None:
        assert self.scope is not None
        if not self._passive_stage_is_current_success():
            self.output("Wildcard DNS probe blocked: successful passive collection for the current session is required.")
            return
        if not self.dnsx.is_file():
            self.output("Wildcard DNS probe unavailable: DNSx is not installed.")
            return
        phrase = self._request_phrase(
            "dns_wildcard_probe", f'Type exactly "{DNS_WILDCARD_ACK}" to query two random in-scope DNS labels: ', DNS_WILDCARD_ACK, "DNS_WILDCARD_ACK",
            details={"random_labels": 2},
        )
        if phrase is None:
            self.output("Wildcard DNS probe not authorized; DNSx was not started.")
            return
        result = probe_wildcard_dns(self.dnsx, self.scope, count=2)
        result["root_domain"] = self.scope.root_domain
        operation_dir = self._save_intelligence_payload("wildcard_probe", "wildcard_probe.json", result)
        self.output(f"Wildcard DNS evidence saved to {operation_dir}; rerun DNS Intelligence to compare it with discovered names.")

    def _run_asset_inventory(self) -> None:
        assert self.scope is not None
        artifacts = self._stage_artifacts()
        if not artifacts:
            self.output("Asset correlation unavailable: run or load at least one authorized reconnaissance stage first.")
            return
        previous_inventory = None
        domain_directory = self.results_root / self.scope.root_domain
        if domain_directory.is_dir():
            root = domain_directory.resolve()
            prior_runs = sorted(
                (path for path in domain_directory.iterdir() if path.is_dir() and path.resolve().is_relative_to(root) and path != self.session_directory),
                key=lambda path: path.name, reverse=True,
            )
            for prior_run in prior_runs:
                matches = sorted(prior_run.rglob("asset_inventory.json"), key=lambda path: str(path), reverse=True)
                for path in matches:
                    if not path.resolve().is_relative_to(prior_run.resolve()):
                        continue
                    try:
                        candidate = json.loads(path.read_text(encoding="utf-8"))
                    except (OSError, UnicodeError, json.JSONDecodeError):
                        continue
                    if isinstance(candidate, dict) and candidate.get("root_domain", candidate.get("target")) == self.scope.root_domain:
                        previous_inventory = candidate
                        break
                if previous_inventory is not None:
                    break
        payload = correlate_assets(
            self.scope, passive=artifacts.get("passive"), dns=artifacts.get("dns"),
            http=artifacts.get("http"), nmap=artifacts.get("nmap"), database=artifacts.get("database"),
            previous_inventory=previous_inventory,
        )
        operation_dir = self._save_intelligence_payload("asset_inventory", "asset_inventory.json", payload)
        self.output(f"Unified asset inventory saved to {operation_dir}; {len(payload['assets'])} distinct host/infrastructure assets.")

    def _run_attack_surface(self) -> None:
        assert self.scope is not None
        artifacts = self._stage_artifacts()
        if not artifacts:
            self.output("Attack Surface Mapping unavailable: no stored stage artifacts are available in this session.")
            return
        findings = [
            finding
            for payload in self._intelligence_payloads.values()
            for finding in payload.get("findings", []) if isinstance(finding, dict)
        ]
        payload = build_attack_surface(
            self.scope, passive=artifacts.get("passive"), dns=artifacts.get("dns"),
            http=artifacts.get("http"), nmap=artifacts.get("nmap"), database=artifacts.get("database"),
            assets=artifacts.get("asset_inventory"), findings=findings,
        )
        operation_dir = self._save_intelligence_payload("attack_surface", "attack_surface.json", payload)
        self.output(f"Offline attack-surface graph saved to {operation_dir}; {len(payload['nodes'])} nodes, {len(payload['relations'])} relations.")

    def _run_http_intelligence(self) -> None:
        assert self.scope is not None
        if self.httpx_records is None or self.session_directory is None:
            self.output("HTTP Intelligence unavailable: a stored HTTPX inventory from this session is required; no request was made.")
            return
        payload = analyze_http_inventory({"root_domain": self.scope.root_domain, "records": self.httpx_records})
        operation_dir = self._save_intelligence_payload("http_intelligence", "http_intelligence.json", payload)
        self.output(f"Offline HTTP Intelligence saved to {operation_dir}; {len(payload['observations'])} observations, {len(payload['findings'])} evidence-backed findings.")
        if any(row.get("response_headers_status") == "not_collected" for row in payload["observations"]):
            self.output("Note: the installed HTTPX output did not provide response headers; they are marked not_collected, not absent.")

    def _run_vulnerability_intelligence(self) -> None:
        assert self.scope is not None
        if not self.last_nmap_artifact or not self.last_nmap_artifact.is_file():
            self.output("Threat Intelligence requires successful, authorized Nmap/service evidence; no scan was started.")
            return
        try:
            nmap_payload = json.loads(self.last_nmap_artifact.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            self.output(f"Threat Intelligence blocked: successful Nmap artifact could not be read ({exc}).")
            return
        if (
            not isinstance(nmap_payload, dict)
            or nmap_payload.get("status") not in {"success", "partial"}
            or nmap_payload.get("scanner") != "nmap"
            or nmap_payload.get("target") != self.scope.root_domain
        ):
            self.output("Threat Intelligence blocked: saved Nmap artifact is not a successful supported result for the current target.")
            return
        feed_path = self.input("Local NVD-format JSON cache/feed path (blank for offline/no-feed report): ").strip()
        feed = None
        if feed_path:
            path = Path(feed_path)
            if not path.is_file():
                self.output("Local feed not found; no network request was attempted.")
                return
            feed = load_nvd_feed(path)
        payload = analyze_vulnerabilities(nmap_payload, feed)
        operation_dir = self._save_intelligence_payload("vulnerability", "vulnerability_intelligence.json", payload)
        self.output(f"Defensive CVE intelligence saved to {operation_dir}; {len(payload['findings'])} exact-CPE matches.")
        self.output("Matches are candidate intelligence, not confirmed exploitability; no exploit was downloaded or run.")
        self._view_vulnerabilities(payload["findings"])

    def _run_unified_report(self) -> None:
        assert self.scope is not None
        artifacts = self._stage_artifacts()
        run_dir = self._ensure_session_directory()
        report = build_unified_report(self.scope, artifacts, run_id=run_dir.name, timeline=self.authorization.history)
        operation_dir = self._operation_directory("report")
        paths = write_report_artifacts(operation_dir, report)
        self._intelligence_payloads["unified_report"] = report
        self.output(f"Partial unified report generated from available artifacts ({report['status']}):")
        self._note_operation("unified report", str(report["status"]), str(operation_dir))
        for kind, path in paths.items():
            self.output(f"  {kind.upper()}: {path}")

    def _load_saved_run_artifacts(self, run_directory: Path) -> dict[str, dict]:
        assert self.scope is not None
        root = run_directory.resolve()
        filenames = {
            "passive.json": "passive", "dns.json": "dns", "live_web_inventory.json": "http",
            "nmap.json": "nmap", "database_inventory.json": "database",
            "dns_intelligence.json": "dns_intelligence", "asset_inventory.json": "asset_inventory",
            "attack_surface.json": "attack_surface", "vulnerability_intelligence.json": "vulnerability",
        }
        found: dict[str, dict] = {}
        for path in sorted(run_directory.rglob("*.json"), key=lambda item: str(item)):
            resolved = path.resolve()
            if path.name == "enumeration_summary.json" and resolved.is_relative_to(root):
                try:
                    summary = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, UnicodeError, json.JSONDecodeError):
                    continue
                sources = summary.get("passive", {}).get("sources") if isinstance(summary, dict) and isinstance(summary.get("passive"), dict) else None
                if isinstance(sources, dict) and summary.get("root_domain", self.scope.root_domain) == self.scope.root_domain:
                    found["passive_sources"] = sources
                continue
            if not resolved.is_relative_to(root) or path.name not in filenames:
                continue
            key = filenames[path.name]
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict):
                continue
            target = payload.get("root_domain", payload.get("target", self.scope.root_domain))
            if target != self.scope.root_domain:
                continue
            if key in {"dns", "http"}:
                records = payload.get("records", [])
                records = records if isinstance(records, list) else []
                statuses = [str(row.get("status", "success")) for row in records if isinstance(row, dict)]
                errors = {"failed", "timeout", "blocked"} & set(statuses)
                payload["status"] = "failed" if records and len(errors) == len(set(statuses)) else "partial" if errors else "success"
            found[key] = payload
        return found

    def _run_historical_changes(self) -> None:
        assert self.scope is not None
        domain_directory = self.results_root / self.scope.root_domain
        if not domain_directory.is_dir():
            self.output("Historical comparison unavailable: no saved V2 runs exist for this target.")
            return
        root = domain_directory.resolve()
        runs = sorted(
            (path for path in domain_directory.iterdir() if path.is_dir() and path.resolve().is_relative_to(root) and path != self.session_directory),
            key=lambda path: path.name, reverse=True,
        )
        if not runs:
            self.output("Historical comparison unavailable: there is no previous run for this target.")
            return
        self.output("Previous V2 runs:")
        for index, path in enumerate(runs, 1):
            self.output(f"[{index}] {path.name}")
        selection = self.input("Select previous run (0 to cancel): ").strip()
        if selection == "0":
            return
        if not selection.isdigit() or not 1 <= int(selection) <= len(runs):
            self.output("Invalid previous-run selection.")
            return
        previous_dir = runs[int(selection) - 1]
        previous_artifacts = self._load_saved_run_artifacts(previous_dir)
        current_artifacts = self._stage_artifacts()
        previous = {"root_domain": self.scope.root_domain, "run_id": previous_dir.name, **previous_artifacts}
        current_id = self.session_directory.name if self.session_directory else "current-session"
        current = {"root_domain": self.scope.root_domain, "run_id": current_id, **current_artifacts}
        if self.source_stats is not None and "passive" in current_artifacts:
            current["passive_sources"] = self.source_stats.get("sources")
        payload = compare_runs(previous, current)
        operation_dir = self._save_intelligence_payload("changes", "change_report.json", payload)
        self.output(f"Historical comparison saved to {operation_dir}; {len(payload['changes'])} confirmed changes, {len(payload['unknown_comparisons'])} stages unknown/unavailable.")

    def _run_full_workflow(self) -> None:
        assert self.scope is not None
        if not self.dnsx.is_file():
            self.output("Full workflow unavailable: DNSx is not installed.")
            return
        if not self._ensure_passive_authorization():
            return
        sources = (["subfinder"] if self.subfinder.is_file() else []) + ["crt.sh"]
        self.output("\n[FULL] Passive collection and DNS are the only automatic stages in this workflow.")
        self._run_passive(sources)
        if self.passive_payload is None or self.passive_payload.get("status") != "success" or not self._passive_stage_is_current_success():
            self.output("[FULL] Passive collection failed or did not complete; DNS, HTTPX, and Nmap stages were skipped.")
            return
        self._run_dns()
        if self.httpx.is_file() and self._dns_stage_is_current():
            answer = self.input("Run active HTTPX now? Type YES to continue to its separate authorization prompt: ").strip()
            if answer == "YES":
                self._run_httpx()
        else:
            self.output("HTTPX stage unavailable or prerequisites missing; skipped without probing.")
        executable = self._available_nmap()
        if executable:
            answer = self.input("Run active Nmap now? Type YES to select a scan mode and authorize it separately: ").strip()
            if answer == "YES":
                self.output("Select Nmap mode for the explicitly requested full workflow:")
                self.output("[1] Common TCP ports  [2] Full TCP ports  [3] Custom ports  [0] Skip")
                choice = self.input("Nmap mode: ").strip()
                if choice == "1":
                    self._run_nmap(NmapScanOptions(TcpScanMode.COMMON))
                elif choice == "2":
                    self._run_nmap(NmapScanOptions(TcpScanMode.FULL))
                elif choice == "3":
                    ports = self.input("Custom TCP ports (0 to skip): ").strip()
                    if ports == "0":
                        self.output("Nmap skipped.")
                    else:
                        options = NmapScanOptions(TcpScanMode.CUSTOM, ports=ports)
                        try:
                            options.validate()
                            self._run_nmap(options)
                        except ValueError as exc:
                            self.output(f"Invalid custom ports; Nmap skipped: {exc}")
                else:
                    self.output("Nmap skipped.")
        else:
            self.output("Nmap is not installed; active Nmap stage skipped.")
        if self.last_nmap_artifact is not None:
            answer = self.input("Run offline Database Service Discovery on the successful Nmap artifact? [y/N]: ").strip().lower()
            if answer == "y":
                self._run_database_discovery()
        self._run_offline_pipeline()

    def _view_previous_results(self) -> None:
        assert self.scope is not None
        domain_directory = self.results_root / self.scope.root_domain
        if not domain_directory.is_dir():
            self.output(f"No saved results for {self.scope.root_domain}.")
            return
        root = domain_directory.resolve()
        directories = sorted(
            (item for item in domain_directory.iterdir() if item.is_dir() and item.resolve().is_relative_to(root)),
            key=lambda item: item.name,
            reverse=True,
        )
        if not directories:
            self.output(f"No saved results for {self.scope.root_domain}.")
            return
        self.output(f"Saved runs for {self.scope.root_domain}:")
        for index, directory in enumerate(directories, 1):
            self.output(f"[{index}] {directory.name}{' (current session)' if directory == self.session_directory else ''}")
        choice = self.input("Select a run to inspect (0 to back): ").strip()
        if choice == "0":
            return
        if not choice.isdigit() or not 1 <= int(choice) <= len(directories):
            self.output("Invalid saved-run selection.")
            return
        selected = directories[int(choice) - 1]
        selected_root = selected.resolve()
        files = sorted(
            path for path in selected.rglob("*")
            if path.is_file() and path.resolve().is_relative_to(selected_root)
        )
        if not files:
            self.output("The selected run contains no artifacts.")
            return
        self.output(f"Artifacts in {selected}:")
        for index, path in enumerate(files, 1):
            self.output(f"[{index}] {path.relative_to(selected)}")
        file_choice = self.input("Select a text artifact to view (0 to back): ").strip()
        if file_choice == "0":
            return
        if not file_choice.isdigit() or not 1 <= int(file_choice) <= len(files):
            self.output("Invalid artifact selection.")
            return
        artifact = files[int(file_choice) - 1]
        try:
            content = artifact.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            self.output(f"Could not read this artifact as UTF-8 text: {exc}")
            return
        max_chars = 16000
        self.output(f"\n--- {artifact.relative_to(selected)} ---")
        self.output(content[:max_chars] + ("\n[output truncated]" if len(content) > max_chars else ""))
        self.output("--- end artifact ---")


def run_interactive(**kwargs: object) -> int:
    """Launch the interactive application; keyword injection is used by tests."""
    return InteractiveApp(**kwargs).run()  # type: ignore[arg-type]
