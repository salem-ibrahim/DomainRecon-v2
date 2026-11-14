"""Interactive menus for the platform modules (engagement, TLS, technology, cloud, misconfiguration,
takeover, AD imports, correlation, ATT&CK, findings lifecycle, session/artifacts).

Mixed into ``InteractiveApp``; every handler checks prerequisites, validates scope, enforces
authorization for network actions, saves an enveloped immutable artifact, and registers it in the
session so the unified report picks it up.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domainrecon.active.httpx_probe import check_httpx_ready
from domainrecon.collectors.tls_probe import TLS_ACK, probe_tls
from domainrecon.core.authorization import GRANTED
from domainrecon.core.engagement import PROFILES, build_engagement, load_engagement, operation_history
from domainrecon.core.errors import DomainReconError
from domainrecon.core.storage import write_json_artifact
from domainrecon.intelligence.ad_assessment import import_ad_findings
from domainrecon.intelligence.certificate_intelligence import analyze_certificates
from domainrecon.intelligence.cloud_intelligence import load_asn_map, load_provider_ranges, range_file_digest, analyze_cloud
from domainrecon.intelligence.correlation import correlate
from domainrecon.intelligence.dns_intelligence import analyze_dns_artifacts
from domainrecon.intelligence.findings_lifecycle import RETEST_RESULTS, STATUSES, FindingsRegistry
from domainrecon.intelligence.http_intelligence import analyze_http_inventory
from domainrecon.intelligence.misconfiguration import assess_misconfigurations, import_assessment_evidence
from domainrecon.intelligence.mitre_mapping import build_attack_matrix
from domainrecon.intelligence.takeover_intelligence import analyze_takeover
from domainrecon.intelligence.technology_fingerprint import fingerprint_technologies

_TLS_PORT_HINTS = {443, 8443, 465, 993, 995, 636, 990, 5986, 9443}

# (main-menu number, label) for the platform modules; numbers 1-14 keep their legacy meaning.
PLATFORM_MENU: tuple[tuple[str, str, str], ...] = (
    ("15", "Engagement Management (scope, exclusions, operations, limits, history)", "_engagement_menu"),
    ("16", "TLS & Certificate Intelligence", "_tls_menu"),
    ("17", "Technology Fingerprinting", "_run_technology"),
    ("18", "Cloud Infrastructure Intelligence", "_run_cloud"),
    ("19", "Security Misconfiguration Assessment", "_run_misconfiguration"),
    ("20", "Subdomain Takeover Intelligence", "_takeover_menu"),
    ("21", "Active Directory Assessment Imports", "_run_ad_import"),
    ("22", "Attack Path & Risk Correlation", "_run_correlation"),
    ("23", "MITRE ATT&CK Mapping", "_run_mitre"),
    ("24", "Findings Lifecycle & Retesting", "_findings_menu"),
    ("25", "Session & Artifact Management", "_session_menu"),
)


class PlatformMenusMixin:
    def _platform_availability(self, number: str) -> str:
        """Availability label shown next to each platform menu entry (no entry is decorative)."""
        dns_current = self._dns_stage_is_current()
        has_http = self.httpx_records is not None
        has_nmap = (self.nmap_records or {}).get("status") in {"success", "partial"}
        has_findings = any(isinstance(p, dict) and p.get("findings") for p in self._intelligence_payloads.values())
        needs = {
            "16": None if dns_current or has_http else "needs current-session DNS (active) or stored HTTPX TLS data (offline)",
            "17": None if has_http or has_nmap or self.database_inventory else "needs HTTPX, Nmap, or database evidence",
            "18": None if dns_current or "dns_intelligence" in self._intelligence_payloads or has_http else "needs DNS or HTTPX evidence",
            "19": None if has_http or has_nmap else "needs HTTPX/Nmap evidence, or an evidence file to import",
            "20": None if dns_current or "dns_intelligence" in self._intelligence_payloads else "needs current-session DNS results",
            "22": None if has_findings else "needs at least one stage with findings",
            "23": None if has_findings else "needs findings (run analyses or correlation first)",
            "24": None if "correlation" in self._intelligence_payloads or FindingsRegistry(self.results_root, self.scope.root_domain).ledger.path.is_file() else "sync needs a correlation result; listing/export available once findings are tracked",
        }.get(number)
        return "available" if needs is None else needs

    # ------------------------------------------------------------------ helpers
    def _limit(self, name: str, default: float) -> float:
        engagement = getattr(self, "engagement", None)
        return min(default, engagement.limit(name)) if engagement else default

    def _ensure_dns_intelligence(self) -> dict | None:
        payload = self._intelligence_payloads.get("dns_intelligence")
        if payload is None and self._dns_stage_is_current():
            self._run_dns_intelligence()
            payload = self._intelligence_payloads.get("dns_intelligence")
        return payload

    def _ensure_http_intelligence(self) -> dict | None:
        payload = self._intelligence_payloads.get("http_intelligence")
        if payload is None and self.httpx_records is not None and self.session_directory is not None:
            self._run_http_intelligence()
            payload = self._intelligence_payloads.get("http_intelligence")
        return payload

    def _ask_path(self, prompt: str, *, required: bool, max_bytes: int) -> Path | None | bool:
        return self._local_file(prompt, required=required, max_bytes=max_bytes)

    # ------------------------------------------------------------------ 15 engagement
    def _engagement_menu(self) -> None:
        current = getattr(self, "engagement", None)
        self.output("\nENGAGEMENT MANAGEMENT (configuration only; never proof of authorization)")
        self.output(f"Current engagement: {current.name + ' [' + current.engagement_id + ']' if current else 'none (root-domain scope only)'}")
        self.output("[1] Load engagement file (.yaml/.yml subset or .json)")
        self.output("[2] Create engagement interactively")
        self.output("[3] Show engagement scope, operations and limits")
        self.output("[4] Show and verify immutable operation history")
        self.output("[0] Back")
        choice = self.input("Select an engagement action: ").strip()
        if choice == "1":
            path = self._ask_path("Engagement file path: ", required=True, max_bytes=262_144)
            if isinstance(path, Path):
                self._apply_engagement(load_engagement(path))
        elif choice == "2":
            self._create_engagement()
        elif choice == "3":
            self._show_engagement()
        elif choice == "4":
            self._show_operation_history()

    def _create_engagement(self) -> None:
        assert self.scope is not None
        name = self.input("Engagement name: ").strip()
        profile = (self.input(f"Testing profile {sorted(PROFILES)} [standard]: ").strip() or "standard").lower()
        excluded = [item.strip() for item in self.input("Excluded hostnames/IPs/CIDRs (comma-separated, blank for none): ").split(",") if item.strip()]
        ranges = [item.strip() for item in self.input("Authorized public IP ranges (comma-separated CIDRs, blank = any public IP of in-scope names): ").split(",") if item.strip()]
        port_scanning = self.input("Allow port scanning in this engagement? Type YES to enable: ").strip() == "YES"
        operations = dict(PROFILES.get(profile, PROFILES["standard"]))
        operations["port_scanning"] = port_scanning
        engagement = build_engagement({"engagement": {"name": name, "target": self.scope.root_domain, "profile": profile, "scope": {"domains": [self.scope.root_domain], "ip_ranges": ranges, "excluded_assets": excluded}, "operations": operations}})
        directory = self.results_root / engagement.target / "engagements" / engagement.engagement_id
        directory.mkdir(parents=True, exist_ok=True)
        write_json_artifact(directory, "engagement.json", engagement.to_dict())
        self._apply_engagement(engagement)

    def _apply_engagement(self, engagement: Any) -> None:
        if self.scope is not None and engagement.target != self.scope.root_domain:
            answer = self.input(f"Engagement target {engagement.target} differs from {self.scope.root_domain}. Type SWITCH to change target and reset the session: ").strip()
            if answer != "SWITCH":
                self.output("Engagement not applied; target unchanged.")
                return
        self._set_target(engagement.target)
        self.engagement = engagement
        self.scope = engagement.scope_policy()
        operation_history(self.results_root, engagement).append({"event": "engagement_applied", "engagement_id": engagement.engagement_id, "source": engagement.source, "source_sha256": engagement.sha256, "session_id": self.authorization.session_id})
        self.output(f"Engagement '{engagement.name}' applied ({engagement.engagement_id}); scope narrowed by {len(engagement.excluded_hostnames)} excluded hostname(s), {len(engagement.excluded_networks)} excluded network(s), {len(engagement.ip_ranges)} authorized IP range(s).")
        for note in engagement.deprecations:
            self.output(f"Deprecation: {note}")
        self._show_engagement()

    def _show_engagement(self) -> None:
        engagement = getattr(self, "engagement", None)
        if engagement is None:
            self.output("No engagement loaded; only root-domain ScopePolicy and per-operation acknowledgements apply.")
            return
        self.output(json.dumps(engagement.to_dict(), indent=2, sort_keys=True))

    def _show_operation_history(self) -> None:
        engagement = getattr(self, "engagement", None)
        if engagement is None:
            self.output("No engagement loaded; per-run authorization records are listed under Session & Artifact Management.")
            return
        ledger = operation_history(self.results_root, engagement)
        verification = ledger.verify()
        self.output(f"Operation history: {verification['entries']} entries; integrity {'VERIFIED' if verification['valid'] else 'FAILED: ' + verification.get('error', '')}")
        for entry in ledger.entries()[-20:]:
            self.output(f"  #{entry['sequence']} {entry['recorded_at_utc']} {entry.get('event')} {entry.get('operation', '')} {entry.get('result', '')}")

    # ------------------------------------------------------------------ 16 TLS
    def _tls_targets(self) -> list[dict[str, Any]]:
        targets: list[dict[str, Any]] = []
        for row in self.dns_records or []:
            if not isinstance(row, dict) or str(row.get("status")) != "success" or not self.scope.permits_hostname(str(row.get("hostname", ""))):
                continue
            records = row.get("records", {}) if isinstance(row.get("records"), dict) else {}
            for address in list(records.get("a", [])) + list(records.get("aaaa", [])):
                targets.append({"hostname": row["hostname"], "ip": address, "port": 443})
        nmap = self.nmap_records if isinstance(self.nmap_records, dict) else {}
        for host in nmap.get("hosts", []):
            for port in host.get("ports", []) if isinstance(host, dict) else []:
                if port.get("state") == "open" and (port.get("port") in _TLS_PORT_HINTS or "ssl" in str(port.get("service", "")) or "https" in str(port.get("service", ""))):
                    for name in host.get("hostnames") or [nmap.get("target")]:
                        targets.append({"hostname": name, "ip": host.get("address"), "port": port.get("port")})
        unique = {(t["hostname"], t["ip"], t["port"]): t for t in targets}
        return list(unique.values())

    def _tls_menu(self, preset: str | None = None) -> None:
        assert self.scope is not None
        stored = [row for row in self.httpx_records or [] if isinstance(row, dict) and isinstance(row.get("tls"), dict) and row["tls"].get("status") == "success"]
        targets = self._tls_targets() if self._dns_stage_is_current() else []
        self.output("\nTLS & CERTIFICATE INTELLIGENCE")
        self.output(f"[1] Analyze stored HTTPX certificate data (offline) - {'available' if stored else 'unavailable: no stored HTTPX TLS observations'}")
        self.output(f"[2] Inspect TLS endpoints (active, IP-pinned, {len(targets)} endpoint(s)) - {'available' if targets else 'unavailable: current-session DNS results required'}")
        self.output("[0] Back")
        choice = preset or self.input("Select a TLS action: ").strip()
        observations: list[dict[str, Any]] = [{"hostname": row.get("hostname"), "ip": row.get("ip"), "port": 443 if str(row.get("url", "")).startswith("https") else 80, "tls": row["tls"], "tls_version": row["tls"].get("version")} for row in stored]
        inputs = ["http"] if stored else []
        if choice == "2":
            if not targets:
                self.output("TLS inspection unavailable: no current-session DNS answers. Nothing was started.")
                return
            phrase = self._request_phrase("tls_certificate_probe", f'Type exactly "{TLS_ACK}" to perform pinned TLS handshakes with {len(targets)} endpoint(s): ', TLS_ACK, "TLS_ACK", details={"endpoint_count": len(targets)})
            if phrase is None:
                self.output("TLS inspection not authorized; no connection was made.")
                return
            probed = probe_tls(self.scope, targets, acknowledgement=phrase, requests_per_second=self._limit("requests_per_second", 2), progress=lambda line: self.output(f"  TLS: {line}"))
            observations += probed
            inputs.append("tls_probe")
            failures = [row for row in probed if row.get("status") != "success"]
            self.output(f"TLS handshakes: {len(probed) - len(failures)} succeeded, {len(failures)} failed or blocked.")
        elif choice != "1" or not stored:
            if choice not in {"0", ""}:
                self.output("Nothing was run.")
            return
        payload = analyze_certificates(observations)
        payload["root_domain"] = self.scope.root_domain
        payload["observations"] = [{k: v for k, v in row.items() if k != "chain_der_b64"} for row in observations]
        operation_dir = self._save_intelligence_payload("certificates", "certificate_intelligence.json", payload, inputs=inputs)
        self.output(f"Certificate intelligence saved to {operation_dir}; {len(payload['certificates'])} unique certificate(s), {len(payload['findings'])} finding(s).")
        self._view_certificates(payload)

    # ------------------------------------------------------------------ 17-21 analyzers
    def _run_technology(self) -> None:
        http = self._current_http_payload()
        nmap = self.nmap_records if (self.nmap_records or {}).get("status") in {"success", "partial"} else None
        if not (http or nmap or self.database_inventory):
            self.output("Technology fingerprinting requires stored HTTPX, Nmap, or database evidence from this session; nothing was run.")
            return
        payload = fingerprint_technologies(http=http, nmap=nmap, database=self.database_inventory, generated_at=datetime.now(timezone.utc).isoformat())
        payload["root_domain"] = self.scope.root_domain
        operation_dir = self._save_intelligence_payload("technology", "technology_inventory.json", payload, inputs=[n for n, v in (("http", http), ("nmap", nmap), ("database", self.database_inventory)) if v])
        self.output(f"Technology inventory saved to {operation_dir}; {len(payload['technologies'])} fingerprint(s) by category {payload['category_counts']}.")
        self._view_technologies(payload)

    def _run_cloud(self, interactive: bool = True) -> None:
        dns_intel = self._ensure_dns_intelligence()
        if dns_intel is None and self.httpx_records is None:
            self.output("Cloud intelligence requires DNS intelligence (current-session DNS) or HTTPX evidence; nothing was run.")
            return
        ranges: list[dict[str, str]] = []
        sources: list[str] = []
        raw = self.input("Optional published IP-range files (comma-separated paths; AWS/Azure/Google JSON, CSV, or plain CIDR list; blank for none): ").strip() if interactive else ""
        for item in [part.strip().strip('"') for part in raw.split(",") if part.strip()]:
            path = Path(item)
            if not path.is_file():
                self.output(f"Range file not found, skipped: {path.name}")
                continue
            provider = None
            if path.suffix.lower() not in {".json", ".csv"}:
                provider = self.input(f"Provider name for plain CIDR list {path.name}: ").strip() or None
            ranges += load_provider_ranges(path, provider)
            sources.append(f"{path.name} sha256={range_file_digest(path)}")
        asn_path = self._ask_path("Optional ASN map CSV (network,asn,organization; blank for none): ", required=False, max_bytes=50_000_000) if interactive else None
        if asn_path is False:
            return
        asn_map = load_asn_map(asn_path) if isinstance(asn_path, Path) else None
        payload = analyze_cloud(dns_intel, http=self._current_http_payload(), certificates=self._intelligence_payloads.get("certificates"), provider_ranges=ranges, asn_map=asn_map, range_sources=sources)
        payload["root_domain"] = self.scope.root_domain
        operation_dir = self._save_intelligence_payload("cloud", "cloud_intelligence.json", payload, inputs=["dns_intelligence"] + (["http"] if self.httpx_records else []) + sources)
        confirmed = sum(1 for row in payload["attributions"] if row["attribution"] == "confirmed_by_published_range")
        self.output(f"Cloud intelligence saved to {operation_dir}; {len(payload['attributions'])} attribution(s), {confirmed} confirmed by published ranges, the rest inferred.")
        self._view_cloud(payload)

    def _run_misconfiguration(self, interactive: bool = True) -> None:
        http_intel = self._ensure_http_intelligence()
        nmap = self.nmap_records if (self.nmap_records or {}).get("status") in {"success", "partial"} else None
        path = self._ask_path("Optional authorized-tool evidence to import (generic JSON/CSV, Nuclei JSONL, testssl.sh JSON; blank for none): ", required=False, max_bytes=20_000_000) if interactive else None
        if path is False:
            return
        imported: list[dict[str, Any]] = []
        import_meta = None
        if isinstance(path, Path):
            tool = self.input("Tool that produced this evidence (for provenance): ").strip() or "unspecified_tool"
            imported, import_meta = import_assessment_evidence(path, tool=tool)
        if not (http_intel or nmap or imported):
            self.output("Misconfiguration assessment requires HTTPX/HTTP intelligence, Nmap evidence, or an imported evidence file; nothing was run.")
            return
        payload = assess_misconfigurations(http_intelligence=http_intel, nmap=nmap, imported=imported, generated_at=datetime.now(timezone.utc).isoformat())
        payload["root_domain"] = self.scope.root_domain
        payload["import_provenance"] = import_meta
        operation_dir = self._save_intelligence_payload("misconfiguration", "misconfiguration_assessment.json", payload, inputs=[n for n, v in (("http_intelligence", http_intel), ("nmap", nmap), ("import", imported)) if v])
        self.output(f"Misconfiguration assessment saved to {operation_dir}; {len(payload['findings'])} finding(s) ({payload['imported_findings']} imported).")
        self._view_findings(payload["findings"], "SECURITY MISCONFIGURATION FINDINGS")

    def _takeover_menu(self) -> None:
        if self._ensure_dns_intelligence() is None:
            self.output("Takeover intelligence requires DNS intelligence from the current session (run Passive + DNS first); nothing was run.")
            return
        path = self._ask_path("Optional operator takeover-signature file (same JSON schema as domainrecon\\data\\takeover_signatures.json; blank = bundled only): ", required=False, max_bytes=2_000_000)
        if path is False:
            return
        self._run_takeover(path if isinstance(path, Path) else None)

    def _run_takeover(self, signatures_path: Path | None = None) -> None:
        dns_intel = self._ensure_dns_intelligence()
        if dns_intel is None:
            self.output("Takeover intelligence requires DNS intelligence from the current session (run Passive + DNS first); nothing was run.")
            return
        payload = analyze_takeover(dns_intel, self._current_http_payload(), root_domain=self.scope.root_domain, generated_at=datetime.now(timezone.utc).isoformat(), signatures_path=signatures_path)
        operation_dir = self._save_intelligence_payload("takeover", "takeover_intelligence.json", payload, inputs=["dns_intelligence"] + (["http"] if self.httpx_records else []))
        self.output(f"Takeover intelligence saved to {operation_dir}; classifications {payload['classification_counts']}. No resource was registered or claimed.")
        self._view_takeover(payload)

    def _run_ad_import(self) -> None:
        path = self._ask_path("AD assessment export (PingCastle .xml, Certipy find -json, or generic .json/.csv): ", required=True, max_bytes=50_000_000)
        if not isinstance(path, Path):
            return
        tool = self.input("Tool name (e.g. PingCastle, Certipy, BloodHound-derived CSV): ").strip() or "unspecified_tool"
        payload = import_ad_findings(path, tool=tool)
        payload["root_domain"] = self.scope.root_domain
        operation_dir = self._save_intelligence_payload("ad_assessment", "ad_assessment.json", payload, inputs=[f"imported:{path.name}"])
        self.output(f"AD assessment import saved to {operation_dir}; {len(payload['findings'])} finding(s) by category {payload['category_counts']}; {len(payload['errors'])} record error(s).")
        self._view_findings(payload["findings"], "ACTIVE DIRECTORY FINDINGS (imported)")

    # ------------------------------------------------------------------ 22-23 correlation / ATT&CK
    def _run_correlation(self) -> None:
        artifacts = self._stage_artifacts()
        if not any(isinstance(artifacts.get(stage), dict) and artifacts[stage].get("findings") for stage in artifacts):
            self.output("Correlation requires at least one stage with findings; nothing was run.")
            return
        payload = correlate(self.scope, artifacts, generated_at=datetime.now(timezone.utc).isoformat())
        operation_dir = self._save_intelligence_payload("correlation", "risk_correlation.json", payload, inputs=sorted(k for k, v in artifacts.items() if isinstance(v, dict) and v.get("findings")))
        self.output(f"Risk correlation saved to {operation_dir}; {len(payload['canonical_findings'])} canonical finding(s) ({payload['duplicates_merged']} duplicate(s) merged), priorities {payload['priority_counts']}, {len(payload['attack_paths'])} theoretical attack-path hypothesis(es).")
        self._view_correlation(payload)

    def _run_mitre(self) -> None:
        correlation = self._intelligence_payloads.get("correlation")
        findings = correlation.get("canonical_findings", []) if correlation else [f for p in self._stage_artifacts().values() if isinstance(p, dict) for f in p.get("findings", []) if isinstance(f, dict)]
        if not findings:
            self.output("ATT&CK mapping requires findings (run analyses or correlation first); nothing was run.")
            return
        payload = build_attack_matrix(findings)
        payload["root_domain"] = self.scope.root_domain
        operation_dir = self._save_intelligence_payload("mitre", "mitre_attack_matrix.json", payload, inputs=["correlation" if correlation else "stage_findings"])
        self.output(f"ATT&CK matrix saved to {operation_dir}; {payload['mapped_technique_count']} technique(s) across {len(payload['matrix'])} tactic(s); {payload['unmapped_findings']} finding(s) without a mapping.")
        self._view_attack_matrix(payload)
        for tactic, cells in payload["matrix"].items():
            self.output(f"  {tactic}: " + ", ".join(f"{tid} ({len(cell['finding_ids'])})" for tid, cell in cells.items()))

    # ------------------------------------------------------------------ 24 lifecycle
    def _findings_menu(self) -> None:
        registry = FindingsRegistry(self.results_root, self.scope.root_domain)
        state = registry.state()
        self.output(f"\nFINDINGS LIFECYCLE & RETESTING ({len(state)} tracked finding(s); ledger {'verified' if registry.ledger.verify()['valid'] else 'INTEGRITY FAILURE'})")
        self.output("[1] Sync correlated findings from this session")
        self.output("[2] List tracked findings")
        self.output("[3] Change a finding status")
        self.output("[4] Record a retest result")
        self.output("[5] Add a remediation note")
        self.output("[6] Export lifecycle snapshot (included in the report)")
        self.output("[0] Back")
        choice = self.input("Select a lifecycle action: ").strip()
        if choice == "1":
            correlation = self._intelligence_payloads.get("correlation")
            if not correlation:
                self.output("Run Attack Path & Risk Correlation first; findings are tracked by their canonical DRF- identifiers.")
                return
            counts = registry.sync(correlation["canonical_findings"], run_id=self._ensure_session_directory().name)
            self.output(f"Lifecycle sync: {counts}")
        elif choice == "2":
            for row in sorted(state.values(), key=lambda r: r["finding_id"]):
                self.output(f"  {row['finding_id']} [{row['status']}] {row.get('severity')} {row.get('asset_id')} - {row.get('title')} (first {row['first_detected'][:19]}, last {str(row['last_observed'])[:19]})")
            if not state:
                self.output("  No tracked findings.")
        elif choice == "3":
            fid = self.input("Finding ID (DRF-...): ").strip()
            status = self.input(f"New status {list(STATUSES)}: ").strip().upper()
            note = self.input("Reason / remediation note (required): ")
            registry.set_status(fid, status, note=note)
            self.output(f"{fid} -> {status} recorded.")
        elif choice == "4":
            fid = self.input("Finding ID (DRF-...): ").strip()
            result = self.input(f"Retest result {sorted(RETEST_RESULTS)}: ").strip().lower()
            evidence = self.input("Retest evidence reference (artifact path, ticket, or description): ")
            registry.record_retest(fid, result, evidence=evidence, run_id=self.session_directory.name if self.session_directory else None)
            self.output(f"Retest recorded; {fid} is now {registry.state()[fid]['status']}.")
        elif choice == "5":
            fid = self.input("Finding ID (DRF-...): ").strip()
            registry.add_note(fid, self.input("Note: "))
            self.output("Note recorded.")
        elif choice == "6":
            directory = self._operation_directory("lifecycle")
            path = registry.snapshot(directory)
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["artifact_path"] = f"{directory.name}/{path.name}"
            payload["root_domain"] = self.scope.root_domain
            self._intelligence_payloads["lifecycle"] = payload
            self.output(f"Lifecycle snapshot saved to {path}; status counts {payload['status_counts']}.")

    # ------------------------------------------------------------------ 25 session / artifacts
    def _session_menu(self) -> None:
        run = self.session_directory
        engagement = getattr(self, "engagement", None)
        self.output("\nSESSION & ARTIFACT MANAGEMENT")
        self.output(f"Session ID: {self.authorization.session_id} | Run: {run.name if run else 'not started'} | Engagement: {engagement.name if engagement else 'none'}")
        for stage, payload in sorted(self._intelligence_payloads.items()):
            self.output(f"  registered: {stage:<26} {payload.get('status', 'success'):<14} {payload.get('artifact_path', '')}")
        self.output("[1] Write artifact integrity manifest (SHA-256 of every run file)")
        self.output("[2] Verify run artifacts against the latest manifest")
        self.output("[3] List authorization records for this run")
        self.output("[4] Check HTTPX binary readiness (version + loopback-only pinning gates)")
        self.output("[0] Back")
        choice = self.input("Select a session action: ").strip()
        if choice == "4":
            report = check_httpx_ready(self.httpx)
            self.output(json.dumps(report, indent=2, sort_keys=True))
            self._httpx_inspection = None
            self._httpx_ready = bool(report.get("ready"))
            if report.get("ready"):
                self._health = None  # refresh the dashboard status
            return
        if run is None:
            if choice in {"1", "2", "3"}:
                self.output("No run directory exists yet in this session.")
            return
        if choice == "1":
            files = {str(path.relative_to(run)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(run.rglob("*")) if path.is_file() and not path.name.startswith("artifact_manifest-")}
            name = f"artifact_manifest-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}.json"
            write_json_artifact(run, name, {"schema_id": "domainrecon.artifact_manifest", "schema_version": 1, "run_id": run.name, "session_id": self.authorization.session_id, "generated_at": datetime.now(timezone.utc).isoformat(), "files": files})
            self.output(f"Manifest {name} records {len(files)} file(s).")
        elif choice == "2":
            manifests = sorted(run.glob("artifact_manifest-*.json"))
            if not manifests:
                self.output("No manifest exists; write one first.")
                return
            recorded = json.loads(manifests[-1].read_text(encoding="utf-8"))["files"]
            changed = [name for name, digest in recorded.items() if not (run / name).is_file() or hashlib.sha256((run / name).read_bytes()).hexdigest() != digest]
            self.output(f"Integrity check against {manifests[-1].name}: {len(recorded) - len(changed)} unchanged, {len(changed)} modified or missing." + ("" if not changed else " CHANGED: " + ", ".join(changed[:10])))
        elif choice == "3":
            for path in sorted(run.glob("authorization-*.json")):
                record = json.loads(path.read_text(encoding="utf-8"))
                self.output(f"  {record['authorized_at_utc'][:19]} {record['operation']:<22} {record['result']:<8} {record['authorization_method']}")

    # ------------------------------------------------------------------ full workflow (offline part)
    def _run_offline_pipeline(self, include_report: bool = True) -> None:
        """After collection, run every offline analysis whose prerequisites exist, then report."""
        self.output("\n[FULL] Running offline analyses on collected evidence (no network activity).")
        steps = (
            ("DNS intelligence", self._dns_stage_is_current, self._run_dns_intelligence),
            ("Asset inventory", lambda: bool(self._stage_artifacts()), self._run_asset_inventory),
            ("HTTP intelligence", lambda: self.httpx_records is not None, self._run_http_intelligence),
            ("Technology fingerprinting", lambda: bool(self.httpx_records or self.nmap_records or self.database_inventory), self._run_technology),
            ("Takeover intelligence", lambda: "dns_intelligence" in self._intelligence_payloads, self._run_takeover),
            ("Cloud intelligence (no imported ranges)", lambda: "dns_intelligence" in self._intelligence_payloads or self.httpx_records is not None, lambda: self._run_cloud(interactive=False)),
            ("Misconfiguration rules (no imports)", lambda: self.httpx_records is not None or (self.nmap_records or {}).get("status") in {"success", "partial"}, lambda: self._run_misconfiguration(interactive=False)),
            ("Delivery/exposure", lambda: self._defensive_prerequisites()["delivery"] is None, self._run_delivery_intelligence),
            ("Correlation", lambda: True, self._run_correlation),
            ("ATT&CK mapping", lambda: "correlation" in self._intelligence_payloads, self._run_mitre),
            ("Unified report", lambda: include_report, self._run_unified_report),
        )
        for label, ready, action in steps:
            if not ready():
                self.output(f"  {label}: skipped (prerequisites not met)")
                continue
            try:
                action()
            except (OSError, ValueError, KeyError, TypeError, DomainReconError) as exc:
                self.output(f"  {label}: failed ({exc}); continuing with remaining offline steps.")
