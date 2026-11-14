"""Presentation layer for the interactive CLI: dashboard, grouped navigation, authorization
pre-flight panels, result tables, scope review, and the guided pilot workflow.

Mixed into ``InteractiveApp``. Nothing here performs collection or weakens a control: every
operation still runs through the existing handlers, ScopePolicy, engagement gating, typed
acknowledgements, and authorization records. Views only read session state.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domainrecon import __version__
from domainrecon.active.httpx_probe import inspect_httpx
from domainrecon.core import public_suffix
from domainrecon.core.errors import ScopeViolation

TAGLINE = "Authorized, scope-limited security assessment CLI"
# operation id -> (label, PASSIVE|ACTIVE, what it does on the network)
OPERATION_INFO: dict[str, tuple[str, str, str]] = {
    "passive_enumeration": ("Passive subdomain enumeration", "PASSIVE", "queries third-party sources (Subfinder providers, crt.sh); no traffic to the target"),
    "dns_resolution": ("DNS resolution and email policy records", "PASSIVE", "DNS queries through public resolvers for discovered names, the apex and _dmarc"),
    "dns_dnssec_query": ("DNSSEC indicator query", "PASSIVE", "two DNS queries (DNSKEY, DS) to the engagement's configured resolver"),
    "dns_wildcard_probe": ("Wildcard DNS probe", "ACTIVE", "resolves two random in-scope labels through DNSx"),
    "httpx_active_probe": ("HTTP/HTTPS probing (HTTPX)", "ACTIVE", "GET requests to discovered hosts, pinned to validated addresses, max 2 req/s"),
    "tls_certificate_probe": ("TLS certificate inspection", "ACTIVE", "TLS handshakes to validated addresses with the hostname as SNI"),
    "nmap_tcp_scan": ("Nmap TCP connect scan", "ACTIVE", "TCP connect scan of validated public addresses"),
    "nmap_host_scan": ("Nmap TCP connect scan of discovered hosts", "ACTIVE", "TCP connect scan of validated public addresses of the listed hostnames"),
    "nmap_resume": ("Resume interrupted Nmap scan", "ACTIVE", "continues a previous TCP connect scan against the same pinned addresses"),
}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_MENU_KIND = {"15": "ADMIN", "16": "ACTIVE", "17": "OFFLINE", "18": "OFFLINE", "19": "OFFLINE", "20": "OFFLINE", "21": "IMPORT", "22": "OFFLINE", "23": "OFFLINE", "24": "ADMIN", "25": "ADMIN"}


def _level(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("level")
    return str(value or "").upper()


def _short(value: Any, limit: int = 80) -> str:
    text = value if isinstance(value, str) else ", ".join(str(v) for v in value) if isinstance(value, (list, tuple, set)) else "" if value is None else str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


class ConsoleViewsMixin:
    # ------------------------------------------------------------------ session facts
    def _note_operation(self, label: str, status: str, detail: str = "") -> None:
        self.last_operation = {"label": label, "status": status, "detail": detail, "at": datetime.now(timezone.utc).strftime("%H:%M:%S UTC")}

    def _httpx_readiness(self) -> tuple[str, str]:
        if getattr(self, "_httpx_ready", False):
            return "ready (loopback pinning gates passed)", "OK"
        if not self.httpx.is_file():
            return "not installed - HTTP probing disabled (run --check-httpx for details)", "FAIL"
        if getattr(self, "_httpx_inspection", None) is None:
            self._httpx_inspection = inspect_httpx(self.httpx)  # local version query only
        report = self._httpx_inspection
        if report["status"] == "compatible_pending_loopback_gate":
            return f"v{report['version']} found - loopback pinning gate runs before first use", "WARN"
        if report["status"] == "incompatible_version":
            return f"v{report['version']} incompatible (pinned input needs v{report['minimum']}+)", "FAIL"
        return f"binary not usable ({report['status']})", "FAIL"

    def _psl_summary(self) -> tuple[str, str]:
        status = public_suffix.status()
        if status.get("active") == "official":
            return f"official list {status.get('version', '')} ({status.get('integrity')}, {status.get('rule_count')} rules)".replace("  ", " "), "OK"
        if status.get("active") == "error":
            return f"error: {status.get('error')}", "FAIL"
        return f"bundled offline subset ({status.get('rule_count')} rules) - official list not installed", "WARN"

    def _findings_summary(self) -> tuple[str, str]:
        correlation = self._intelligence_payloads.get("correlation")
        if correlation:
            rows, basis = correlation.get("canonical_findings", []), "correlated"
        else:
            rows = [f for name, p in self._intelligence_payloads.items() if isinstance(p, dict) and name not in {"impact", "unified_report", "mitre", "lifecycle"} for f in p.get("findings", []) if isinstance(f, dict)]
            basis = "uncorrelated stage findings"
        if not rows:
            return "none recorded yet", "INFO"
        counts = {severity: sum(1 for row in rows if _level(row.get("severity")) == severity) for severity in _SEVERITIES}
        other = len(rows) - sum(counts.values())
        text = "  ".join(f"{severity} {count}" for severity, count in counts.items() if count) or "0"
        state = "FAIL" if counts["CRITICAL"] or counts["HIGH"] else "WARN" if counts["MEDIUM"] else "OK"
        return f"{text}{'  unrated ' + str(other) if other else ''}  ({len(rows)} {basis})", state

    def _dashboard_facts(self) -> tuple[list[tuple[str, Any, str | None]], list[tuple[str, Any, str | None]]]:
        engagement = self.engagement
        scope = self.scope
        health = self._dependency_status()
        entries = [entry for _title, group in self._menu_groups() for entry in group if entry["number"] != "0"] if scope else []
        from domainrecon.ui import menu_state
        ready = sum(1 for entry in entries if menu_state(entry.get("note", ""))[0] == "READY")
        last = getattr(self, "last_operation", None)
        scope_detail = "VALID" if scope else "pending"
        if scope and (scope.excluded_hostnames or scope.excluded_networks or scope.authorized_networks):
            scope_detail += f" ({len(scope.excluded_hostnames)} excluded host(s), {len(scope.excluded_networks)} excluded network(s), {len(scope.authorized_networks)} authorized range(s))"
        session = [
            ("Engagement", f"{engagement.name} [{engagement.engagement_id}]" if engagement else "none (root-domain scope only)", "OK" if engagement else "INFO"),
            ("Target", scope.root_domain if scope else "(not selected)", "OK" if scope else "WARN"),
            ("Scope validation", scope_detail, "OK" if scope else "WARN"),
            ("Session ID", self.authorization.session_id[:12], None),
            ("Run ID", self.session_directory.name if self.session_directory else "not started", None),
            ("Passive authorization", "confirmed for this session" if self.passive_authorized else "not yet confirmed", "OK" if self.passive_authorized else "INFO"),
            ("Active authorization", "typed phrase per operation; never stored", "INFO"),
            ("Last operation", f"{last['label']}: {last['status']} ({last['at']})" if last else "none in this session", None),
            ("Findings", *self._findings_summary()),
        ]
        httpx_text, httpx_state = self._httpx_readiness()
        psl_text, psl_state = self._psl_summary()
        readiness = [
            ("HTTPX", httpx_text, httpx_state),
            ("Public Suffix List", psl_text, psl_state),
            ("Subfinder", health["Subfinder"], "OK" if health["Subfinder"].startswith("available") else "FAIL"),
            ("DNSx", health["DNSx"], "OK" if health["DNSx"].startswith("available") else "FAIL"),
            ("Nmap", health["Nmap"], "FAIL" if health["Nmap"].casefold().startswith(("failed", "unavailable", "not installed")) else "OK"),
            ("Modules", f"{ready} ready, {len(entries) - ready} waiting on prerequisites or dependencies" if entries else "select a target to evaluate", None),
        ]
        return session, readiness

    def _show_dashboard(self) -> None:
        session, readiness = self._dashboard_facts()
        if self.ui.layout:
            if not getattr(self, "_banner_shown", False):
                self.ui.banner(__version__, TAGLINE)
                self._banner_shown = True
            self.ui.write("")
            self.ui.key_values("SESSION", session)
            self.ui.key_values("READINESS", readiness)
            return
        # Plain mode keeps the legacy line formats (scripts and tests rely on them) and appends the new facts.
        self.output("\n" + "=" * 68)
        self.output(f"DomainRecon V2  |  version {__version__}")
        self.output(TAGLINE)
        self.output("=" * 68)
        for name, status in self._dependency_status().items():
            self.output(f"{name:<12} {status}")
        self.output(f"Current target: {self.scope.root_domain if self.scope else '(not selected)'}")
        self.output(f"Scope validation: {'VALID' if self.scope else 'pending'}")
        self.output(f"Passive authorization: {'confirmed for this session' if self.passive_authorized else 'not yet confirmed'}")
        self.output(f"Current run ID: {self.session_directory.name if self.session_directory else 'not started'}")
        self.output(f"Results directory: {self.session_directory if self.session_directory else self.results_root}")
        for label, value, _state in [row for row in session if row[0] in {"Engagement", "Session ID", "Active authorization", "Last operation", "Findings"}] + [row for row in readiness if row[0] in {"HTTPX", "Public Suffix List", "Modules"}]:
            self.output(f"{label}: {value}")

    # ------------------------------------------------------------------ navigation
    def _engagement_note(self, operation: str, note: str) -> str:
        if self.engagement is not None:
            allowed, reason = self.engagement.operation_allowed(operation)
            if not allowed:
                return f"unavailable: {reason}"
        return note

    def _menu_groups(self) -> list[tuple[str, list[dict[str, str]]]]:
        """Every entry maps to a working handler; notes carry the real prerequisite state."""
        from domainrecon.platform_menu import PLATFORM_MENU

        dns_available = self.dnsx.is_file()
        passive_ready = self._passive_stage_is_current_success()
        has_nmap = self.last_nmap_artifact is not None
        prerequisite: list[str] = []
        if self.passive_payload is None:
            prerequisite.append("passive collection required")
        elif self.passive_payload.get("status") != "success":
            prerequisite.append("passive collection failed; retry enumeration")
        elif not passive_ready:
            prerequisite.append("passive results are incomplete for this session")
        dns_reasons = ([] if dns_available else ["DNSx missing"]) + prerequisite
        http_reasons = ([] if self.httpx.is_file() else ["HTTPX binary missing"]) + (prerequisite or ([] if self._dns_stage_is_current() else ["current-session DNS results required"]))
        notes = {
            "1": self._engagement_note("passive_enumeration", "available"),
            "2": self._engagement_note("dns_resolution", "available" if not dns_reasons else "unavailable: " + "; ".join(dns_reasons)),
            "3": self._engagement_note("httpx_active_probe", "available; pinned-IP capability gate runs on selection" if not http_reasons else "unavailable: " + "; ".join(http_reasons)),
            "4": self._engagement_note("nmap_tcp_scan", "available" if self._available_nmap() is not None else "unavailable: Nmap not installed"),
            "5": "available" if has_nmap else "unavailable: successful Nmap result required",
            "6": "available with successful Nmap evidence and a local NVD JSON feed" if has_nmap else "requires a successful Nmap result and a local NVD JSON feed",
            "7": "available; HTTPX/Nmap remain separately authorized" if dns_available else "unavailable: passive source and DNSx required",
            "27": "available; every active stage needs its own confirmation and acknowledgement",
            "26": "available",
        }
        for number, _label, _method in PLATFORM_MENU:
            notes[number] = self._platform_availability(number)
        notes["16"] = self._engagement_note("tls_certificate_probe", notes["16"])
        labels = {number: label for number, label, _method in PLATFORM_MENU}

        short = {"15": "Engagement Management", "3": "HTTP Services Discovery (HTTPX)", "14": "Defensive Analysis (Stages 03-07)", "12": "Unified Security Report (JSON/CSV/HTML)",
                 "10": "Offline Intelligence (DNS, HTTP, assets)", "6": "Vulnerability Intelligence (Stage 02)", "2": "DNS Resolution & Email Policy Records"}

        def entry(number: str, label: str | None = None, kind: str = "OFFLINE") -> dict[str, str]:
            return {"number": number, "label": label or labels[number], "short": short.get(number, ""), "kind": _MENU_KIND.get(number, kind), "note": notes.get(number, "")}

        return [
            ("ENGAGEMENT", [entry("15"), entry("26", "Scope Review & Target Check", "ADMIN"), entry("9", "Change Target Domain", "ADMIN"), entry("25")]),
            ("RECONNAISSANCE", [
                entry("1", "Passive Subdomain Enumeration", "PASSIVE"), entry("2", "DNS Resolution", "PASSIVE"), entry("10", "Stage 01 Offline Intelligence Menu"),
                entry("3", "Live Web Services Discovery (ProjectDiscovery HTTPX)", "ACTIVE"), entry("16"), entry("4", "Nmap Port Scanning", "ACTIVE"), entry("5", "Database Service Discovery"),
            ]),
            ("INTELLIGENCE", [
                entry("17"), entry("18"), entry("6", "Stage 02 Threat Intelligence"), entry("19"), entry("20"),
                entry("14", "Stages 03-07 Offline Defensive Analysis (delivery, assessment, persistence, IOC, impact)"), entry("21"),
            ]),
            ("ANALYSIS", [entry("22"), entry("23"), entry("13", "Historical Change Detection"), entry("11", "Kill Chain Stage Implementation Status", "ADMIN")]),
            ("REPORTING", [entry("12", "Unified JSON/CSV/HTML Report (all available stages)"), entry("24"), entry("8", "View Previous Results", "ADMIN")]),
            ("WORKFLOWS", [entry("27", "Guided Pilot Workflow", "GUIDED"), entry("7", "Full Reconnaissance Workflow", "GUIDED"), {"number": "0", "label": "Exit", "kind": "", "note": ""}]),
        ]

    def _show_main_menu(self) -> None:
        assert self.scope is not None
        if not self.ui.layout:
            self.output("\nMAIN MENU")
        self.ui.menu(self._menu_groups())
        if self.ui.layout:
            self.ui.write("")
            self.ui.wrapped("PASSIVE = third-party/DNS lookups | ACTIVE = traffic to target hosts, separate typed acknowledgement | OFFLINE = stored evidence only", first="  ")

    # ------------------------------------------------------------------ operational safety
    def _show_preflight(self, operation: str, details: dict | None = None) -> None:
        """Always show target, operation type, scope limits and authorization requirement before a network operation."""
        assert self.scope is not None
        label, kind, effect = OPERATION_INFO.get(operation, (operation.replace("_", " "), "ACTIVE", "network operation"))
        scope = self.scope
        hostnames = (details or {}).get("hostnames")
        limits = f"concurrency {int(self._limit('max_concurrency', 2))}, {self._limit('requests_per_second', 2):g} request(s)/s" + (" (engagement)" if self.engagement else " (defaults)")
        lines = [
            f"Operation : {label}  [{kind}]",
            f"Target    : {scope.root_domain}" + (f"  ({len(hostnames)} hostname(s) listed)" if isinstance(hostnames, list) else ""),
            f"Effect    : {effect}",
            f"Scope     : {len(scope.excluded_hostnames)} excluded host(s), {len(scope.excluded_networks)} excluded network(s); " + (f"authorized ranges {', '.join(scope.authorized_networks)}" if scope.authorized_networks else "any validated public address of in-scope names"),
            f"Limits    : {limits}",
            f"Engagement: {self.engagement.name if self.engagement else 'none'}",
            "Requires  : exact typed acknowledgement (the typed text is never stored); the decision is written to the audit trail",
        ]
        self.ui.panel(f"{kind} OPERATION - AUTHORIZATION REQUIRED", lines, "WARN" if kind == "ACTIVE" else "INFO")

    # ------------------------------------------------------------------ result tables
    def _view_assets(self, records: list[dict]) -> None:
        self.ui.table([{"key": "hostname", "title": "Hostname", "flex": True, "min": 20}, {"key": "sources", "title": "Sources"}],
                      [{"hostname": r.get("hostname"), "sources": ", ".join(r.get("sources", []))} for r in records or []], title=f"DISCOVERED ASSETS ({len(records or [])})", empty="No in-scope hostnames were returned.")

    def _view_dns(self, records: list[dict]) -> None:
        rows = []
        for row in records or []:
            data = row.get("records", {}) if isinstance(row.get("records"), dict) else {}
            rows.append({"hostname": row.get("hostname"), "status": str(row.get("status")), "addresses": ", ".join(list(data.get("a", [])) + list(data.get("aaaa", []))), "cname": _short(data.get("cname", []), 60), "note": row.get("error") or ""})
        self.ui.table([{"key": "hostname", "title": "Hostname", "flex": True, "min": 18}, {"key": "status", "title": "DNS status"}, {"key": "addresses", "title": "A / AAAA", "flex": True, "min": 15},
                       {"key": "cname", "title": "CNAME chain", "flex": True, "min": 12}], rows, title=f"DNS RECORDS ({len(rows)})")

    def _view_http(self, records: list[dict]) -> None:
        rows = [{"url": r.get("url") or r.get("hostname"), "code": r.get("status_code") or "-", "class": r.get("classification"), "title": _short(r.get("title"), 50), "server": _short(r.get("web_server"), 30), "ip": r.get("ip"),
                 "detail": _short(r.get("error"), 60)} for r in records or []]
        self.ui.table([{"key": "url", "title": "URL / host", "flex": True, "min": 20}, {"key": "code", "title": "HTTP"}, {"key": "class", "title": "Classification"}, {"key": "title", "title": "Title (as served)", "flex": True, "min": 10},
                       {"key": "server", "title": "Server (self-reported)", "flex": True, "min": 10}, {"key": "ip", "title": "Pinned IP"}], rows, title=f"HTTP SERVICES ({len(rows)})")

    def _view_services(self, result: dict) -> None:
        rows = []
        for host in result.get("hosts", []) if isinstance(result, dict) else []:
            for port in host.get("ports", []):
                if port.get("state") == "open":
                    rows.append({"address": host.get("address"), "hostnames": ", ".join(host.get("hostnames", [])), "port": f"{port.get('port')}/{port.get('protocol', 'tcp')}", "service": port.get("service"),
                                 "product": " ".join(str(x) for x in (port.get("product"), port.get("version")) if x), "source": "nmap -sV" if port.get("product") else "port only"})
        self.ui.table([{"key": "address", "title": "Address"}, {"key": "hostnames", "title": "Hostnames", "flex": True, "min": 12}, {"key": "port", "title": "Port"}, {"key": "service", "title": "Service"},
                       {"key": "product", "title": "Product / version", "flex": True, "min": 12}, {"key": "source", "title": "Evidence"}], rows, title=f"OPEN NETWORK SERVICES ({len(rows)})", empty="No open TCP ports were observed.")

    def _view_vulnerabilities(self, findings: list[dict]) -> None:
        label = {"exact_cpe_match": "EXACT VERSION", "version_range_match": "VERSION RANGE", "candidate_match": "CANDIDATE (unproven)"}
        rows = [{"cve": f.get("cve_id"), "asset": f"{f.get('hostname') or f.get('ip_address') or f.get('asset_id')}" + (f":{f.get('port')}" if f.get("port") else ""), "match": label.get(f.get("match_type"), f.get("classification") or "-"),
                 "cvss": f.get("cvss_score") if f.get("cvss_score") is not None else (f.get("cvss") or {}).get("base_score") if isinstance(f.get("cvss"), dict) else "-", "severity": _level(f.get("severity")) or "-",
                 "confidence": f.get("match_confidence") or f.get("confidence")} for f in findings or [] if f.get("cve_id")]
        self.ui.table([{"key": "cve", "title": "CVE"}, {"key": "asset", "title": "Asset", "flex": True, "min": 14}, {"key": "match", "title": "Match basis"}, {"key": "cvss", "title": "CVSS"},
                       {"key": "severity", "title": "Severity", "kind": "severity"}, {"key": "confidence", "title": "Confidence"}], rows, title=f"VULNERABILITY MATCHES ({len(rows)})", empty="No CVE matched the observed CPE/version evidence.")
        if rows:
            self.ui.info("A match states applicability from CPE/version evidence; it is not confirmed exploitability. CANDIDATE matches are unproven.")

    def _view_certificates(self, payload: dict) -> None:
        rows = [{"subject": c.get("subject_cn") or _short(c.get("subject_dn"), 40), "issuer": _short(c.get("issuer_dn"), 50), "expires": str(c.get("not_after"))[:10], "key": f"{c.get('key_algorithm') or '?'} {c.get('key_size') or ''}".strip(),
                 "hosts": ", ".join(sorted({str(o.get("hostname")) for o in c.get("observed_on", [])})), "evidence": "full certificate" if c.get("evidence_source") == "tls_probe_der" else "HTTPX fields only"} for c in payload.get("certificates", [])]
        self.ui.table([{"key": "subject", "title": "Subject CN", "flex": True, "min": 14}, {"key": "issuer", "title": "Issuer", "flex": True, "min": 14}, {"key": "expires", "title": "Expires"}, {"key": "key", "title": "Key"},
                       {"key": "hosts", "title": "Observed on", "flex": True, "min": 14}, {"key": "evidence", "title": "Evidence"}], rows, title=f"TLS CERTIFICATES ({len(rows)})")
        self._view_findings(payload.get("findings", []), "CERTIFICATE / TLS FINDINGS")

    def _view_findings(self, findings: list[dict], title: str) -> None:
        rows = [{"severity": _level(f.get("severity")) or "INFO", "asset": f.get("asset_id") or f.get("hostname") or f.get("matched_asset") or f.get("host") or "-",
                 "finding": _short(f.get("title") or f.get("type") or f.get("persistence_category") or f.get("ioc_value") or f.get("classification"), 70), "confidence": _level(f.get("confidence")).lower() or "-",
                 "basis": _short(f.get("detection_basis") or f.get("source") or f.get("source_feed") or f.get("classification"), 40)} for f in findings or [] if isinstance(f, dict)]
        rows.sort(key=lambda r: _SEVERITIES.index(r["severity"]) if r["severity"] in _SEVERITIES else 9)
        self.ui.table([{"key": "severity", "title": "Severity", "kind": "severity"}, {"key": "asset", "title": "Asset", "flex": True, "min": 14}, {"key": "finding", "title": "Finding", "flex": True, "min": 16},
                       {"key": "confidence", "title": "Confidence"}, {"key": "basis", "title": "Evidence basis", "flex": True, "min": 10}], rows, title=f"{title} ({len(rows)})", empty="No findings.")

    def _view_technologies(self, payload: dict) -> None:
        source = {"self_reported_banner": "self-reported banner", "nmap_service_version": "Nmap -sV", "httpx_tech_detect": "HTTPX detection"}
        rows = [{"asset": t["asset"], "product": t["product"], "category": t["category"], "version": t.get("version") or "-", "basis": source.get(t.get("version_source"), "no version evidence" if not t.get("version") else str(t.get("version_source"))),
                 "confidence": t["confidence"]} for t in payload.get("technologies", [])]
        self.ui.table([{"key": "asset", "title": "Asset", "flex": True, "min": 14}, {"key": "product", "title": "Product", "flex": True, "min": 10}, {"key": "category", "title": "Category"}, {"key": "version", "title": "Version"},
                       {"key": "basis", "title": "Version basis"}, {"key": "confidence", "title": "Confidence"}], rows, title=f"TECHNOLOGY INVENTORY ({len(rows)})")

    def _view_cloud(self, payload: dict) -> None:
        rows = [{"asset": a["asset"], "provider": a["provider"], "attribution": "CONFIRMED (published range)" if a["attribution"] == "confirmed_by_published_range" else "INFERRED", "confidence": a["confidence"],
                 "signals": ", ".join(sorted({e["evidence_type"] for e in a["evidence"]}))} for a in payload.get("attributions", [])]
        self.ui.table([{"key": "asset", "title": "Asset", "flex": True, "min": 14}, {"key": "provider", "title": "Provider"}, {"key": "attribution", "title": "Attribution"}, {"key": "confidence", "title": "Confidence"},
                       {"key": "signals", "title": "Signals", "flex": True, "min": 10}], rows, title=f"CLOUD ATTRIBUTION ({len(rows)})", empty="No provider signal was observed.")

    def _view_takeover(self, payload: dict) -> None:
        rows = [{"severity": f["severity"], "asset": f["asset_id"], "classification": f["classification"].replace("_", " "), "provider": f["evidence"].get("provider") or "-", "reason": _short(f.get("reason"), 80), "confidence": f["confidence"]}
                for f in payload.get("findings", [])]
        self.ui.table([{"key": "severity", "title": "Severity", "kind": "severity"}, {"key": "asset", "title": "Alias", "flex": True, "min": 14}, {"key": "classification", "title": "Classification"}, {"key": "provider", "title": "Provider"},
                       {"key": "reason", "title": "Why", "flex": True, "min": 14}, {"key": "confidence", "title": "Confidence"}], rows, title=f"TAKEOVER INDICATORS ({len(rows)})", empty="No alias to an external provider was observed.")
        if rows:
            self.ui.info("Indicators come from passive evidence and curated, unverified signatures; nothing was claimed or registered.")

    def _view_correlation(self, payload: dict) -> None:
        rows = [{"id": f["finding_id"], "priority": f["priority"], "severity": f["severity"], "risk": f["risk"]["score"], "asset": f["asset_id"], "title": _short(f.get("title"), 60), "confidence": f["confidence"], "sources": ", ".join(f["sources"])}
                for f in payload.get("canonical_findings", [])]
        self.ui.table([{"key": "id", "title": "Finding ID"}, {"key": "priority", "title": "Pri"}, {"key": "severity", "title": "Severity", "kind": "severity"}, {"key": "risk", "title": "Risk"}, {"key": "asset", "title": "Asset", "flex": True, "min": 12},
                       {"key": "title", "title": "Finding", "flex": True, "min": 14}, {"key": "confidence", "title": "Confidence"}, {"key": "sources", "title": "Stages", "flex": True, "min": 8}], rows, title=f"CORRELATED FINDINGS ({len(rows)})")
        paths = [{"path": _short(p["title"], 70), "status": "VERIFIED (imported evidence)" if p["verification_status"] == "verified_by_imported_evidence" else "THEORETICAL - not tested", "techniques": ", ".join(t["technique_id"] for t in p["techniques"]),
                  "confidence": p["confidence"]} for p in payload.get("attack_paths", [])]
        self.ui.table([{"key": "path", "title": "Attack-path hypothesis", "flex": True, "min": 20}, {"key": "status", "title": "Verification"}, {"key": "techniques", "title": "ATT&CK"}, {"key": "confidence", "title": "Confidence"}],
                      paths, title=f"ATTACK-PATH HYPOTHESES ({len(paths)})", empty="No hypothesis was derived from the current findings.")

    def _view_attack_matrix(self, payload: dict) -> None:
        rows = [{"tactic": tactic, "technique": tid, "name": cell["technique_name"], "count": len(cell["finding_ids"])} for tactic, cells in payload.get("matrix", {}).items() for tid, cell in cells.items()]
        self.ui.table([{"key": "tactic", "title": "Tactic"}, {"key": "technique", "title": "Technique"}, {"key": "name", "title": "Name", "flex": True, "min": 16}, {"key": "count", "title": "Findings"}], rows, title=f"MITRE ATT&CK MAPPING ({len(rows)})")

    # ------------------------------------------------------------------ 26 scope review
    def _scope_review(self) -> None:
        assert self.scope is not None
        scope = self.scope
        psl_text, _state = self._psl_summary()
        self.ui.key_values("SCOPE", [
            ("Root domain", scope.root_domain, "OK"),
            ("Root validation", f"registrable domain per {psl_text}", None),
            ("Excluded hostnames", ", ".join(sorted(scope.excluded_hostnames)) or "none", "WARN" if scope.excluded_hostnames else None),
            ("Excluded networks", ", ".join(scope.excluded_networks) or "none", "WARN" if scope.excluded_networks else None),
            ("Authorized IP ranges", ", ".join(scope.authorized_networks) or "not restricted (any validated public address of in-scope names)", None),
            ("Always blocked", "private, loopback, link-local, multicast, reserved, IPv4-mapped/6to4/Teredo addresses; names outside the root", None),
        ])
        if self.engagement is not None:
            self.ui.table([{"key": "operation", "title": "Operation"}, {"key": "state", "title": "Engagement", "kind": "state"}, {"key": "note", "title": "Note", "flex": True}],
                          [{"operation": name, "state": "OK enabled" if enabled else "FAIL disabled", "note": "still requires its typed acknowledgement" if enabled else "refused before any prompt"} for name, enabled in self.engagement.operations.items()],
                          title="ENGAGEMENT OPERATIONS")
        while True:
            value = self.input("Check a hostname or IP against the scope (blank to go back): ").strip()
            if not value:
                return
            try:
                classification = scope.classify_ip(value)
                if classification["category"] != "invalid":
                    scope.require_public_ip(value)
                    self.output(f"IN SCOPE as a destination: {classification['address']} is {classification['category']} (IPv{classification['version']}); it may be contacted only when an in-scope hostname resolves to it.")
                else:
                    self.output(f"IN SCOPE: {scope.require_hostname(value)} is within {scope.root_domain} and not excluded.")
            except ScopeViolation as exc:
                self.output(f"OUT OF SCOPE - scope violation: {exc}")

    # ------------------------------------------------------------------ 27 guided pilot workflow
    def _guided_stages(self) -> list[dict[str, Any]]:
        def blocked(operation: str) -> str | None:
            if self.engagement is not None:
                allowed, reason = self.engagement.operation_allowed(operation)
                return None if allowed else reason
            return None

        return [
            {"id": "1", "label": "Passive subdomain enumeration", "kind": "PASSIVE", "needs": blocked("passive_enumeration")},
            {"id": "2", "label": "DNS resolution and email policy records", "kind": "PASSIVE", "needs": blocked("dns_resolution") or (None if self.dnsx.is_file() else "DNSx is not installed")},
            {"id": "3", "label": "HTTP/HTTPS probing (HTTPX)", "kind": "ACTIVE", "needs": blocked("httpx_active_probe") or (None if self.httpx.is_file() else "HTTPX binary is not installed")},
            {"id": "4", "label": "TLS certificate inspection", "kind": "ACTIVE", "needs": blocked("tls_certificate_probe")},
            {"id": "5", "label": "Nmap port scan (you choose scope and ports)", "kind": "ACTIVE", "needs": blocked("nmap_tcp_scan") or (None if self._available_nmap() is not None else "Nmap is not installed")},
            {"id": "6", "label": "Offline analyses (DNS/HTTP intelligence, assets, technology, cloud, takeover, misconfiguration, correlation, ATT&CK)", "kind": "OFFLINE", "needs": None},
            {"id": "7", "label": "Unified JSON/CSV/HTML report", "kind": "OFFLINE", "needs": None},
        ]

    def _guided_workflow(self) -> None:
        assert self.scope is not None
        self.ui.heading("GUIDED PILOT WORKFLOW")
        self.output("Seven steps: engagement, scope, readiness, stage selection, authorized execution, findings review, report. Nothing runs without your explicit confirmation.")
        # 1. engagement
        self.ui.heading("STEP 1 OF 7 - ENGAGEMENT")
        self.output(f"Current engagement: {self.engagement.name if self.engagement else 'none (root-domain scope only)'}")
        self.output("[1] Continue with the current engagement and scope")
        self.output("[2] Load an engagement file")
        self.output("[3] Create an engagement")
        self.output("[0] Back")
        choice = self.input("Select an engagement option: ").strip()
        if choice == "2":
            path = self._local_file("Engagement file path: ", required=True, max_bytes=262_144)
            if not isinstance(path, Path):
                return
            from domainrecon.core.engagement import load_engagement
            self._apply_engagement(load_engagement(path))
        elif choice == "3":
            self._create_engagement()
        elif choice != "1":
            self.output("Guided workflow cancelled; nothing was run.")
            return
        # 2. scope
        self.ui.heading("STEP 2 OF 7 - SCOPE VALIDATION")
        scope = self.scope
        self.output(f"Target: {scope.root_domain} | excluded hostnames: {', '.join(sorted(scope.excluded_hostnames)) or 'none'} | excluded networks: {', '.join(scope.excluded_networks) or 'none'} | authorized IP ranges: {', '.join(scope.authorized_networks) or 'not restricted'}")
        if self.input(f"Type YES to confirm that {scope.root_domain} and these exclusions match your written authorization: ").strip() != "YES":
            self.output("Scope not confirmed; guided workflow cancelled and nothing was run.")
            return
        # 3. readiness
        self.ui.heading("STEP 3 OF 7 - MODULE READINESS")
        stages = self._guided_stages()
        self.ui.table([{"key": "id", "title": "#"}, {"key": "label", "title": "Stage", "flex": True, "min": 24}, {"key": "kind", "title": "Type", "kind": "kind"}, {"key": "state", "title": "Readiness", "kind": "state"}, {"key": "note", "title": "Note", "flex": True, "min": 10}],
                      [{"id": s["id"], "label": s["label"], "kind": s["kind"], "state": "READY" if s["needs"] is None else "BLOCKED", "note": s["needs"] or ("explicit confirmation + typed acknowledgement" if s["kind"] == "ACTIVE" else "")} for s in stages])
        # 4. selection
        self.ui.heading("STEP 4 OF 7 - STAGE SELECTION")
        raw = self.input("Stages to run, comma-separated (for example 1,2,6,7; blank to cancel): ").strip()
        if not raw:
            self.output("No stage selected; guided workflow cancelled.")
            return
        requested = [part.strip() for part in raw.split(",") if part.strip()]
        by_id = {s["id"]: s for s in stages}
        invalid = [part for part in requested if part not in by_id]
        if invalid:
            self.output(f"Invalid stage selection: {', '.join(invalid)}. Choose numbers 1-7; nothing was run.")
            return
        selected = [by_id[key] for key in sorted(set(requested), key=int)]
        outcomes: list[dict[str, str]] = []
        # 5. execution
        self.ui.heading("STEP 5 OF 7 - AUTHORIZED EXECUTION")
        for stage in selected:
            if stage["needs"] is not None:
                outcomes.append({"stage": stage["label"], "kind": stage["kind"], "outcome": "FAIL blocked", "detail": stage["needs"]})
                self.output(f"Stage skipped: {stage['label']} is unavailable: {stage['needs']}")
                continue
            if stage["kind"] == "ACTIVE":
                answer = self.input(f"ACTIVE stage '{stage['label']}' against {self.scope.root_domain}. Type YES to continue to its authorization prompt (anything else skips it): ").strip()
                if answer != "YES":
                    outcomes.append({"stage": stage["label"], "kind": stage["kind"], "outcome": "WARN declined", "detail": "operator did not confirm; nothing was sent"})
                    self.output(f"Stage declined: {stage['label']}; nothing was sent.")
                    continue
            before = getattr(self, "last_operation", None)
            self._run_guided_stage(stage["id"])
            after = getattr(self, "last_operation", None)
            ran = after is not None and after is not before
            outcomes.append({"stage": stage["label"], "kind": stage["kind"], "outcome": f"OK {after['status']}" if ran and after["status"] not in {"not authorized", "error"} else f"WARN {after['status']}" if ran else "INFO no result recorded",
                             "detail": after["detail"] if ran else "see messages above"})
        # 6. findings
        self.ui.heading("STEP 6 OF 7 - FINDINGS REVIEW")
        correlation = self._intelligence_payloads.get("correlation")
        if correlation:
            self._view_correlation(correlation)
        else:
            self.output(f"Findings: {self._findings_summary()[0]}. Select stage 6 (offline analyses) to correlate and prioritize findings.")
        # 7. summary
        self.ui.heading("STEP 7 OF 7 - REPORT AND SUMMARY")
        self.ui.table([{"key": "stage", "title": "Stage", "flex": True, "min": 24}, {"key": "kind", "title": "Type", "kind": "kind"}, {"key": "outcome", "title": "Outcome", "kind": "state"}, {"key": "detail", "title": "Detail", "flex": True, "min": 12}], outcomes)
        report = self._intelligence_payloads.get("unified_report")
        self.output(f"Report: {'generated in this run (' + str(self.session_directory) + ')' if report else 'not generated; select stage 7 or use menu 12'}")

    def _run_guided_stage(self, stage_id: str) -> None:
        if stage_id == "1":
            if self._ensure_passive_authorization():
                self._run_passive((["subfinder"] if self.subfinder.is_file() else []) + ["crt.sh"])
        elif stage_id == "2":
            self._run_dns()
        elif stage_id == "3":
            self._run_httpx()
        elif stage_id == "4":
            self._tls_menu(preset="2")
        elif stage_id == "5":
            self._nmap_menu()
        elif stage_id == "6":
            self._run_offline_pipeline(include_report=False)
        elif stage_id == "7":
            self._run_unified_report()
