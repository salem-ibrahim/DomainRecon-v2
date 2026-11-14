"""Minimal v2 command line preserving passive-by-default behavior."""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from domainrecon.active.httpx_probe import DEFAULT_HTTPX_PATH, HTTPX_INSTALL_GUIDANCE, check_httpx_pinning, check_httpx_ready, discover_httpx, export_live_inventory, probe_httpx
from domainrecon.analysis.database_discovery import load_and_analyze_nmap
from domainrecon.collectors.dns_intelligence import collect_dns, collect_dns_policy
from domainrecon.core.authorization import GRANTED, METHOD_COMMAND_LINE, build_record, new_session_id, persist_record
from domainrecon.core.csv_safe import render_csv
from domainrecon.core.engagement import load_engagement, operation_history
from domainrecon.core.public_suffix import install_public_suffix_list, status as psl_status, update_public_suffix_list
from domainrecon.core.events import log_event
from domainrecon.collectors.passive import enumerate_passive_detailed
from domainrecon.core.errors import DomainReconError, ScopeViolation
from domainrecon.core.models import ActiveAuthorization
from domainrecon.core.scope import ScopePolicy
from domainrecon.core.storage import create_scan_directory, write_json_artifact, write_text_artifact
from domainrecon.scanners.nmap import NmapScanOptions, TcpScanMode, nmap_version, run_nmap, run_nmap_hosts



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="domainrecon-v2")
    parser.add_argument("domain", nargs="?", help="Authorized root domain")
    parser.add_argument("--health", action="store_true", help="Show installed tool status without network activity")
    parser.add_argument("--acknowledge", default="", help="Required exact passive authorization phrase")
    parser.add_argument("--subfinder", type=Path, default=Path("tools/subfinder/subfinder.exe"))
    parser.add_argument("--dns", action="store_true", help="Resolve passively discovered hosts with DNSx (or hosts from --hosts-file)")
    parser.add_argument("--hosts-file", type=Path, help="Optional DNSx input file; otherwise resolve names discovered in this run")
    parser.add_argument("--dnsx", type=Path, default=Path("tools/dnsx/dnsx.exe"))
    parser.add_argument("--results", type=Path, default=Path("results"))
    parser.add_argument("--http-probe", action="store_true", help="Opt in to ProjectDiscovery HTTPX against same-run discovered hosts after DNSx validation")
    parser.add_argument("--httpx", type=Path, default=Path("tools/httpx/httpx.exe"), help="ProjectDiscovery HTTPX executable (requires pinned-IP input support)")
    parser.add_argument("--nmap-mode", choices=[mode.value for mode in TcpScanMode], help="Run an authorized TCP discovery scan independently")
    parser.add_argument("--nmap-ports", help="Custom TCP ports, e.g. 443,8000-8010")
    parser.add_argument("--nmap-no-service-detection", action="store_true")
    parser.add_argument("--nmap-max-rate", type=int)
    parser.add_argument("--nmap-max-parallelism", type=int)
    parser.add_argument("--nmap-timeout", type=int)
    parser.add_argument("--nmap", type=Path, default=Path("tools/nmap/nmap.exe"))
    parser.add_argument("--nmap-hosts-file", type=Path, help="With --nmap-mode: scan these explicitly listed in-scope hostnames (one per line) instead of only the root domain")
    parser.add_argument("--engagement", type=Path, help="Engagement file (.yaml subset or .json); narrows scope and can disable operations, never authorizes them")
    parser.add_argument("--check-httpx", action="store_true", help="Validate the HTTPX binary: version plus loopback-only IPv4/IPv6 pinning gates (no external traffic)")
    parser.add_argument("--update-psl", action="store_true", help="Explicitly download the official Public Suffix List (requires --confirm-download)")
    parser.add_argument("--install-psl", type=Path, help="Install the official Public Suffix List from a local file (offline; same validation and integrity metadata as --update-psl)")
    parser.add_argument("--confirm-download", action="store_true", help="Confirm the explicit --update-psl network download")
    parser.add_argument("--nmap-ipv6", action="store_true", help="With --nmap-mode: also scan validated public IPv6 answers (separate -6 invocations); IPv4 is always scanned")
    parser.add_argument("--nmap-per-hostname", action="store_true", help="With --nmap-hosts-file: scan each hostname separately instead of each unique IP once")
    parser.add_argument("--acknowledge-active", default="", help='Required exact phrase for HTTPX or Nmap: "I AUTHORIZE ACTIVE PROBING" for HTTPX')
    parser.add_argument("--database-discovery", action="store_true", help="Analyze an existing Nmap JSON artifact offline")
    parser.add_argument("--nmap-input", type=Path, help="Existing Phase 1 nmap.json artifact for offline Database Discovery")
    return parser


def _tool_status(path: Path) -> str:
    return f"available: {path}" if path.is_file() else f"not installed: {path}"


def _dns_summary(records: list[dict], *, requested: bool, input_source: str, elapsed_seconds: float) -> dict:
    if not requested:
        return {"requested": False, "input_source": None, "status": "not_requested", "elapsed_seconds": 0.0, "resolved": [], "unresolved": [], "failed": []}
    by_status: dict[str, list[str]] = {"success": [], "unresolved": [], "failed": []}
    for record in records:
        status = str(record.get("status", "failed"))
        hostname = record.get("hostname")
        if not isinstance(hostname, str):
            continue
        by_status.setdefault(status, []).append(hostname)
    failed = sorted(set(by_status.get("failed", []) + by_status.get("timeout", [])))
    unresolved = sorted(set(by_status.get("unresolved", [])))
    resolved = sorted(set(by_status.get("success", [])))
    if not records:
        status = "no_hosts"
    elif failed and not (resolved or unresolved):
        status = "failed"
    elif failed:
        status = "partial"
    else:
        status = "success"
    return {
        "requested": True,
        "input_source": input_source,
        "status": status,
        "elapsed_seconds": round(elapsed_seconds, 6),
        "resolved": resolved,
        "unresolved": unresolved,
        "failed": failed,
    }


def _subdomain_exports(passive_records: list[dict], dns_records: list[dict], *, dns_requested: bool, extra_hosts: list[str] | None = None) -> tuple[str, str]:
    passive_by_host = {record["hostname"]: record for record in passive_records if isinstance(record.get("hostname"), str)}
    for hostname in extra_hosts or []:
        passive_by_host.setdefault(hostname, {"hostname": hostname, "sources": ["hosts_file"]})
    dns_by_host = {record["hostname"]: record for record in dns_records if isinstance(record.get("hostname"), str)}
    rows: list[dict[str, str]] = []
    for hostname, source_record in sorted(passive_by_host.items()):
        dns_record = dns_by_host.get(hostname, {})
        raw = dns_record.get("records", {})
        raw = raw if isinstance(raw, dict) else {}
        addresses: list[str] = []
        for key in ("a", "aaaa"):
            values = raw.get(key, [])
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                addresses.extend(str(value) for value in values)
        sources = source_record.get("sources", [])
        sources = sorted({str(value) for value in sources}) if isinstance(sources, list) else []
        rows.append({
            "hostname": hostname,
            "sources": ";".join(sources),
            "dns_status": str(dns_record.get("status", "not_requested" if not dns_requested else "not_returned")),
            "addresses": ";".join(sorted(set(addresses))),
            "dns_records_json": json.dumps(raw, sort_keys=True, separators=(",", ":")) if raw else "",
        })
    fieldnames = ["hostname", "sources", "dns_status", "addresses", "dns_records_json"]
    csv_text = render_csv(fieldnames, rows)
    text_lines = ["DomainRecon V2 passive subdomain results", f"Unique names: {len(rows)}", ""]
    text_lines.extend(
        f"{row['hostname']} | sources={row['sources'] or 'unknown'} | DNS={row['dns_status']}"
        + (f" | addresses={row['addresses']}" if row["addresses"] else "")
        for row in rows
    )
    if not rows:
        text_lines.append("No in-scope subdomains were returned by the passive sources.")
    return csv_text, "\n".join(text_lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if not raw_args:
        from domainrecon.interactive import run_interactive

        return run_interactive()
    args = parser.parse_args(raw_args)
    httpx_explicit = args.httpx != DEFAULT_HTTPX_PATH  # an operator-supplied --httpx path (not discovery)
    if args.httpx == DEFAULT_HTTPX_PATH and not args.httpx.is_file():
        selected = discover_httpx(None)["selected"]  # local candidates only (tools, PATH, Go bin); version query, no network
        if selected:
            args.httpx = Path(selected)
    if args.check_httpx:
        report = check_httpx_ready(args.httpx)
        print(json.dumps(report, sort_keys=True))
        return 0 if report.get("ready") else 1
    if args.health:
        httpx_status = _tool_status(args.httpx)
        health = {"nmap": nmap_version(args.nmap), "subfinder": _tool_status(args.subfinder), "dnsx": _tool_status(args.dnsx), "httpx": httpx_status, "public_suffix_list": psl_status()}
        discovery = discover_httpx(args.httpx)
        health["httpx_discovery"] = {"selected": discovery["selected"], "candidates": discovery["candidates"]}
        if not discovery["selected"]:
            health["httpx_install"] = HTTPX_INSTALL_GUIDANCE
        print(json.dumps(health, sort_keys=True))
        return 0
    if args.install_psl:
        try:
            metadata = install_public_suffix_list(args.install_psl)
        except (OSError, ValueError) as exc:
            parser.error(f"--install-psl failed: {exc}")
        print(json.dumps({"public_suffix_list": metadata}, sort_keys=True))
        return 0
    if args.update_psl:
        if not args.confirm_download:
            parser.error("--update-psl downloads the official list from publicsuffix.org; add --confirm-download to proceed")
        metadata = update_public_suffix_list()
        print(json.dumps({"public_suffix_list": metadata}, sort_keys=True))
        return 0
    if not args.domain:
        parser.error("domain is required unless --health is used")
    try:
        scope = ScopePolicy(args.domain)
    except ScopeViolation as exc:
        parser.error(f"invalid domain: {exc}")
    session_id = new_session_id()
    engagement = None
    if args.engagement:
        try:
            engagement = load_engagement(args.engagement)
        except (OSError, ValueError, DomainReconError) as exc:
            parser.error(f"invalid engagement file: {exc}")
        if engagement.target != scope.root_domain:
            parser.error(f"engagement target {engagement.target} does not match {scope.root_domain}")
        scope = engagement.scope_policy()
        requested = ["port_scanning"] if args.nmap_mode else [] if args.database_discovery else ["passive_recon"] + (["dns_assessment"] if args.dns else []) + (["http_assessment"] if args.http_probe else [])
        for operation in requested:
            allowed, reason = engagement.operation_allowed(operation)
            if not allowed:
                parser.error(f"operation refused: {reason}")

    if args.database_discovery:
        if args.nmap_hosts_file or args.nmap_per_hostname or args.nmap_ipv6 or args.nmap_mode or args.dns or args.hosts_file or args.acknowledge or args.acknowledge_active or args.http_probe or httpx_explicit or args.nmap_ports or args.nmap_no_service_detection or args.nmap_max_rate is not None or args.nmap_max_parallelism is not None or args.nmap_timeout is not None:
            parser.error("--database-discovery cannot be combined with passive, DNS, HTTPX, or Nmap scan options")
        if not args.nmap_input or not args.nmap_input.is_file():
            parser.error("--database-discovery requires an existing --nmap-input JSON artifact")
        try:
            inventory = load_and_analyze_nmap(args.nmap_input, scope)
            scan_dir = create_scan_directory(args.results, scope.root_domain)
            log_event(scan_dir / "database-discovery.events.jsonl", "started", source_artifact=str(args.nmap_input))
            write_json_artifact(scan_dir, "database_inventory.json", inventory)
            log_event(scan_dir / "database-discovery.events.jsonl", "completed", inventory_count=len(inventory["inventory"]), candidate_count=len(inventory["candidates"]), error_count=len(inventory["errors"]))
        except (OSError, ValueError) as exc:
            raise SystemExit(f"Database Discovery error: {exc}") from exc
        print(scan_dir)
        return 0

    if args.nmap_mode:
        if args.dns or args.hosts_file or args.acknowledge or args.nmap_input or args.http_probe or httpx_explicit:
            parser.error("Nmap mode cannot be combined with passive, DNS, HTTPX, or offline-analysis options")
        if args.acknowledge_active != "I AUTHORIZE PORT SCANNING":
            parser.error('Nmap requires --acknowledge-active "I AUTHORIZE PORT SCANNING"')
        if args.nmap_per_hostname and not args.nmap_hosts_file:
            parser.error("--nmap-per-hostname requires --nmap-hosts-file")
        options = NmapScanOptions(
            TcpScanMode(args.nmap_mode),
            args.nmap_ports,
            not args.nmap_no_service_detection,
            args.nmap_max_rate if args.nmap_max_rate is not None else 100,
            args.nmap_max_parallelism if args.nmap_max_parallelism is not None else 2,
            args.nmap_timeout if args.nmap_timeout is not None else 900,
        )
        try:
            options.validate()
        except ValueError as exc:
            parser.error(str(exc))
        nmap_hosts: list[str] | None = None
        if args.nmap_hosts_file:
            if not args.nmap_hosts_file.is_file():
                parser.error("--nmap-hosts-file must point to an existing UTF-8 text file")
            try:
                lines = [line.strip() for line in args.nmap_hosts_file.read_text(encoding="utf-8").splitlines()]
            except (OSError, UnicodeError) as exc:
                parser.error(f"could not read --nmap-hosts-file: {exc}")
            nmap_hosts = [line for line in lines if line and not line.startswith("#")]
            if not nmap_hosts:
                parser.error("--nmap-hosts-file contains no hostnames")
        try:
            scan_dir = create_scan_directory(args.results, scope.root_domain)
            persist_record(scan_dir, build_record(
                target=scope.root_domain, operation="nmap_host_scan" if nmap_hosts else "nmap_tcp_scan", method=METHOD_COMMAND_LINE,
                result=GRANTED, session_id=session_id, run_id=scan_dir.name, acknowledgement_id="NMAP_ACK",
                details={"mode": options.mode.value, "ports": options.ports, "hostnames": nmap_hosts or [scope.root_domain], "per_hostname": bool(args.nmap_per_hostname), "ipv6": bool(args.nmap_ipv6)},
            ))
            if engagement is not None:
                operation_history(args.results, engagement).append({"event": "cli_run", "operations": ["nmap_host_scan" if nmap_hosts else "nmap_tcp_scan"], "run_id": scan_dir.name, "session_id": session_id, "engagement_id": engagement.engagement_id})
            if nmap_hosts or args.nmap_ipv6:
                result = run_nmap_hosts(args.nmap, scope, nmap_hosts or [scope.root_domain], options, scan_dir, active_acknowledgement=args.acknowledge_active, per_hostname=args.nmap_per_hostname, max_concurrency=int(min(2, engagement.limit("max_concurrency"))) if engagement else 2, ipv6=args.nmap_ipv6)
            else:
                result = run_nmap(args.nmap, scope, scope.root_domain, options, scan_dir, active_acknowledgement=args.acknowledge_active)
            write_json_artifact(scan_dir, "nmap.json", result)
        except (OSError, ValueError, DomainReconError) as exc:
            raise SystemExit(f"Nmap error: {exc}") from exc
        print(scan_dir)
        return 0 if result.get("status") == "success" else 1

    if args.nmap_hosts_file or args.nmap_per_hostname or args.nmap_ipv6:
        parser.error("--nmap-hosts-file, --nmap-per-hostname and --nmap-ipv6 require --nmap-mode")
    if args.acknowledge_active and not args.http_probe:
        parser.error("--acknowledge-active requires --http-probe or --nmap-mode")
    if args.nmap_ports or args.nmap_no_service_detection or args.nmap_max_rate is not None or args.nmap_max_parallelism is not None or args.nmap_timeout is not None:
        parser.error("Nmap-specific options require --nmap-mode")
    if args.nmap_input:
        parser.error("--nmap-input requires --database-discovery")
    if args.acknowledge != "I AM AUTHORIZED":
        parser.error('Passive collection requires --acknowledge "I AM AUTHORIZED"')
    if args.http_probe:
        if not args.dns:
            parser.error("--http-probe requires --dns so only DNSx-validated discovered hosts can be probed")
        if args.hosts_file:
            parser.error("--http-probe cannot use --hosts-file; only same-run passive discoveries may be probed")
        if args.acknowledge_active != "I AUTHORIZE ACTIVE PROBING":
            parser.error('--http-probe requires --acknowledge-active "I AUTHORIZE ACTIVE PROBING"')
        try:
            check_httpx_pinning(args.httpx)
        except (OSError, RuntimeError) as exc:
            parser.error(f"HTTPX security preflight failed: {exc}")
    elif args.acknowledge_active or httpx_explicit:
        parser.error("--acknowledge-active and a custom --httpx path require --http-probe or --nmap-mode")
    if args.hosts_file and not args.dns:
        parser.error("--hosts-file is only valid with --dns")
    supplied_hosts: list[str] | None = None
    if args.dns and args.hosts_file:
        if not args.hosts_file.is_file():
            parser.error("--hosts-file must point to an existing UTF-8 text file")
        try:
            supplied_hosts = scope.filter_hostnames(args.hosts_file.read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeError) as exc:
            parser.error(f"could not read --hosts-file: {exc}")

    started_at = datetime.now(timezone.utc).isoformat()
    overall_started = time.perf_counter()
    try:
        scan_dir = create_scan_directory(args.results, scope.root_domain)
        write_json_artifact(scan_dir, "scan_manifest.json", {"schema_version": 2, "root_domain": scope.root_domain, "passive_only": not args.dns})
        # Authorization decisions are recorded before any source, resolver, or probe is contacted.
        for operation, ack_id in (("passive_enumeration", "PASSIVE_ACK"), *((("dns_resolution", "PASSIVE_ACK"),) if args.dns else ()), *((("httpx_active_probe", "HTTPX_ACK"),) if args.http_probe else ())):
            persist_record(scan_dir, build_record(
                target=scope.root_domain, operation=operation, method=METHOD_COMMAND_LINE, result=GRANTED,
                session_id=session_id, run_id=scan_dir.name, acknowledgement_id=ack_id,
                details={"dns_input": "hosts_file" if supplied_hosts is not None else "passive_results"} if operation == "dns_resolution" else None,
            ))
        if engagement is not None:
            operation_history(args.results, engagement).append({"event": "cli_run", "operations": ["passive_enumeration"] + (["dns_resolution"] if args.dns else []) + (["httpx_active_probe"] if args.http_probe else []), "run_id": scan_dir.name, "session_id": session_id, "engagement_id": engagement.engagement_id})
        passive, source_stats = enumerate_passive_detailed(args.subfinder, scope)
        write_json_artifact(scan_dir, "passive.json", passive)
        dns_records: list[dict] = []
        dns_elapsed = 0.0
        if args.dns:
            passive_hosts = [record["hostname"] for record in passive["records"]]
            dns_hosts = supplied_hosts if supplied_hosts is not None else passive_hosts
            dns_started = time.perf_counter()
            dns_records = collect_dns(args.dnsx, scope, dns_hosts)
            policy_records = collect_dns_policy(args.dnsx, scope, engagement.dkim_selectors if engagement else ())
            dns_elapsed = time.perf_counter() - dns_started
            write_json_artifact(scan_dir, "dns.json", {"root_domain": scope.root_domain, "records": dns_records})
            write_json_artifact(scan_dir, "dns_policy.json", {"root_domain": scope.root_domain, "records": policy_records})
        httpx_records: list[dict] = []
        if args.http_probe:
            httpx_started = time.perf_counter()
            authorization = ActiveAuthorization(scope.root_domain, True, args.acknowledge_active)
            httpx_records = probe_httpx(args.httpx, scope, authorization, passive["records"], dns_records, threads=int(min(2, engagement.limit("max_concurrency"))) if engagement else 2, rate_limit=int(min(2, engagement.limit("requests_per_second"))) if engagement else 2)
            httpx_elapsed = round(time.perf_counter() - httpx_started, 6)
            status_counts: dict[str, int] = {}
            for record in httpx_records:
                classification = str(record.get("classification", "UNKNOWN"))
                status_counts[classification] = status_counts.get(classification, 0) + 1
            inventory = {
                "schema_version": 1,
                "root_domain": scope.root_domain,
                "elapsed_seconds": httpx_elapsed,
                "status_counts": status_counts,
                "records": httpx_records,
            }
            csv_text, readable_text = export_live_inventory(httpx_records)
            write_json_artifact(scan_dir, "live_web_inventory.json", inventory)
            write_text_artifact(scan_dir, "live_web_inventory.csv", csv_text)
            write_text_artifact(scan_dir, "live_web_inventory.txt", readable_text)
        dns_input_source = "hosts_file" if supplied_hosts is not None else "passive_results"
        dns_summary = _dns_summary(dns_records, requested=args.dns, input_source=dns_input_source, elapsed_seconds=dns_elapsed)
        summary = {
            "schema_version": 1,
            "root_domain": scope.root_domain,
            "started_at_utc": started_at,
            "elapsed_seconds": round(time.perf_counter() - overall_started, 6),
            "passive": {
                "status": passive["status"],
                "unique_subdomains": len(passive["records"]),
                "elapsed_seconds": source_stats["elapsed_seconds"],
                "sources": source_stats["sources"],
            },
            "dns": dns_summary,
        }
        extra_hosts = supplied_hosts if supplied_hosts is not None else None
        csv_text, readable_text = _subdomain_exports(passive["records"], dns_records, dns_requested=args.dns, extra_hosts=extra_hosts)
        write_json_artifact(scan_dir, "enumeration_summary.json", summary)
        write_text_artifact(scan_dir, "subdomains.csv", csv_text)
        write_text_artifact(scan_dir, "subdomains.txt", readable_text)
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Passive enumeration/output error: {exc}") from exc
    print(scan_dir)
    source_failed = any(stats["status"] == "failed" for stats in source_stats["sources"].values())
    dns_failed = any(str(record.get("status")) in {"failed", "timeout"} for record in dns_records)
    httpx_failed = any(str(record.get("status")) in {"failed", "timeout", "blocked"} for record in httpx_records)
    return 1 if source_failed or dns_failed or httpx_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
