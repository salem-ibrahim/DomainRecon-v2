"""Conservative offline change detection over immutable run artifacts."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

SCHEMA_ID = "domainrecon.change_report"
SCHEMA_VERSION = 1


def _index(rows: Any, key: str) -> dict[str, dict[str, Any]]:
    if not isinstance(rows, list):
        return {}
    return {str(row[key]).casefold(): row for row in rows if isinstance(row, dict) and isinstance(row.get(key), str)}


def _stage_available(run: dict[str, Any], stage: str, artifact_key: str) -> bool:
    payload = run.get(artifact_key)
    if not isinstance(payload, dict):
        return False
    status = str(payload.get("status", "success" if artifact_key in run else "")).lower()
    return status == "success" and payload.get("available", True) is not False


def _ip_addresses(row: dict[str, Any]) -> set[str]:
    raw = row.get("records", {})
    if not isinstance(raw, dict):
        return set()
    result: set[str] = set()
    for key in ("a", "aaaa"):
        values = raw.get(key, [])
        for value in ([values] if isinstance(values, str) else values if isinstance(values, list) else []):
            if isinstance(value, str):
                result.add(value)
    return result


def _nmap_services(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    services: dict[str, dict[str, Any]] = {}
    for host in payload.get("hosts", []) if isinstance(payload.get("hosts", []), list) else []:
        if not isinstance(host, dict):
            continue
        address = host.get("address")
        if not isinstance(address, str):
            continue
        for port in host.get("ports", []) if isinstance(host.get("ports", []), list) else []:
            if not isinstance(port, dict) or port.get("state") != "open":
                continue
            number = port.get("port")
            proto = port.get("protocol", "tcp")
            if not isinstance(number, int):
                continue
            key = f"{address}/{proto}/{number}"
            services[key] = {field: port.get(field) for field in ("state", "service", "product", "version", "cpes") if field in port}
    return services


def _change(kind: str, asset: str, before: Any, after: Any, prev_id: str, cur_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    raw = f"{prev_id}|{cur_id}|{kind}|{asset}|{before!r}|{after!r}".encode("utf-8")
    return {"change_id": hashlib.sha256(raw).hexdigest()[:20], "change_type": kind, "asset_identifier": asset, "previous_run_id": prev_id, "current_run_id": cur_id, "before": before, "after": after, "evidence": evidence, "timestamp": datetime.now(timezone.utc).isoformat()}


def compare_runs(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Compare run snapshots; only successful observations can prove removals."""
    root_prev = previous.get("root_domain", previous.get("target"))
    root_cur = current.get("root_domain", current.get("target"))
    if not isinstance(root_prev, str) or root_prev != root_cur:
        raise ValueError("Historical comparison requires the same root domain.")
    prev_id = str(previous.get("run_id", "previous"))
    cur_id = str(current.get("run_id", "current"))
    changes: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    prev_pass = previous.get("passive") or {}
    cur_pass = current.get("passive") or {}
    prev_hosts = _index(prev_pass.get("records"), "hostname")
    cur_hosts = _index(cur_pass.get("records"), "hostname")
    prev_dns = _index((previous.get("dns") or {}).get("records"), "hostname")
    cur_dns = _index((current.get("dns") or {}).get("records"), "hostname")
    passive_comparable = _stage_available(previous, "passive", "passive") and _stage_available(current, "passive", "passive")
    if passive_comparable:
        for host in sorted(cur_hosts.keys() - prev_hosts.keys()):
            changes.append(_change("subdomain_added", host, None, cur_hosts[host], prev_id, cur_id, {"stage": "passive"}))
    else:
        unknown.append({"stage": "passive", "reason": "Both runs need successful passive enumeration before additions can be confirmed; absences are classified per host."})
    asset_status = _passive_asset_status(previous, current, prev_hosts, cur_hosts, prev_dns, cur_dns)
    for row in asset_status:
        if row["status"] == CONFIRMED_REMOVED:
            changes.append(_change("subdomain_removed", row["hostname"], prev_hosts[row["hostname"]], None, prev_id, cur_id, {"stage": "dns", "basis": row["reason"], "evidence": row["evidence"]}))
    dns_comparable = _stage_available(previous, "dns", "dns") and _stage_available(current, "dns", "dns")
    if dns_comparable:
        for host in sorted(prev_dns.keys() & cur_dns.keys()):
            if prev_dns[host].get("status") == cur_dns[host].get("status") == "success":
                old, new = prev_dns[host].get("records", {}), cur_dns[host].get("records", {})
                if old != new:
                    changes.append(_change("dns_records_changed", host, old, new, prev_id, cur_id, {"stage": "dns", "previous_artifact": "dns.json", "current_artifact": "dns.json"}))
                old_ips, new_ips = _ip_addresses(prev_dns[host]), _ip_addresses(cur_dns[host])
                for ip in sorted(new_ips - old_ips):
                    changes.append(_change("ip_association_added", host, None, ip, prev_id, cur_id, {"stage": "dns", "record_type": "A_or_AAAA"}))
                for ip in sorted(old_ips - new_ips):
                    changes.append(_change("ip_association_removed", host, ip, None, prev_id, cur_id, {"stage": "dns", "record_type": "A_or_AAAA"}))
            elif prev_dns[host].get("status") != cur_dns[host].get("status"):
                changes.append(_change("dns_status_changed", host, prev_dns[host].get("status"), cur_dns[host].get("status"), prev_id, cur_id, {"stage": "dns"}))
    else:
        unknown.append({"stage": "dns", "reason": "DNS was not successfully observed in both runs; no DNS removals inferred."})
    for stage, artifact_key, rows_key in (("http", "http", "records"), ("nmap", "nmap", "hosts"), ("database", "database", "inventory"), ("vulnerability", "vulnerability", "findings")):
        old_payload, new_payload = previous.get(artifact_key), current.get(artifact_key)
        comparable = _stage_available(previous, stage, artifact_key) and _stage_available(current, stage, artifact_key)
        if not comparable:
            unknown.append({"stage": stage, "reason": f"{stage} data is unavailable or incomplete in one or both runs; removals are unknown."})
            continue
        if stage == "nmap":
            old_rows = _nmap_services(old_payload)
            new_rows = _nmap_services(new_payload)
        elif stage == "database":
            old_rows = _index(old_payload.get(rows_key), "finding_id")
            new_rows = _index(new_payload.get(rows_key), "finding_id")
        else:
            old_rows = _index(old_payload.get(rows_key), "url" if stage == "http" else "finding_id")
            new_rows = _index(new_payload.get(rows_key), "url" if stage == "http" else "finding_id")
        for identity in sorted(new_rows.keys() - old_rows.keys()):
            changes.append(_change(f"{stage}_observation_added", identity, None, new_rows[identity], prev_id, cur_id, {"stage": stage}))
        for identity in sorted(old_rows.keys() - new_rows.keys()):
            changes.append(_change(f"{stage}_observation_removed", identity, old_rows[identity], None, prev_id, cur_id, {"stage": stage}))
        for identity in sorted(old_rows.keys() & new_rows.keys()):
            if old_rows[identity] != new_rows[identity]:
                changes.append(_change(f"{stage}_observation_changed", identity, old_rows[identity], new_rows[identity], prev_id, cur_id, {"stage": stage}))
    status_counts = {status: sum(1 for row in asset_status if row["status"] == status) for status in ASSET_STATUSES}
    return {
        "schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "root_domain": root_cur, "previous_run_id": prev_id, "current_run_id": cur_id,
        "generated_at": datetime.now(timezone.utc).isoformat(), "changes": changes, "unknown_comparisons": unknown,
        "asset_status": asset_status, "asset_status_counts": status_counts,
        "limitations": [
            "Passive sources are incomplete by nature: a name missing from a later passive run is NOT_OBSERVED, never removed.",
            "CONFIRMED_REMOVED requires DNS evidence: the name resolved successfully in the previous run and returned no records in the current run's DNS query.",
            "Previous observations are preserved verbatim in previous_observation for every status.",
        ],
    }


CONFIRMED_REMOVED = "CONFIRMED_REMOVED"
NOT_OBSERVED = "NOT_OBSERVED"
SOURCE_FAILED = "SOURCE_FAILED"
INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
STILL_PRESENT = "STILL_PRESENT"
ASSET_STATUSES = (CONFIRMED_REMOVED, NOT_OBSERVED, SOURCE_FAILED, INSUFFICIENT_DATA, STILL_PRESENT)


def _source_label(value: Any) -> str:
    text = str(value).strip().casefold()
    return "crtsh" if text in {"crt.sh", "crtsh"} else text


def _source_outcomes(run: dict[str, Any]) -> dict[str, str] | None:
    """Per-source status for a run, from passive_sources / an enumeration summary when available."""
    raw = run.get("passive_sources")
    if not isinstance(raw, dict):
        return None
    outcomes: dict[str, str] = {}
    for name, stats in raw.items():
        status = stats.get("status") if isinstance(stats, dict) else stats
        outcomes[_source_label(name)] = "success" if str(status).casefold() == "success" else "failed"
    return outcomes


def _passive_asset_status(
    previous: dict[str, Any], current: dict[str, Any], prev_hosts: dict[str, dict[str, Any]], cur_hosts: dict[str, dict[str, Any]],
    prev_dns: dict[str, dict[str, Any]], cur_dns: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Classify every previously observed hostname without ever equating passive absence with removal."""
    cur_pass = current.get("passive") if isinstance(current.get("passive"), dict) else None
    current_success = _stage_available(current, "passive", "passive")
    outcomes = _source_outcomes(current)
    errors = cur_pass.get("errors", []) if cur_pass else []
    observed_sources = {_source_label(source) for row in cur_hosts.values() for source in (row.get("sources") or []) if isinstance(row.get("sources"), list)}
    dns_both = _stage_available(previous, "dns", "dns") or bool(prev_dns)
    rows: list[dict[str, Any]] = []
    for host in sorted(prev_hosts):
        previous_row = prev_hosts[host]
        previous_sources = sorted({_source_label(source) for source in previous_row.get("sources", []) if isinstance(source, str)}) if isinstance(previous_row.get("sources"), list) else []
        evidence: dict[str, Any] = {"previous_sources": previous_sources}
        if host in cur_hosts:
            status, reason = STILL_PRESENT, "Observed again by passive enumeration in the current run."
            evidence["current_sources"] = cur_hosts[host].get("sources", [])
        elif cur_pass is None:
            status, reason = INSUFFICIENT_DATA, "The current run has no passive enumeration artifact."
        elif (cur_dns.get(host) or {}).get("status") == "unresolved" and (prev_dns.get(host) or {}).get("status") == "success" and dns_both:
            status, reason = CONFIRMED_REMOVED, "The name resolved in the previous run and the current DNS query returned no records."
            evidence["previous_dns"] = prev_dns[host].get("records")
            evidence["current_dns_status"] = "unresolved"
        elif not current_success:
            status, reason = SOURCE_FAILED if errors else INSUFFICIENT_DATA, "Current passive enumeration did not complete successfully."
            evidence["current_errors"] = errors
        elif outcomes is not None:
            failed = sorted(source for source in previous_sources if outcomes.get(source) == "failed")
            missing = sorted(source for source in previous_sources if source not in outcomes)
            if failed:
                status, reason = SOURCE_FAILED, "A source that previously reported this name failed in the current run: " + ", ".join(failed)
            elif missing or not previous_sources:
                status, reason = INSUFFICIENT_DATA, "The source(s) that previously reported this name were not queried in the current run: " + (", ".join(missing) or "unknown")
            else:
                status, reason = NOT_OBSERVED, "All sources that previously reported this name succeeded but did not return it; this is not proof of removal."
            evidence["current_source_status"] = outcomes
        elif errors:
            status, reason = SOURCE_FAILED, "At least one passive source failed in the current run."
            evidence["current_errors"] = errors
        elif not previous_sources or not set(previous_sources) <= observed_sources:
            status, reason = INSUFFICIENT_DATA, "Per-source results are unavailable and the previous source(s) did not report any name in the current run."
        else:
            status, reason = NOT_OBSERVED, "Not returned by the current passive sources; this is not proof of removal."
        rows.append({"hostname": host, "status": status, "reason": reason, "previous_observation": previous_row, "evidence": evidence})
    return rows
