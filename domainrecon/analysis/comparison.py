"""Conservative snapshot comparison: failures are unknown, never removals.

DEPRECATED compatibility helper (retained, not used by any DomainRecon workflow). Superseded by
``domainrecon.intelligence.change_detection.compare_runs`` (per-host NOT_OBSERVED / SOURCE_FAILED /
INSUFFICIENT_DATA / CONFIRMED_REMOVED statuses). Kept for existing imports and its regression test;
scheduled for removal in the next major version.
"""
from __future__ import annotations

from typing import Any


def _index(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {record["hostname"]: record for record in records if isinstance(record, dict) and isinstance(record.get("hostname"), str)}


def _successful(record: dict[str, Any] | None) -> bool:
    return bool(record) and record.get("status") == "success"


def compare_snapshots(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Return confirmed deltas and explicit unknowns for incomplete observations."""
    previous_hosts = _index(previous.get("hosts", []))
    current_hosts = _index(current.get("hosts", []))
    current_complete = current.get("enumeration_status") == "success"
    added = sorted(set(current_hosts) - set(previous_hosts))
    absent = sorted(set(previous_hosts) - set(current_hosts))
    removed = absent if current_complete else []
    unknown_removed = [] if current_complete else absent
    changes: dict[str, list[dict[str, Any]]] = {"dns": [], "ip": [], "http": [], "tls": []}
    for host in sorted(set(previous_hosts) & set(current_hosts)):
        old, new = previous_hosts[host], current_hosts[host]
        for key, category in (("dns", "dns"), ("ips", "ip"), ("http", "http"), ("tls", "tls")):
            old_value, new_value = old.get(key), new.get(key)
            if old_value is None or new_value is None:
                continue
            if isinstance(old_value, dict) and isinstance(new_value, dict) and not (_successful(old_value) and _successful(new_value)):
                continue
            if old_value != new_value:
                changes[category].append({"hostname": host, "before": old_value, "after": new_value})
    return {"new_assets": added, "removed_assets": removed, "unknown_removed_assets": unknown_removed, "changes": changes}
