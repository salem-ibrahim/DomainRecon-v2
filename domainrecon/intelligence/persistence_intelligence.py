"""Offline persistence indicator analyzer for imported evidence; never executes endpoint actions."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_ID = "domainrecon.persistence_evidence"
SCHEMA_VERSION = 1
_MAX_BYTES = 10_000_000
_MAX_EVENTS = 50_000
_MAX_TEXT = 4096
_ATTACK = {
    "windows_service": ("T1543.003", "Create or Modify System Process: Windows Service"),
    "scheduled_task": ("T1053.005", "Scheduled Task"),
    "registry_run_key": ("T1547.001", "Registry Run Keys / Startup Folder"),
    "linux_cron": ("T1053.003", "Cron"),
    "linux_systemd": ("T1543.002", "Systemd Service"),
    "ssh_authorized_keys": ("T1098.004", "SSH Authorized Keys"),
}


def _get_path(obj: dict[str, Any], path: str) -> Any:
    current: Any = obj
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


_EVENT_ID_PATHS = ("event_id", "EventID", "eventId", "EventId", "data.win.system.eventID", "win.system.eventID", "System.EventID", "Event.System.EventID", "winlog.event_id", "event.code")
_SYSTEMD_UNIT_PATH = re.compile(r"(?:/etc/systemd/(?:system|user)/|/usr/lib/systemd/(?:system|user)/|/lib/systemd/system/|/run/systemd/system/|\.config/systemd/user/)[^\s\"']*\.(?:service|timer|socket|path)")
_SYSTEMD_WRITE_CONTEXT = re.compile(
    r"nametype\W*create|created symlink|systemctl\W+(?:enable|link|edit|daemon-reload)|\bunit file\b.*\b(?:created|modified|written)\b"
    r"|\"?(?:syscheck|fim)\b|\b(?:file|unit)[ _-]?(?:added|created|modified|written)\b|\bevent\W+(?:added|modified)\b"
    r"|\bop\W*(?:create|write|rename)\b|\bsyscall\W*(?:creat|rename|renameat2?|link|linkat|symlink|symlinkat)\b",
    re.IGNORECASE,
)
# Matches Run/RunOnce keys and Startup folders whether backslashes are single (raw) or doubled (JSON-escaped).
_RUN_KEY = re.compile(r"(?i)\\+software\\+(?:wow6432node\\+)?microsoft\\+windows\\+currentversion\\+run(?:once)?(?:\\+|\"|\b)|\\+start menu\\+programs\\+startup\\+")
_ROUTINE_SERVICE_MESSAGE =re.compile(r"\b(?:Started|Starting|Stopped|Stopping|Reloaded|Reloading|Finished|Deactivated|Succeeded|Failed)\b[^\n]*\.service", re.IGNORECASE)


def _windows_event_id(raw: dict[str, Any]) -> str | None:
    """Return the Windows/Sysmon event ID; a Wazuh ``rule.id`` is never treated as an event ID."""
    for path in _EVENT_ID_PATHS:
        value = _get_path(raw, path) if "." in path else raw.get(path)
        if isinstance(value, dict):
            value = value.get("#text") or value.get("value")
        if value not in (None, "") and not isinstance(value, (dict, list, bool)):
            return str(value).strip()
    return None


def _normalize_event(raw: dict[str, Any], source: str, line: int) -> dict[str, Any]:
    system = raw.get("system", {}) if isinstance(raw.get("system"), dict) else {}
    event_id = _windows_event_id(raw)
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    wazuh_rule_id = str(rule.get("id")) if rule.get("id") not in (None, "") else None
    full_text = json.dumps(raw, ensure_ascii=False, sort_keys=True)
    lower = full_text.casefold()
    platform = str(raw.get("platform", "windows" if event_id in {"7045", "4697", "4698", "4702", "4657", "12", "13", "14"} or "windows" in lower or "microsoft-windows" in lower else "linux" if any(x in lower for x in ("systemd", "cron", "authorized_keys", "type=path", "audit(")) else "unknown")).casefold()
    host = next((value for value in (
        raw.get("host"), raw.get("hostname"), raw.get("computer"), raw.get("Computer"), raw.get("MachineName"),
        _get_path(raw, "agent.name"), system.get("computer"), _get_path(raw, "win.system.computer"),
        _get_path(raw, "data.win.system.computer"), _get_path(raw, "System.Computer"), _get_path(raw, "host.name"),
    ) if isinstance(value, str) and value.strip()), None)
    timestamp = raw.get("timestamp", raw.get("@timestamp", raw.get("timeCreated", system.get("timeCreated") or _get_path(raw, "win.system.timeCreated"))))
    description = str(raw.get("description", raw.get("message", raw.get("full_log", raw.get("command_line", "")))))
    category = None
    if event_id in {"7045", "4697"}:
        category = "windows_service"
    elif event_id in {"4698", "4702"} or (event_id in {"106", "140"} and "taskscheduler" in lower):
        # 106/140 are only Task Scheduler events when the TaskScheduler provider/channel is present.
        category = "scheduled_task"
    elif event_id in {"4657", "12", "13", "14"} and _RUN_KEY.search(full_text):
        category = "registry_run_key"
    elif platform == "linux":
        paths = re.findall(r"(?:name|path|file|object|exe)=\"?([^\s\"]+)", full_text, re.I)
        candidates = " ".join(paths + [description, full_text]).casefold()
        if re.search(r"(?:/etc/cron\.|/etc/cron/|/etc/crontab|/var/spool/cron|/var/spool/at/)", candidates):
            category = "linux_cron"
        elif _SYSTEMD_UNIT_PATH.search(candidates) and _SYSTEMD_WRITE_CONTEXT.search(candidates):
            # A unit file path alone, or a routine "Started x.service" message, is not persistence evidence;
            # require evidence that a unit file was created, enabled, or modified.
            category = "linux_systemd"
        elif re.search(r"(?:\.ssh/authorized_keys|authorized_keys)", candidates):
            category = "ssh_authorized_keys"
    routine = bool(_ROUTINE_SERVICE_MESSAGE.search(description)) and category is None
    return {"source_artifact": source, "source_line": line, "raw_record": raw, "host": str(host)[:256] if host else None, "timestamp": str(timestamp)[:128] if timestamp else None, "event_id": event_id, "wazuh_rule_id": wazuh_rule_id, "platform": platform, "description": description[:_MAX_TEXT], "category": category, "routine_service_message": routine}


def _load(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
    """Parse evidence from one byte snapshot; malformed JSONL records are isolated and reported."""
    if not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")
    if path.stat().st_size > _MAX_BYTES:
        raise ValueError("Evidence file exceeds the 10 MB offline-analysis limit.")
    raw_bytes = path.read_bytes()
    if len(raw_bytes) > _MAX_BYTES:
        raise ValueError("Evidence file exceeds the 10 MB offline-analysis limit.")
    digest = hashlib.sha256(raw_bytes).hexdigest()  # hash and parse the same bytes
    try:
        data = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Evidence file is not valid UTF-8: {exc}") from exc
    suffix = path.suffix.casefold()
    rows: list[tuple[int, Any]] = []
    errors: list[dict[str, Any]] = []
    if suffix == ".csv":
        rows = [(index, row) for index, row in enumerate(csv.DictReader(io.StringIO(data)), 2)]
    elif suffix in {".jsonl", ".ndjson"}:
        for index, line in enumerate(data.splitlines(), 1):
            if not line.strip():
                continue
            try:
                rows.append((index, json.loads(line)))
            except json.JSONDecodeError as exc:
                errors.append({"line": index, "error": "invalid_json", "detail": f"{exc.msg} at column {exc.colno}", "length": len(line)})
            if len(rows) + len(errors) > _MAX_EVENTS:
                raise ValueError("Evidence file exceeds the 50,000-event limit.")
    else:
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Evidence file is not valid JSON ({exc.msg} at line {exc.lineno}); use .jsonl for per-line isolation.") from exc
        rows = list(enumerate(parsed if isinstance(parsed, list) else [parsed], 1))
    if len(rows) > _MAX_EVENTS:
        raise ValueError("Evidence file exceeds the 50,000-event limit.")
    events = []
    for index, row in rows:
        if not isinstance(row, dict):
            errors.append({"line": index, "error": "record_not_object"})
            continue
        events.append(_normalize_event(row, path.name, index))
    errors.sort(key=lambda item: item["line"])
    return events, errors, digest


def analyze_persistence_evidence(path: Path, *, source_label: str, generated_at: str | None = None) -> dict[str, Any]:
    """Parse a local export, detect event-shaped indicators, and retain precise provenance."""
    if not isinstance(source_label, str) or not source_label.strip():
        raise ValueError("Evidence source label is required.")
    events, errors, digest = _load(path)
    findings = []
    for event in events:
        category = event["category"]
        if category not in _ATTACK:
            continue
        technique_id, technique_name = _ATTACK[category]
        ev = {key: event[key] for key in ("source_artifact", "source_line", "event_id", "wazuh_rule_id", "platform", "description")}
        if event["host"]:
            ev["host"] = event["host"]
        identifier = hashlib.sha256(f"{digest}:{event['source_line']}:{category}".encode()).hexdigest()[:16]
        findings.append({"finding_id": "persist-" + identifier, "event_timestamp": event["timestamp"], "host": event["host"], "event_source": source_label.strip()[:256], "event_identifier": event["event_id"], "persistence_category": category, "evidence": ev, "confidence": {"level": "medium" if event["event_id"] else "low", "rationale": "A persistence-related event/path was observed in an imported record; execution, malicious intent, and persistence success are not inferred."}, "severity": {"level": "medium", "rationale": "Triage priority only; business criticality and authorization context were not supplied."}, "mitre_attack": {"tactic_id": "TA0003", "tactic_name": "Persistence", "technique_id": technique_id, "technique_name": technique_name, "reference_version": "ATT&CK Enterprise technique identifiers as documented on 2026-11-12"}, "recommended_investigation": ["Validate the source record and collection integrity.", "Confirm whether the change was authorized with the host owner.", "Review surrounding audit events and current configuration using approved endpoint procedures; this analyzer does not access endpoints."]})
    status = "partial" if errors else "success"
    routine = sum(1 for event in events if event.get("routine_service_message"))
    return {"schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": generated_at or datetime.now(timezone.utc).isoformat(), "status": status, "source": {"label": source_label.strip()[:256], "filename": path.name, "sha256": digest, "format": path.suffix.casefold()}, "events_reviewed": len(events), "routine_service_messages_ignored": routine, "invalid_records": len(errors), "findings": findings, "errors": errors, "limitations": ["Imported evidence only; no endpoint access or command execution occurs.", "Events indicate a lead for review, not confirmed malicious persistence or compromise.", "No event observed is not evidence that persistence is absent."]}
