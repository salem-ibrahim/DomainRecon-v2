"""Findings lifecycle and retesting on an append-only, hash-chained ledger per target.

Statuses: NEW, CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, REMEDIATED, RETEST_REQUIRED, CLOSED.
Nothing is ever overwritten: observations, status changes, notes and retest results are appended
as events, and the current state is derived by replaying them. Closure requires a retest.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from domainrecon.core.ledger import HashChainLedger
from domainrecon.core.storage import write_json_artifact

STATUSES = ("NEW", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "REMEDIATED", "RETEST_REQUIRED", "CLOSED")
TRANSITIONS: dict[str, set[str]] = {
    "NEW": {"CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RETEST_REQUIRED"},
    "CONFIRMED": {"ACCEPTED_RISK", "REMEDIATED", "FALSE_POSITIVE"},
    "REMEDIATED": {"RETEST_REQUIRED"},
    "RETEST_REQUIRED": set(),  # leaves only through a recorded retest result
    "ACCEPTED_RISK": {"CONFIRMED", "CLOSED"},
    "FALSE_POSITIVE": {"NEW", "CLOSED"},
    "CLOSED": set(),  # reopens automatically if observed again
}
RETEST_RESULTS = {"still_present": "CONFIRMED", "not_observed": "CLOSED", "inconclusive": "RETEST_REQUIRED"}


class FindingsRegistry:
    def __init__(self, results_root: Path, target: str) -> None:
        self.directory = results_root / target / "findings_registry"
        self.ledger = HashChainLedger(self.directory / "lifecycle.jsonl")
        self.target = target

    def state(self) -> dict[str, dict[str, Any]]:
        findings: dict[str, dict[str, Any]] = {}
        for event in self.ledger.entries():
            fid = event["finding_id"]
            row = findings.setdefault(fid, {"finding_id": fid, "status": "NEW", "first_detected": event["recorded_at_utc"], "last_observed": None, "status_history": [], "evidence_history": [], "notes": [], "retests": []})
            kind = event["event"]
            if kind == "observed":
                row["last_observed"] = event["recorded_at_utc"]
                row["title"], row["severity"], row["asset_id"] = event.get("title"), event.get("severity"), event.get("asset_id")
                row["evidence_history"].append({"run_id": event.get("run_id"), "at": event["recorded_at_utc"], "evidence_references": event.get("evidence_references", [])})
                if row["status"] == "CLOSED":
                    row["status"] = "NEW"
                    row["status_history"].append({"status": "NEW", "at": event["recorded_at_utc"], "reason": "re-observed after closure (regression)"})
                elif not row["status_history"]:
                    row["status_history"].append({"status": "NEW", "at": event["recorded_at_utc"], "reason": "first detected"})
            elif kind == "status_change":
                row["status"] = event["to_status"]
                row["status_history"].append({"status": event["to_status"], "at": event["recorded_at_utc"], "reason": event.get("note"), "actor": event.get("actor")})
            elif kind == "note":
                row["notes"].append({"at": event["recorded_at_utc"], "note": event.get("note"), "actor": event.get("actor")})
            elif kind == "retest":
                row["retests"].append({"at": event["recorded_at_utc"], "result": event["result"], "evidence": event.get("evidence"), "run_id": event.get("run_id")})
                row["status"] = RETEST_RESULTS[event["result"]]
                row["status_history"].append({"status": row["status"], "at": event["recorded_at_utc"], "reason": f"retest: {event['result']}"})
        return findings

    def sync(self, canonical_findings: list[dict[str, Any]], *, run_id: str) -> dict[str, int]:
        before = self.state()
        counts = {"new": 0, "re_observed": 0, "reopened": 0}
        for finding in canonical_findings:
            fid = finding["finding_id"]
            previous = before.get(fid)
            counts["new" if previous is None else "reopened" if previous["status"] == "CLOSED" else "re_observed"] += 1
            self.ledger.append({"event": "observed", "finding_id": fid, "run_id": run_id, "title": finding.get("title"), "severity": finding.get("severity"), "asset_id": finding.get("asset_id"),
                                "evidence_references": finding.get("evidence_references", [])[:20]})
        return counts

    def set_status(self, finding_id: str, to_status: str, *, note: str, actor: str = "operator") -> dict[str, Any]:
        current = self.state().get(finding_id)
        if current is None:
            raise KeyError(f"Unknown finding {finding_id}")
        if to_status not in STATUSES or to_status not in TRANSITIONS[current["status"]]:
            raise ValueError(f"Transition {current['status']} -> {to_status} is not allowed; allowed: {sorted(TRANSITIONS[current['status']]) or 'retest only'}")
        if not note.strip():
            raise ValueError("A note is required for every status change.")
        return self.ledger.append({"event": "status_change", "finding_id": finding_id, "from_status": current["status"], "to_status": to_status, "note": note.strip()[:2000], "actor": actor[:120]})

    def add_note(self, finding_id: str, note: str, *, actor: str = "operator") -> dict[str, Any]:
        if finding_id not in self.state():
            raise KeyError(f"Unknown finding {finding_id}")
        return self.ledger.append({"event": "note", "finding_id": finding_id, "note": note.strip()[:2000], "actor": actor[:120]})

    def record_retest(self, finding_id: str, result: str, *, evidence: str, run_id: str | None = None) -> dict[str, Any]:
        current = self.state().get(finding_id)
        if current is None:
            raise KeyError(f"Unknown finding {finding_id}")
        if current["status"] != "RETEST_REQUIRED":
            raise ValueError("A retest can only be recorded for findings in RETEST_REQUIRED status.")
        if result not in RETEST_RESULTS:
            raise ValueError(f"Retest result must be one of {sorted(RETEST_RESULTS)}.")
        return self.ledger.append({"event": "retest", "finding_id": finding_id, "result": result, "evidence": evidence.strip()[:2000], "run_id": run_id})

    def snapshot(self, directory: Path) -> Path:
        """Write an immutable point-in-time export of the lifecycle state."""
        state = self.state()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        payload = {"schema_id": "domainrecon.findings_lifecycle", "schema_version": 1, "target": self.target, "generated_at": datetime.now(timezone.utc).isoformat(), "status": "success",
                   "ledger_integrity": self.ledger.verify(), "status_counts": {s: sum(1 for f in state.values() if f["status"] == s) for s in STATUSES},
                   "findings": [], "lifecycle": sorted(state.values(), key=lambda row: row["finding_id"])}
        return write_json_artifact(directory, f"findings_lifecycle-{stamp}.json", json.loads(json.dumps(payload, default=str)))
