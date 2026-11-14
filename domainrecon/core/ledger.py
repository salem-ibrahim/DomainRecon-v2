"""Append-only, hash-chained JSONL ledgers (operation history, findings lifecycle).

Each line stores ``previous_hash`` and its own ``entry_hash`` (SHA-256 over the canonical entry
without ``entry_hash``). Lines are only ever appended; ``verify`` detects edits, deletions, and
reordering. The ledger is tamper-evident, not tamper-proof.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(entry: dict[str, Any]) -> str:
    body = {key: value for key, value in entry.items() if key != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


class HashChainLedger:
    def __init__(self, path: Path) -> None:
        self.path = path

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        rows: list[dict[str, Any]] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existing = self.entries()
        previous = existing[-1]["entry_hash"] if existing else GENESIS
        entry = {**event, "sequence": len(existing) + 1, "recorded_at_utc": datetime.now(timezone.utc).isoformat(), "previous_hash": previous}
        entry["entry_hash"] = _digest(entry)
        with self.path.open("a", encoding="utf-8", newline="") as handle:
            handle.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
        return entry

    def verify(self) -> dict[str, Any]:
        previous = GENESIS
        try:
            rows = self.entries()
        except json.JSONDecodeError as exc:
            return {"valid": False, "entries": 0, "error": f"unparseable ledger line: {exc}"}
        for index, entry in enumerate(rows, 1):
            if entry.get("sequence") != index or entry.get("previous_hash") != previous or entry.get("entry_hash") != _digest(entry):
                return {"valid": False, "entries": len(rows), "error": f"chain broken at entry {index}"}
            previous = entry["entry_hash"]
        return {"valid": True, "entries": len(rows), "head": previous}
