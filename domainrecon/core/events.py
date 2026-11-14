"""Append-only structured JSONL events for long-running module execution."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def log_event(path: Path, event: str, **fields: Any) -> None:
    record = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "event": event, **fields}
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
