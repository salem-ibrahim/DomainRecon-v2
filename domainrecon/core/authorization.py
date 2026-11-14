"""Structured, immutable authorization audit records.

Every passive or active network operation records who/what/when was authorized
*before* the operation starts. Records never contain the text an operator typed,
credentials, tokens, or secrets: only the identifier of the expected phrase and
whether it matched. Each record is written once as its own JSON artifact and is
never rewritten.
"""
from __future__ import annotations

import getpass
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ArtifactExists
from .storage import write_json_artifact

SCHEMA_ID = "domainrecon.authorization_record"
SCHEMA_VERSION = 1
GRANTED = "granted"
DENIED = "denied"
METHOD_TYPED_PHRASE = "interactive_typed_acknowledgement"
METHOD_SESSION_PASSIVE = "interactive_session_passive_acknowledgement"
METHOD_COMMAND_LINE = "command_line_acknowledgement"
_OPERATION = re.compile(r"^[a-z0-9_]{1,48}$")
_SAFE_DETAIL_TYPES = (str, int, float, bool, type(None))


def new_session_id() -> str:
    return uuid.uuid4().hex


def _operator() -> str | None:
    try:
        return getpass.getuser()[:128]
    except Exception:  # noqa: BLE001 - account lookup is best-effort metadata only
        return None


def _safe_details(details: dict[str, Any] | None) -> dict[str, Any]:
    if not details:
        return {}
    clean: dict[str, Any] = {}
    for key, value in details.items():
        if not isinstance(key, str) or any(word in key.casefold() for word in ("password", "secret", "token", "credential", "key", "phrase", "typed")):
            continue
        if isinstance(value, _SAFE_DETAIL_TYPES):
            clean[key] = value[:256] if isinstance(value, str) else value
        elif isinstance(value, (list, tuple)) and all(isinstance(item, _SAFE_DETAIL_TYPES) for item in value):
            clean[key] = [item[:256] if isinstance(item, str) else item for item in list(value)[:1000]]
    return clean


def build_record(
    *, target: str, operation: str, method: str, result: str, session_id: str, run_id: str | None,
    acknowledgement_id: str | None = None, details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not _OPERATION.fullmatch(operation):
        raise ValueError("Authorization operation must be a short lower-case identifier.")
    if result not in {GRANTED, DENIED}:
        raise ValueError("Authorization result must be granted or denied.")
    return {
        "schema_id": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "record_id": uuid.uuid4().hex,
        "session_id": session_id,
        "run_id": run_id,
        "target": target,
        "operation": operation,
        "authorization_method": method,
        "acknowledgement_id": acknowledgement_id,
        "result": result,
        "authorized_at_utc": datetime.now(timezone.utc).isoformat(),
        "operator_account": _operator(),
        "details": _safe_details(details),
        "note": "The typed acknowledgement text is never stored; only whether it matched the required phrase.",
    }


def persist_record(directory: Path, record: dict[str, Any]) -> Path:
    """Write one record as a new immutable artifact; never overwrite an existing record."""
    for index in range(1, 1000):
        if any(directory.glob(f"authorization-{index:03d}-*.json")):
            continue  # sequence numbers are global per run so records sort chronologically
        name = f"authorization-{index:03d}-{record['operation']}.json"
        try:
            return write_json_artifact(directory, name, record)
        except ArtifactExists:
            continue
    raise ArtifactExists(f"Could not allocate an authorization record name in {directory}")


class AuthorizationLedger:
    """Collects records for one interactive session; writes them into the active run directory."""

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id = session_id or new_session_id()
        self.history: list[dict[str, Any]] = []
        self._pending: list[dict[str, Any]] = []

    def record(
        self, *, target: str, operation: str, method: str, result: str, run_directory: Path | None,
        acknowledgement_id: str | None = None, details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = build_record(
            target=target, operation=operation, method=method, result=result, session_id=self.session_id,
            run_id=run_directory.name if run_directory else None, acknowledgement_id=acknowledgement_id, details=details,
        )
        self.history.append(record)
        if run_directory is None:
            # A denied request must not create a run directory; keep it until a run exists.
            self._pending.append(record)
        else:
            persist_record(run_directory, record)
        return record

    def attach(self, run_directory: Path) -> None:
        """Persist records captured before the run directory existed (same target only)."""
        pending, self._pending = self._pending, []
        for record in pending:
            persist_record(run_directory, {**record, "run_id": run_directory.name, "recorded_before_run_directory_existed": True})

    def reset_pending(self) -> None:
        """Drop unpersisted records when the target changes; they stay in memory history."""
        self._pending = []
