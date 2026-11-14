"""Small, dependency-free, JSON-safe v2 data models."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class ObservationStatus(StrEnum):
    NOT_RUN = "not_run"
    SUCCESS = "success"
    UNRESOLVED = "unresolved"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"
    FAILED = "failed"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ActiveAuthorization:
    root_domain: str
    approved: bool = False
    acknowledgement: str = ""

    def is_valid(self) -> bool:
        return self.approved and self.acknowledgement == "I AUTHORIZE ACTIVE PROBING"


@dataclass(frozen=True)
class HostRecord:
    hostname: str
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class ArtifactStatus:
    status: ObservationStatus
    error: str | None = None


@dataclass
class ScanManifest:
    schema_version: int
    scan_id: str
    root_domain: str
    started_at: str
    passive_only: bool = True
    stages: dict[str, dict[str, Any]] = field(default_factory=dict)
    tool_versions: dict[str, str] = field(default_factory=dict)

    @classmethod
    def new(cls, scan_id: str, root_domain: str) -> "ScanManifest":
        return cls(2, scan_id, root_domain, utc_now())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
