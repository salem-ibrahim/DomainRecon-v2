"""Immutable result storage and read-only v1 compatibility imports."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .errors import ArtifactExists
from .scope import ScopePolicy


def _atomic_create(path: Path, content: str) -> None:
    if path.exists():
        raise ArtifactExists(f"Artifact already exists: {path}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    if temporary.exists():
        raise ArtifactExists(f"Temporary artifact already exists: {temporary}")
    temporary.write_text(content, encoding="utf-8", newline="")
    try:
        # Link creation is atomic and refuses an existing target on NTFS.
        os.link(temporary, path)
    except FileExistsError as exc:
        raise ArtifactExists(f"Artifact already exists: {path}") from exc
    finally:
        temporary.unlink(missing_ok=True)


def create_scan_directory(results_root: Path, root_domain: str) -> Path:
    scope = ScopePolicy(root_domain)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parent = results_root / scope.root_domain
    for index in range(1000):
        name = stamp if index == 0 else f"{stamp}-{index:02d}"
        candidate = parent / name
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            continue
    raise ArtifactExists(f"Could not allocate a scan directory below {parent}")


def write_json_artifact(scan_directory: Path, filename: str, data: Any) -> Path:
    if Path(filename).name != filename or not filename.endswith(".json"):
        raise ValueError("Artifact filename must be a simple .json filename.")
    path = scan_directory / filename
    _atomic_create(path, json.dumps(data, indent=2, sort_keys=True) + "\n")
    return path


def write_text_artifact(scan_directory: Path, filename: str, content: str) -> Path:
    if Path(filename).name != filename or Path(filename).suffix.lower() not in {".txt", ".csv"}:
        raise ValueError("Text artifact filename must be a simple .txt or .csv filename.")
    path = scan_directory / filename
    _atomic_create(path, content)
    return path


def read_v1_scan(scan_directory: Path, scope: ScopePolicy) -> list[dict[str, Any]]:
    """Read v1 subdomains.json without writing or modifying any v1 artifact."""
    payload = json.loads((scan_directory / "subdomains.json").read_text(encoding="utf-8"))
    if payload.get("domain") != scope.root_domain or not isinstance(payload.get("subdomains"), list):
        raise ValueError("Not a compatible v1 scan for this root domain.")
    imported: list[dict[str, Any]] = []
    for item in payload["subdomains"]:
        if not isinstance(item, dict) or not isinstance(item.get("hostname"), str):
            continue
        if scope.permits_hostname(item["hostname"]):
            imported.append({"hostname": scope.require_hostname(item["hostname"]), "sources": item.get("sources", [])})
    return sorted(imported, key=lambda item: item["hostname"])
