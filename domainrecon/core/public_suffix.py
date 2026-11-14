"""Offline public-suffix detection used to refuse registry suffixes as authorized roots.

No network access happens during ordinary execution. Rules come from (in order):

1. ``DOMAINRECON_PSL_FILE`` - an operator-supplied copy of the official list;
2. ``domainrecon/data/public_suffix_list.dat`` - the official list, installed explicitly with
   ``python main.py --update-psl --confirm-download`` (the only code path that downloads it);
3. the bundled conservative subset plus a fail-closed heuristic.

The complete list's ICANN and PRIVATE sections, ``*.`` wildcard rules and ``!`` exception rules
are supported. When a sidecar ``.meta.json`` exists, the list's SHA-256 must match it; a list that
fails verification is never used and the bundled subset is used instead (reported in ``status()``).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.request import Request, urlopen

_DATA_DIRECTORY = Path(__file__).resolve().parent.parent / "data"
_BUNDLED_SUBSET = _DATA_DIRECTORY / "public_suffix_subset.dat"
_OFFICIAL_LOCAL = _DATA_DIRECTORY / "public_suffix_list.dat"
OFFICIAL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
_MAX_LIST_BYTES = 4 * 1024 * 1024
_GENERIC_SECOND_LEVEL = frozenset({
    "ac", "co", "com", "edu", "gob", "go", "gouv", "gov", "govt", "gv", "int", "ltd",
    "mil", "ne", "net", "nom", "or", "org", "plc", "sch",
})


@dataclass(frozen=True)
class SuffixRules:
    exact: frozenset[str]
    wildcard: frozenset[str]
    exceptions: frozenset[str]
    source: str
    authoritative: bool
    private: frozenset[str] = frozenset()
    metadata: dict = field(default_factory=dict)


def _ascii(value: str) -> str:
    try:
        return value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return value.lower()


def _parse(lines: list[str], source: str, authoritative: bool, metadata: dict | None = None) -> SuffixRules:
    exact: set[str] = set()
    wildcard: set[str] = set()
    exceptions: set[str] = set()
    private: set[str] = set()
    in_private = False
    info = dict(metadata or {})
    for raw in lines:
        line = raw.strip()
        if line.startswith("//"):
            if "===BEGIN PRIVATE DOMAINS" in line:
                in_private = True
            elif "===END PRIVATE DOMAINS" in line:
                in_private = False
            match = re.match(r"//\s*(VERSION|COMMIT):\s*(\S+)", line)
            if match:
                info.setdefault(match.group(1).lower(), match.group(2))
            continue
        if not line:
            continue
        rule = line.split()[0]
        if rule.startswith("!"):
            name = _ascii(rule[1:])
            exceptions.add(name)
        elif rule.startswith("*."):
            name = _ascii(rule[2:])
            wildcard.add(name)
        else:
            name = _ascii(rule)
            exact.add(name)
        if in_private:
            private.add(name)
    info.update({"rule_count": len(exact) + len(wildcard) + len(exceptions), "private_rule_count": len(private)})
    return SuffixRules(frozenset(exact), frozenset(wildcard), frozenset(exceptions), source, authoritative, frozenset(private), info)


def _meta_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".meta.json")


def _verified_official(path: Path) -> tuple[SuffixRules | None, dict]:
    """Load an official list; refuse it when its sidecar digest does not match."""
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    meta_file = _meta_path(path)
    metadata: dict = {"sha256": digest, "path": str(path)}
    if meta_file.is_file():
        try:
            recorded = json.loads(meta_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None, {**metadata, "integrity": "metadata_unreadable"}
        if recorded.get("sha256") != digest:
            return None, {**metadata, "integrity": "sha256_mismatch", "expected_sha256": recorded.get("sha256")}
        metadata.update({key: recorded.get(key) for key in ("source_url", "fetched_at_utc") if recorded.get(key)})
        metadata["integrity"] = "verified"
    else:
        metadata["integrity"] = "unverified_no_metadata"
    text = data.decode("utf-8")
    if "===BEGIN ICANN DOMAINS===" not in text:
        return None, {**metadata, "integrity": "not_a_public_suffix_list"}
    return _parse(text.splitlines(), str(path), True, metadata), metadata


@lru_cache(maxsize=4)
def _load(override: str | None) -> SuffixRules:
    problems: list[dict] = []
    if override:
        path = Path(override)
        if not path.is_file():
            raise FileNotFoundError(f"DOMAINRECON_PSL_FILE does not point to a readable file: {override}")
        if "===BEGIN ICANN DOMAINS===" not in path.read_text(encoding="utf-8", errors="replace"):
            # Operator-supplied test lists without section markers are accepted as authoritative rules.
            data = path.read_bytes()
            return _parse(data.decode("utf-8").splitlines(), str(path), True, {"sha256": hashlib.sha256(data).hexdigest(), "integrity": "unverified_no_metadata"})
        rules_, meta = _verified_official(path)
        if rules_ is None:
            raise ValueError(f"DOMAINRECON_PSL_FILE failed integrity verification: {meta.get('integrity')}")
        return rules_
    if _OFFICIAL_LOCAL.is_file():
        rules_, meta = _verified_official(_OFFICIAL_LOCAL)
        if rules_ is not None:
            return rules_
        problems.append(meta)
    bundled = _parse(_BUNDLED_SUBSET.read_text(encoding="utf-8").splitlines(), str(_BUNDLED_SUBSET), False, {"integrity": "bundled_subset"})
    if problems:
        bundled.metadata["rejected_official_list"] = problems
    return bundled


def rules() -> SuffixRules:
    return _load(os.environ.get("DOMAINRECON_PSL_FILE") or None)


def status() -> dict:
    """Offline status for --health: which list is active, its version, and integrity state."""
    try:
        active = rules()
    except (OSError, ValueError) as exc:
        return {"active": "error", "error": str(exc)}
    return {"active": "official" if active.authoritative else "bundled_subset_with_heuristic", "source": active.source, **active.metadata}


def public_suffix_reason(domain: str) -> str | None:
    """Return why ``domain`` (canonical ASCII, lower case) is a public suffix, else ``None``."""
    labels = domain.split(".")
    if len(labels) < 2:
        return "single-label names are top-level domains"
    active = rules()
    if domain in active.exceptions:
        return None
    label = "official list" if active.authoritative else "bundled subset"
    if domain in active.exact:
        kind = "private" if domain in active.private else "ICANN"
        return f"listed {kind} public suffix ({label})"
    parent = ".".join(labels[1:])
    if parent in active.wildcard:
        return f"matches wildcard public-suffix rule *.{parent} ({label})"
    if not active.authoritative and len(labels) == 2 and len(labels[1]) == 2 and labels[1].isalpha() and labels[0] in _GENERIC_SECOND_LEVEL:
        return "generic registry label under a country-code TLD (offline heuristic; install the official list to override)"
    return None


def is_public_suffix(domain: str) -> bool:
    return public_suffix_reason(domain) is not None


def registrable_domain(hostname: str) -> str | None:
    """Return the registrable domain (public suffix + one label), or None if the name is itself a suffix."""
    labels = hostname.lower().rstrip(".").split(".")
    for index in range(len(labels)):
        if is_public_suffix(".".join(labels[index:])):  # longest matching suffix first
            return ".".join(labels[index - 1:]) if index > 0 else None
    return None


def _install(data: bytes, *, source: str, destination: Path) -> dict:
    """Validate and atomically install a list; keep the previous copy; write integrity metadata."""
    if len(data) > _MAX_LIST_BYTES:
        raise ValueError("Public Suffix List exceeds the 4 MiB safety limit.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Public Suffix List is not valid UTF-8.") from exc
    if "===BEGIN ICANN DOMAINS===" not in text or "===BEGIN PRIVATE DOMAINS===" not in text:
        raise ValueError("Content is not a Public Suffix List (ICANN/PRIVATE section markers missing).")
    parsed = _parse(text.splitlines(), source, True)
    if parsed.metadata["rule_count"] < 5000:
        raise ValueError("List is implausibly small; refusing to install it.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        previous = destination.read_bytes()
        archive = destination.with_name(f"{destination.stem}.{hashlib.sha256(previous).hexdigest()[:12]}{destination.suffix}")
        if not archive.exists():
            archive.write_bytes(previous)
    temporary = destination.with_suffix(".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, destination)
    metadata = {"source_url": source, "fetched_at_utc": datetime.now(timezone.utc).isoformat(), "sha256": hashlib.sha256(data).hexdigest(),
                **{k: v for k, v in parsed.metadata.items() if k in {"version", "commit", "rule_count", "private_rule_count"}}}
    _meta_path(destination).write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _load.cache_clear()
    return metadata


def update_public_suffix_list(*, destination: Path = _OFFICIAL_LOCAL, url: str = OFFICIAL_URL, timeout: int = 30) -> dict:
    """Explicit, operator-initiated download of the official list (never called implicitly).

    The request and its final URL (after redirects) must both be HTTPS on publicsuffix.org.
    """
    if not url.startswith("https://publicsuffix.org/"):
        raise ValueError("The Public Suffix List must be fetched over HTTPS from publicsuffix.org.")
    request = Request(url, headers={"User-Agent": "DomainRecon/2.0 (explicit PSL update)"})
    with urlopen(request, timeout=timeout) as response:  # explicit operator action only
        final_url = response.geturl() if hasattr(response, "geturl") else url
        if not str(final_url).startswith("https://publicsuffix.org/"):
            raise ValueError(f"Refusing redirected Public Suffix List source: {final_url}")
        data = response.read(_MAX_LIST_BYTES + 1)
    return _install(data, source=url, destination=destination)


def install_public_suffix_list(source: Path, *, destination: Path = _OFFICIAL_LOCAL) -> dict:
    """Offline install from a local copy obtained through an approved channel (same validation as update)."""
    if not source.is_file():
        raise FileNotFoundError(f"Public Suffix List file not found: {source}")
    if source.stat().st_size > _MAX_LIST_BYTES:
        raise ValueError("Public Suffix List exceeds the 4 MiB safety limit.")
    return _install(source.read_bytes(), source=f"local_file:{source.name}", destination=destination)