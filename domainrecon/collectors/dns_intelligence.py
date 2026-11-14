"""DNSx-backed record collection for pre-approved, in-scope hostnames only."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from domainrecon.core.models import ObservationStatus
from domainrecon.core.scope import ScopePolicy

_DNS_FLAGS = ("-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-caa", "-soa")
_POLICY_FLAGS = ("-txt", "-mx", "-caa", "-ns", "-soa")


def _run_dnsx(executable: Path, names: list[str], flags: tuple[str, ...], accept: Callable[[str], str | None]) -> list[dict[str, Any]]:
    """Run DNSx for already-validated names; ``accept`` maps an answer host to a requested name or None."""
    if not executable.is_file():
        return [{"hostname": host, "status": ObservationStatus.FAILED, "error": "dnsx is not installed"} for host in names]
    if not names:
        return []
    input_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".txt", delete=False) as handle:
            input_name = handle.name
            os.chmod(input_name, 0o600)
            handle.write("\n".join(names) + "\n")
        command = [str(executable), "-l", input_name, "-silent", "-j", *flags, "-retry", "2", "-timeout", "3", "-rl", "10", "-duc"]
        run = subprocess.run(command, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [{"hostname": host, "status": ObservationStatus.FAILED, "error": str(exc)} for host in names]
    finally:
        if input_name:
            try:
                Path(input_name).unlink(missing_ok=True)
            except OSError:
                pass
    if run.returncode != 0:
        detail = run.stderr.strip().splitlines()[-1] if run.stderr.strip() else f"exit {run.returncode}"
        return [{"hostname": host, "status": ObservationStatus.FAILED, "error": detail} for host in names]
    by_host: dict[str, dict[str, Any]] = {}
    for line in run.stdout.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict) or not isinstance(item.get("host"), str):
            continue
        host = accept(item["host"])
        if host is None:
            continue
        by_host[host] = {"hostname": host, "status": ObservationStatus.SUCCESS, "records": item}
    return [by_host.get(host, {"hostname": host, "status": ObservationStatus.UNRESOLVED}) for host in names]


def collect_dns(executable: Path, scope: ScopePolicy, hostnames: list[str]) -> list[dict[str, Any]]:
    approved = scope.filter_hostnames(hostnames)

    def accept(host: str) -> str | None:
        return scope.require_hostname(host) if scope.permits_hostname(host) else None

    return _run_dnsx(executable, approved, _DNS_FLAGS, accept)


def collect_dns_policy(executable: Path, scope: ScopePolicy, dkim_selectors: tuple[str, ...] | list[str] = ()) -> list[dict[str, Any]]:
    """Query only the apex, ``_dmarc.<apex>`` and operator-supplied DKIM selectors (TXT/MX/CAA/NS/SOA).

    Policy names are validated by the narrow ``ScopePolicy.require_dns_policy_name``; global
    hostname validation is unchanged, selectors are never guessed, and these names are never probed.
    """
    names = [scope.require_hostname(scope.root_domain), scope.require_dns_policy_name("_dmarc." + scope.root_domain)]
    names += [scope.require_dns_policy_name(f"{selector}._domainkey.{scope.root_domain}") for selector in dkim_selectors]
    requested = set(names)

    def accept(host: str) -> str | None:
        candidate = host.rstrip(".").lower()
        return candidate if candidate in requested else None

    rows = _run_dnsx(executable, names, _POLICY_FLAGS, accept)
    for row in rows:
        row["query_purpose"] = "dmarc_policy" if row["hostname"].startswith("_dmarc.") else "dkim_selector" if "._domainkey." in row["hostname"] else "apex_email_and_ca_policy"
    return rows
