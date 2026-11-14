"""Test-wide network safety net.

Unit tests must never execute the real reconnaissance binaries or contact external services.
Any attempt to run Subfinder, DNSx, HTTPX, or Nmap from the project ``tools`` folder or a
standard Nmap installation fails the test, unless the corresponding explicitly opt-in
loopback-only integration test is enabled through its environment variable. Live crt.sh /
RDAP lookups are blocked unless a test patches them.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

PROJECT_TOOLS = (Path(__file__).resolve().parents[1] / "tools").resolve()
_REAL_TOOL_NAMES = {"subfinder.exe", "dnsx.exe", "httpx.exe", "nmap.exe", "subfinder", "dnsx", "httpx", "nmap"}
_STANDARD_NMAP_DIRS = [Path(r"C:\Program Files (x86)\Nmap"), Path(r"C:\Program Files\Nmap")]


def _is_real_tool(executable: object) -> bool:
    try:
        path = Path(str(executable)).resolve()
    except (OSError, ValueError):
        return False
    if path.name.casefold() not in _REAL_TOOL_NAMES:
        return False
    if path.is_relative_to(PROJECT_TOOLS):
        return True
    return any(path.is_relative_to(directory) for directory in _STANDARD_NMAP_DIRS)


def _opted_in(executable: object) -> bool:
    name = Path(str(executable)).name.casefold()
    if name.startswith("nmap") and os.environ.get("DOMAINRECON_RUN_NMAP_LAB") == "1":
        return True
    configured = os.environ.get("DOMAINRECON_HTTPX_BIN")
    return bool(configured) and Path(str(executable)).resolve() == Path(configured).resolve()


@pytest.fixture(autouse=True)
def _block_real_network_tools(monkeypatch: pytest.MonkeyPatch):
    original_run = subprocess.run

    def guarded_run(command, *args, **kwargs):
        executable = command[0] if isinstance(command, (list, tuple)) and command else command
        arguments = [str(part) for part in command[1:]] if isinstance(command, (list, tuple)) else []
        version_query = bool(arguments) and set(arguments) <= {"--version", "-version", "-duc"}  # local, no network
        if _is_real_tool(executable) and not version_query and not _opted_in(executable):
            raise AssertionError(f"Unit test attempted to execute a real reconnaissance binary: {executable}. Mock it instead.")
        return original_run(command, *args, **kwargs)

    def blocked_urlopen(*_args, **_kwargs):
        raise AssertionError("Unit test attempted a live HTTP request (crt.sh/RDAP). Mock it instead.")

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr("domainrecon.collectors.passive.urlopen", blocked_urlopen)
    monkeypatch.setattr("domainrecon.collectors.rdap.urlopen", blocked_urlopen)
    yield
