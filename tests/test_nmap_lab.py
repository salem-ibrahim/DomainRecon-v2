"""Opt-in local Nmap smoke test. Never targets a non-loopback address."""
from __future__ import annotations

import os
import shutil
import socket
import threading
from pathlib import Path

import pytest

from domainrecon.core.scope import ScopePolicy
from domainrecon.scanners.nmap import NmapScanOptions, TcpScanMode, resume_nmap, run_nmap


@pytest.mark.integration
def test_nmap_discovers_local_tcp_lab_service(tmp_path: Path) -> None:
    if os.environ.get("DOMAINRECON_RUN_NMAP_LAB") != "1":
        pytest.skip("Set DOMAINRECON_RUN_NMAP_LAB=1 to run the loopback-only Nmap lab test.")
    executable = shutil.which("nmap") or next((str(path) for path in (Path(r"C:\Program Files (x86)\Nmap\nmap.exe"), Path(r"C:\Program Files\Nmap\nmap.exe")) if path.is_file()), None)
    if not executable:
        pytest.skip("Nmap is not installed.")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(0.2)
    listener.bind(("127.0.0.1", 0))
    listener.listen(10)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if stop.is_set():
                    break
                raise
            with client:
                try:
                    client.sendall(b"SSH-2.0-OpenSSH_9.0p1 DomainReconLab\r\n")
                except OSError:
                    # Nmap may close a preliminary TCP connect before its
                    # service probe; keep the controlled lab listener alive.
                    continue

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        options = NmapScanOptions(TcpScanMode.CUSTOM, str(port), True, 10, 1, 30)
        lab_scope = ScopePolicy("example.com", allow_loopback_for_lab=True)
        result = run_nmap(Path(executable), lab_scope, "127.0.0.1", options, tmp_path / "evidence", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        assert result["status"] == "success"
        port_result = result["hosts"][0]["ports"][0]
        assert port_result["port"] == port and port_result["state"] == "open"
        assert port_result["service"] == "ssh"
        assert Path(result["xml_file"]).is_file() and Path(result["resume_file"]).is_file()
        resumed = resume_nmap(Path(executable), Path(result["resume_file"]), scope=lab_scope, target="127.0.0.1", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        # Nmap only resumes interrupted logs. A completed local scan is kept
        # as an immutable native token and Nmap correctly rejects resumption.
        assert resumed["status"] == "failed" and resumed["error"]
    finally:
        stop.set()
        listener.close()
        worker.join(timeout=2)


@pytest.mark.integration
def test_nmap_host_scan_discovers_local_tcp_lab_service(tmp_path: Path) -> None:
    """Loopback-only: run_nmap_hosts in explicit lab mode scans 127.0.0.1 once and preserves per-host results."""
    if os.environ.get("DOMAINRECON_RUN_NMAP_LAB") != "1":
        pytest.skip("Set DOMAINRECON_RUN_NMAP_LAB=1 to run the loopback-only Nmap lab test.")
    from domainrecon.scanners.nmap import run_nmap_hosts

    executable = shutil.which("nmap") or next((str(path) for path in (Path(r"C:\Program Files (x86)\Nmap\nmap.exe"), Path(r"C:\Program Files\Nmap\nmap.exe")) if path.is_file()), None)
    if not executable:
        pytest.skip("Nmap is not installed.")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(10)
    port = listener.getsockname()[1]
    try:
        options = NmapScanOptions(TcpScanMode.CUSTOM, str(port), False, 10, 1, 30)
        lab_scope = ScopePolicy("example.com", allow_loopback_for_lab=True)
        result = run_nmap_hosts(Path(executable), lab_scope, ["127.0.0.1", "127.0.0.1", "10.0.0.1"], options, tmp_path / "evidence", active_acknowledgement="I AUTHORIZE PORT SCANNING")
        assert result["status"] == "success"
        assert len(result["units"]) == 1 and result["units"][0]["addresses"] == ["127.0.0.1"]
        assert any(row["hostname"] == "10.0.0.1" for row in result["rejected_hostnames"])
        ports = result["hosts"][0]["ports"]
        assert any(entry["port"] == port and entry["state"] == "open" for entry in ports)
        assert result["hosts"][0]["hostnames"] == ["127.0.0.1"]
    finally:
        listener.close()
