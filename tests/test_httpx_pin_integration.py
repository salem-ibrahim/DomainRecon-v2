"""Optional loopback-only conformance test for a user-supplied pinned-input HTTPX binary."""
from __future__ import annotations

import http.server
import json
import os
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from domainrecon.active.httpx_probe import _LoopbackDnsResponder, check_httpx_pinning


class _HttpHandler(http.server.BaseHTTPRequestHandler):
    seen_hosts: list[str] = []
    seen = threading.Event()

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        type(self).seen_hosts.append(self.headers.get("Host", ""))
        type(self).seen.set()
        body = b"<html><title>loopback</title></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-DomainRecon-Probe", "pin-self-test")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def test_projectdiscovery_httpx_pinned_host_and_sni_on_loopback() -> None:
    configured = os.environ.get("DOMAINRECON_HTTPX_BIN")
    if not configured:
        pytest.skip("Set DOMAINRECON_HTTPX_BIN to run the real ProjectDiscovery HTTPX loopback test.")
    executable = Path(configured)
    if not executable.is_file():
        pytest.fail(f"DOMAINRECON_HTTPX_BIN does not point to a file: {executable}")
    # This performs only a local HTTP loopback conformance check before the HTTP/TLS test.
    check_httpx_pinning(executable)

    _HttpHandler.seen_hosts = []
    _HttpHandler.seen.clear()
    http_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _HttpHandler)
    http_server.daemon_threads = True
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()

    tls_seen: list[str | None] = []
    tls_seen_event = threading.Event()
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    def capture_sni(_ssl_socket: ssl.SSLObject, server_name: str | None, _context: ssl.SSLContext) -> None:
        tls_seen.append(server_name)
        tls_seen_event.set()

    tls_context.set_servername_callback(capture_sni)
    tls_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tls_listener.bind(("127.0.0.1", 0))
    tls_listener.listen(4)
    tls_listener.settimeout(0.2)
    tls_stop = threading.Event()

    def serve_tls() -> None:
        while not tls_stop.is_set():
            try:
                connection, _peer = tls_listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with connection:
                    # No certificate is needed to inspect ClientHello SNI; the handshake
                    # is intentionally allowed to fail after the callback has recorded it.
                    tls_context.wrap_socket(connection, server_side=True)
            except ssl.SSLError:
                continue

    tls_thread = threading.Thread(target=serve_tls, daemon=True)
    tls_thread.start()
    dns = _LoopbackDnsResponder()
    dns.start()
    host = "pin-check.invalid"
    http_port = http_server.server_address[1]
    tls_port = tls_listener.getsockname()[1]
    targets = [
        {"target": f"http://{host}:{http_port}/", "ip": "127.0.0.1"},
        {"target": f"https://{host}:{tls_port}/", "ip": "127.0.0.1"},
    ]
    input_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".jsonl", delete=False) as handle:
            input_name = handle.name
            handle.write("\n".join(json.dumps(item, separators=(",", ":")) for item in targets) + "\n")
        command = [
            str(executable), "-l", input_name, "-json", "-silent", "-probe", "-status-code", "-ip", "-include-response-header",
            "-title", "-tls-grab", "-x", "GET", "-threads", "2", "-rate-limit", "2",
            "-timeout", "3", "-retries", "0", "-no-fallback-scheme", "-no-stdin", "-duc",
            "-resolvers", f"udp:127.0.0.1:{dns.address[1]}",
        ]
        env = os.environ.copy()
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env.pop(key, None)
        env["NO_PROXY"] = "*"
        env["no_proxy"] = "*"
        result = subprocess.run(command, shell=False, capture_output=True, text=True, timeout=15, check=False, env=env)
        assert result.returncode == 0, result.stderr
        assert _HttpHandler.seen.wait(timeout=3), "Pinned HTTP request did not reach the controlled loopback service."
        assert f"{host}:{http_port}" in _HttpHandler.seen_hosts
        assert "x-domainrecon-probe" in result.stdout.casefold() and "pin-self-test" in result.stdout.casefold(), "HTTPX did not emit the controlled response header in JSON."
        assert tls_seen_event.wait(timeout=3), "Pinned HTTPS request did not send a TLS ClientHello to loopback."
        assert host in tls_seen, f"HTTPX did not preserve the original hostname in TLS SNI: {tls_seen}"
        assert host not in dns.names, "Pinned hostname was resolved despite the supplied IP."
    finally:
        if input_name:
            Path(input_name).unlink(missing_ok=True)
        http_server.shutdown()
        http_server.server_close()
        http_thread.join(timeout=1)
        tls_stop.set()
        tls_listener.close()
        tls_thread.join(timeout=1)
        dns.close()
