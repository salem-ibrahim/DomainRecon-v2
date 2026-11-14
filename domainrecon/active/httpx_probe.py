"""Fail-closed ProjectDiscovery HTTPX integration using pinned target/IP JSON lines."""
from __future__ import annotations

import hashlib
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from domainrecon.analysis.tls import extract_tls
from domainrecon.core.csv_safe import render_csv
from domainrecon.core.errors import AuthorizationRequired, ScopeViolation
from domainrecon.core.models import ActiveAuthorization, ObservationStatus
from domainrecon.core.scope import ScopePolicy

# v1.12.0 predates ProjectDiscovery PR #2691 (merged into dev 2026-10-29),
# which introduced JSON {target, ip} input that pins the socket while preserving
# the hostname for Host and SNI. Refuse older binaries before any target input.
MIN_PINNED_HTTPX_VERSION = (1, 13, 0)
_HTTP_FLAGS = (
    "-json", "-silent", "-probe", "-status-code", "-title", "-web-server",
    "-tech-detect", "-response-time", "-location", "-ip", "-tls-grab", "-include-response-header",
)
_SENSITIVE_RESPONSE_HEADERS = {"set-cookie", "authorization", "proxy-authenticate", "www-authenticate", "x-api-key", "x-auth-token"}
_PIN_CAPABILITY_CACHE: set[tuple[str, str]] = set()


def validate_redirect(scope: ScopePolicy, destination: str) -> bool:
    """Compatibility helper retaining the conservative root-only URL policy."""
    try:
        scope.validate_redirect(destination)
        return True
    except ScopeViolation:
        return False


def _clean_environment() -> dict[str, str]:
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


HTTPX_INSTALL_GUIDANCE = (
    "Install ProjectDiscovery HTTPX v1.13.0+ (pinned target/IP JSON input) with ./setup.ps1 -InstallTools (checksum-verified GitHub release), "
    "or place a vetted httpx.exe in tools\\httpx\\, or pass --httpx <path>. Then run: python main.py --check-httpx. "
    "The binary must pass the loopback pinning/Host/SNI/DNS-bypass gate before any target is probed; older releases and other tools named 'httpx' are refused. "
    "Known blocker (checked 2026-11-12): the newest published ProjectDiscovery release is v1.12.0; pinned target/IP input (PR #2691) is only on the dev branch, so no published release qualifies yet."
)
DEFAULT_HTTPX_PATH = Path("tools/httpx/httpx.exe")


def httpx_candidates(configured: Path | None = None) -> list[Path]:
    """Ordered local candidate paths; nothing is downloaded and no candidate is executed here."""
    candidates: list[Path] = []
    for path in (configured, DEFAULT_HTTPX_PATH, Path(shutil.which("httpx")) if shutil.which("httpx") else None, Path.home() / "go" / "bin" / "httpx.exe", Path.home() / "go" / "bin" / "httpx"):
        if path is not None and path not in candidates:
            candidates.append(path)
    return candidates


def inspect_httpx(executable: Path) -> dict[str, Any]:
    """Run only ``-version -duc`` (local, no network) and classify compatibility."""
    if not executable.is_file():
        return {"path": str(executable), "status": "not_found"}
    try:
        run = subprocess.run([str(executable), "-version", "-duc"], shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=10, check=False, env=_clean_environment())
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"path": str(executable), "status": "not_executable", "error": str(exc)}
    output = f"{run.stdout}\n{run.stderr}"
    match = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", output)
    banner = "projectdiscovery" in output.lower() or bool(re.search(r"(?i)current\s+(httpx\s+)?version", output))
    if run.returncode != 0 or not match:
        return {"path": str(executable), "status": "not_projectdiscovery_or_unparseable", "projectdiscovery_banner_detected": banner, "exit_code": run.returncode}
    version = tuple(int(part) for part in match.groups())
    status = "compatible_pending_loopback_gate" if version >= MIN_PINNED_HTTPX_VERSION else "incompatible_version"
    return {"path": str(executable), "status": status, "version": ".".join(map(str, version)), "minimum": ".".join(map(str, MIN_PINNED_HTTPX_VERSION)), "projectdiscovery_banner_detected": banner}


def discover_httpx(configured: Path | None = None) -> dict[str, Any]:
    """Select the first compatible local candidate; report every candidate and installation guidance."""
    inspected = [inspect_httpx(path) if path.is_file() else {"path": str(path), "status": "not_found"} for path in httpx_candidates(configured)]
    selected = next((row["path"] for row in inspected if row["status"] == "compatible_pending_loopback_gate"), None)
    return {"selected": selected, "candidates": inspected, "guidance": None if selected else HTTPX_INSTALL_GUIDANCE}


def check_httpx_ready(executable: Path) -> dict[str, Any]:
    """Compatibility validation: version check plus loopback-only IPv4 and IPv6 pinning gates (no external traffic)."""
    report = inspect_httpx(executable)
    if report["status"] != "compatible_pending_loopback_gate":
        return {**report, "ready": False, "guidance": HTTPX_INSTALL_GUIDANCE}
    try:
        check_httpx_pinning(executable)
        report["ipv4_pinning_gate"] = "passed"
    except (OSError, RuntimeError) as exc:
        return {**report, "ready": False, "ipv4_pinning_gate": f"failed: {exc}", "guidance": HTTPX_INSTALL_GUIDANCE}
    try:
        check_httpx_pinning(executable, ipv6=True)
        report["ipv6_pinning_gate"] = "passed"
    except (OSError, RuntimeError) as exc:
        report["ipv6_pinning_gate"] = f"failed (IPv6 answers will be recorded, not probed): {exc}"
    return {**report, "ready": True}


def httpx_version(executable: Path) -> tuple[int, int, int]:
    """Return a supported version; old versions are rejected before target probes."""
    if not executable.is_file():
        raise FileNotFoundError(f"ProjectDiscovery HTTPX is not installed: {executable}. {HTTPX_INSTALL_GUIDANCE}")
    try:
        run = subprocess.run(
            [str(executable), "-version", "-duc"],
            shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10, check=False, env=_clean_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not validate HTTPX version: {exc}") from exc
    output = f"{run.stdout}\n{run.stderr}"
    match = re.search(r"\bv?(\d+)\.(\d+)\.(\d+)\b", output)
    if run.returncode != 0 or not match:
        raise RuntimeError("HTTPX did not return a parseable version; pinned-IP mode is disabled.")
    version = tuple(int(part) for part in match.groups())
    if version < MIN_PINNED_HTTPX_VERSION:
        minimum = ".".join(map(str, MIN_PINNED_HTTPX_VERSION))
        found = ".".join(map(str, version))
        raise RuntimeError(f"HTTPX {found} is not accepted: pinned target/IP input requires v{minimum} or newer.")
    return version  # type: ignore[return-value]


class _LoopbackDnsResponder:
    """A local-only resolver returning a different loopback IP for capability checks."""

    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.2)
        self.address = self.socket.getsockname()
        self.names: set[str] = set()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=1)
        self.socket.close()

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                packet, peer = self.socket.recvfrom(1024)
            except (OSError, TimeoutError):
                continue
            try:
                offset = 12
                labels: list[str] = []
                while offset < len(packet) and packet[offset] != 0:
                    length = packet[offset]
                    offset += 1
                    labels.append(packet[offset:offset + length].decode("ascii", "ignore"))
                    offset += length
                offset += 1
                qtype = struct.unpack("!H", packet[offset:offset + 2])[0]
                question_end = offset + 4
                question = packet[12:question_end]
                name = ".".join(labels).lower()
                self.names.add(name)
                answer = b""
                count = 0
                if qtype == 1:
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton("127.0.0.2")
                    count = 1
                header = packet[:2] + b"\x81\x80" + packet[4:6] + struct.pack("!H", count) + b"\x00\x00\x00\x00"
                self.socket.sendto(header + question + answer, peer)
            except (IndexError, ValueError, struct.error, OSError):
                continue


class _LoopbackTlsResponder:
    """Capture SNI from a loopback TLS ClientHello; no certificate or external host is used."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.listener = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.address = self.listener.getsockname()
        self.names: list[str | None] = []
        self.stop_event = threading.Event()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.set_servername_callback(self._capture_sni)
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _capture_sni(self, _ssl_socket: ssl.SSLObject, server_name: str | None, _context: ssl.SSLContext) -> None:
        self.names.append(server_name)

    def start(self) -> None:
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=1)

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                connection, _peer = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with connection:
                    # SNI is available in ClientHello before the missing certificate
                    # causes the local handshake to fail, which is the desired test.
                    self.context.wrap_socket(connection, server_side=True)
            except ssl.SSLError:
                continue


def check_httpx_pinning(executable: Path, *, ipv6: bool = False) -> tuple[int, int, int]:
    """Require a supported version and prove pinning, Host, SNI, and response headers on loopback.

    With ``ipv6=True`` the same proof runs over ``[::1]`` so IPv6 targets are pinned only when the
    installed binary demonstrably honours an IPv6 pinned address.
    """
    version = httpx_version(executable)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    cache_key = (str(executable.resolve()), digest + (":ipv6" if ipv6 else ""))
    if cache_key in _PIN_CAPABILITY_CACHE:
        return version
    loopback = "::1" if ipv6 else "127.0.0.1"

    observed_hosts: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
            observed_hosts.append(self.headers.get("Host", ""))
            body = b"<html><title>pin-check</title></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-DomainRecon-Probe", "pin-self-test")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    server_class = type("_PinServer", (http.server.ThreadingHTTPServer,), {"address_family": socket.AF_INET6 if ipv6 else socket.AF_INET})
    server = server_class((loopback, 0), Handler)
    server.daemon_threads = True
    dns = _LoopbackDnsResponder()
    tls = _LoopbackTlsResponder(loopback)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    dns.start()
    tls.start()
    host = "pin-check.invalid"
    port = server.server_address[1]
    http_target = f"http://{host}:{port}/"
    https_target = f"https://{host}:{tls.address[1]}/"
    input_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".jsonl", delete=False) as handle:
            input_name = handle.name
            os.chmod(input_name, 0o600)
            for target in (http_target, https_target):
                handle.write(json.dumps({"target": target, "ip": loopback}, separators=(",", ":")) + "\n")
        command = [
            str(executable), "-l", input_name, "-json", "-silent", "-probe", "-status-code", "-ip", "-include-response-header",
            "-tls-grab", "-x", "GET", "-threads", "1", "-rate-limit", "2", "-timeout", "3", "-retries", "0",
            "-no-fallback-scheme", "-no-stdin", "-duc", "-resolvers",
            f"udp:127.0.0.1:{dns.address[1]}",
        ]
        run = subprocess.run(
            command, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=10, check=False, env=_clean_environment(),
        )
        observed_ip = False
        observed_header = False
        for line in run.stdout.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                try:
                    status_code = int(item.get("status_code", 0) or 0)
                except (TypeError, ValueError):
                    status_code = 0
                if status_code == 200 and _same_ip(item.get("host_ip", item.get("ip")), loopback):
                    observed_ip = True
                encoded = json.dumps(item, sort_keys=True).casefold()
                if '"x-domainrecon-probe"' in encoded and "pin-self-test" in encoded:
                    observed_header = True
        expected_host = f"{host}:{port}"
        if run.returncode != 0 or not observed_ip or not observed_header or expected_host not in observed_hosts or host not in tls.names or host in dns.names:
            raise RuntimeError("HTTPX failed its loopback pinning, Host, SNI, response-header, or DNS-bypass check; production target probing is disabled.")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"HTTPX loopback pinning check failed safely: {exc}") from exc
    finally:
        if input_name:
            try:
                Path(input_name).unlink(missing_ok=True)
            except OSError:
                pass
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1)
        dns.close()
        tls.close()

    _PIN_CAPABILITY_CACHE.add(cache_key)
    return version


def _same_ip(observed: Any, expected: str) -> bool:
    try:
        return isinstance(observed, str) and ipaddress.ip_address(observed.strip("[]")).compressed == expected
    except ValueError:
        return False


def _public_answers(scope: ScopePolicy, dns_record: dict[str, Any]) -> set[str]:
    """Validated public IPv4 and IPv6 answers; any non-public or excluded answer blocks the host."""
    if str(dns_record.get("status", "")) != str(ObservationStatus.SUCCESS):
        return set()
    raw = dns_record.get("records", {})
    answers: set[str] = set()
    if isinstance(raw, dict):
        for key in ("a", "aaaa"):
            values = raw.get(key, [])
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                for address in values:
                    if isinstance(address, str):
                        answers.add(scope.require_httpx_ip(address))
    return answers


def _redirect_destination(scope: ScopePolicy, base_url: str, location: str) -> tuple[str | None, str | None, str | None]:
    """Validate redirect authority without following it or causing another request."""
    try:
        destination = urljoin(base_url, location)
        parsed = urlsplit(destination)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.fragment:
            raise ScopeViolation("Redirect must be a clean HTTP(S) URL without credentials or fragment.")
        try:
            hostname = scope.require_hostname(parsed.hostname or "")
        except ScopeViolation as exc:
            return destination, None, str(exc)
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ScopeViolation("Redirect contains an invalid port.") from exc
        if port not in {80, 443}:
            return destination, None, "Redirect port is outside the approved HTTP/HTTPS ports."
        return destination, hostname, None
    except (ScopeViolation, ValueError) as exc:
        return None, None, str(exc)


def _classify_error(error: str) -> str:
    lowered = error.casefold()
    if any(token in lowered for token in ("tls", "ssl", "x509", "certificate", "handshake")):
        return "TLS_ERROR"
    if any(token in lowered for token in ("timeout", "timed out", "deadline exceeded")):
        return "TIMEOUT"
    if "connection refused" in lowered or "actively refused" in lowered:
        return "CONNECTION_REFUSED"
    return "UNKNOWN_ERROR"


def _target_key(item: dict[str, Any]) -> tuple[str, str, str] | None:
    raw_input = item.get("input")
    target: str | None = None
    pinned_ip: str | None = None
    if isinstance(raw_input, str):
        try:
            decoded = json.loads(raw_input)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, dict):
            target = decoded.get("target") if isinstance(decoded.get("target"), str) else None
            pinned_ip = decoded.get("ip") if isinstance(decoded.get("ip"), str) else None
    if target is None and isinstance(item.get("url"), str):
        target = item["url"]
        candidate_ip = item.get("host_ip", item.get("ip"))
        pinned_ip = candidate_ip if isinstance(candidate_ip, str) else None
    if not target or not pinned_ip:
        return None
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        ip = ipaddress.ip_address(pinned_ip).compressed
    except (UnicodeError, ValueError):
        return None
    return parsed.scheme, host, ip


def _normalise_headers(item: dict[str, Any]) -> dict[str, str]:
    """Normalize HTTPX -include-response-header fields without retaining bodies."""
    result: dict[str, str] = {}
    raw_values = [item.get(key) for key in ("headers", "response_headers", "header") if item.get(key) is not None]
    response = item.get("response")
    if isinstance(response, dict):
        raw_values.extend(response.get(key) for key in ("headers", "header") if response.get(key) is not None)
    for raw in raw_values:
        pairs: list[tuple[str, Any]] = []
        if isinstance(raw, dict):
            pairs.extend(raw.items())
        elif isinstance(raw, str):
            for line in raw.splitlines():
                key, separator, value = line.partition(":")
                if separator and key.strip():
                    pairs.append((key.strip(), value.strip()))
        elif isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    pairs.extend(entry.items())
                elif isinstance(entry, str):
                    key, separator, value = entry.partition(":")
                    if separator and key.strip():
                        pairs.append((key.strip(), value.strip()))
        for key, value in pairs:
            if not isinstance(key, str):
                continue
            if isinstance(value, list):
                normalized_value = ", ".join(str(part) for part in value)
            else:
                normalized_value = str(value)
            normalized_key = key.casefold()
            result[normalized_key] = "[REDACTED]" if normalized_key in _SENSITIVE_RESPONSE_HEADERS else normalized_value[:2048]
    return result


def _normalise_observation(
    scope: ScopePolicy,
    item: dict[str, Any],
    expected: tuple[str, str, str],
    discovered_hosts: set[str],
    addresses_by_host: dict[str, set[str]],
) -> dict[str, Any]:
    scheme, hostname, expected_ip = expected
    url = item.get("url") if isinstance(item.get("url"), str) else f"{scheme}://{hostname}/"
    error = item.get("error") if isinstance(item.get("error"), str) else ""
    failed = bool(item.get("failed")) or str(item.get("status", "")).casefold() == "failed"
    if failed:
        classification = _classify_error(error or "HTTPX reported a failed probe.")
        return {
            "hostname": hostname, "url": url, "final_url": None, "ip": expected_ip,
            "status": ObservationStatus.FAILED, "classification": classification,
            "status_code": None, "error": error or "HTTPX reported a failed probe.",
        }
    observed_ip = item.get("host_ip", item.get("ip"))
    if not isinstance(observed_ip, str) or observed_ip != expected_ip:
        return {
            "hostname": hostname, "url": url, "final_url": None, "ip": observed_ip,
            "status": ObservationStatus.BLOCKED, "classification": "ACCESS_RESTRICTED",
            "error": "HTTPX connection address did not match the validated pinned IP.",
        }

    try:
        status_code = int(item.get("status_code", item.get("status-code", 0)) or 0)
    except (TypeError, ValueError):
        status_code = 0
    if status_code == 0:
        classification = _classify_error(error or "HTTPX returned no response status.")
        return {
            "hostname": hostname, "url": url, "final_url": None, "ip": expected_ip,
            "status": ObservationStatus.FAILED, "classification": classification,
            "status_code": None, "error": error or "HTTPX returned no response status.",
        }

    if status_code in {401, 407}:
        classification = "AUTH_REQUIRED"
    elif status_code in {403, 423, 451} or 400 <= status_code < 500 and status_code != 404:
        classification = "ACCESS_RESTRICTED"
    elif status_code == 404:
        classification = "NOT_FOUND"
    elif 300 <= status_code < 400:
        classification = "REDIRECT"
    else:
        classification = "LIVE"

    raw_location = item.get("location")
    redirect_url: str | None = None
    redirect_hostname: str | None = None
    redirect_error: str | None = None
    redirect_allowed = False
    if isinstance(raw_location, str) and raw_location:
        redirect_url, redirect_hostname, redirect_error = _redirect_destination(scope, url, raw_location)
        if redirect_url is not None and redirect_hostname is not None:
            redirect_allowed = (
                redirect_hostname in discovered_hosts
                and bool(addresses_by_host.get(redirect_hostname))
            )
            if not redirect_allowed:
                redirect_error = "Redirect target is not a discovered host with validated DNS answers; it was not followed."
        elif redirect_url is not None and redirect_error is not None:
            redirect_error = f"{redirect_error}; redirect was not followed."
        # No automatic redirect-follow option is passed. Even allowed redirects are recorded, not requested.

    tls_raw = item.get("tls") if isinstance(item.get("tls"), dict) else {}
    tls = extract_tls({"tls": tls_raw})
    technologies = item.get("tech", item.get("technologies", []))
    if not isinstance(technologies, list):
        technologies = []
    response_time = item.get("time", item.get("response_time"))
    response_headers = _normalise_headers(item)
    return {
        "hostname": hostname,
        "url": url,
        "final_url": url,
        "status": ObservationStatus.SUCCESS,
        "classification": classification,
        "status_code": status_code,
        "title": item.get("title") if isinstance(item.get("title"), str) else None,
        "web_server": item.get("webserver", item.get("web_server")) if isinstance(item.get("webserver", item.get("web_server")), str) else None,
        "technologies": sorted({str(value) for value in technologies}),
        "response_time": response_time,
        "headers": response_headers,
        "response_headers_status": "observed" if response_headers else "not_collected",
        "redirect_url": redirect_url,
        "redirect_allowed": redirect_allowed if isinstance(raw_location, str) and raw_location else None,
        "redirect_error": redirect_error,
        "ip": expected_ip,
        "tls": tls,
        "error": None,
    }


def export_live_inventory(records: list[dict[str, Any]]) -> tuple[str, str]:
    fields = [
        "hostname", "sources", "url", "classification", "status_code", "title", "web_server",
        "technologies", "response_time", "headers", "response_headers_status", "redirect_url", "redirect_allowed", "ip",
        "tls_version", "tls_subject_dn", "tls_issuer_dn", "tls_serial",
        "tls_not_before", "tls_not_after", "final_url", "error",
    ]
    csv_rows: list[dict[str, Any]] = []
    text_lines = ["DomainRecon V2 Live Web Inventory", f"Observations: {len(records)}", ""]
    for record in records:
        tls = record.get("tls", {}) if isinstance(record.get("tls"), dict) else {}
        row = {key: record.get(key) for key in fields if not key.startswith("tls_")}
        row.update({key: tls.get(key.removeprefix("tls_")) for key in fields if key.startswith("tls_")})
        row["sources"] = ";".join(str(value) for value in record.get("sources", [])) if isinstance(record.get("sources"), list) else ""
        row["technologies"] = ";".join(str(value) for value in record.get("technologies", [])) if isinstance(record.get("technologies"), list) else ""
        row["headers"] = json.dumps(record.get("headers", {}), sort_keys=True, separators=(",", ":")) if isinstance(record.get("headers"), dict) else ""
        # Titles, server banners, headers, redirect URLs and errors are remote-controlled;
        # render_csv neutralizes every cell so spreadsheets never evaluate them as formulas.
        csv_rows.append(row)
        text_lines.append(
            f"{record.get('classification')} {record.get('url')} | status={record.get('status_code') or '-'}"
            f" | ip={record.get('ip') or '-'} | final={record.get('final_url') or '-'}"
            f" | response_headers={record.get('response_headers_status', 'not_collected')}"
        )
        if record.get("title"):
            text_lines.append(f"  title={record['title']}")
        if record.get("redirect_url"):
            text_lines.append(f"  redirect={record['redirect_url']} allowed={record.get('redirect_allowed')}")
        if record.get("error"):
            text_lines.append(f"  error={record['error']}")
    if not records:
        text_lines.append("No eligible discovered hostname had a validated public DNS address.")
    return render_csv(fields, csv_rows), "\n".join(text_lines) + "\n"


def probe_httpx(
    executable: Path,
    scope: ScopePolicy,
    authorization: ActiveAuthorization,
    passive_records: list[dict[str, Any]],
    dns_records: list[dict[str, Any]],
    *,
    threads: int = 2,
    rate_limit: int = 2,
) -> list[dict[str, Any]]:
    """Probe only same-run passive hosts, with validated IPv4/IPv6 addresses pinned in HTTPX input.

    ``threads`` and ``rate_limit`` may only be lowered (engagement limits); both are capped at 2.
    IPv6 answers are probed only when the binary passes the IPv6 loopback pinning gate.
    """
    if authorization.root_domain != scope.root_domain or not authorization.is_valid():
        raise AuthorizationRequired("Active HTTP/TLS probing requires explicit scoped authorization.")

    discovered_hosts: set[str] = set()
    results: list[dict[str, Any]] = []
    sources_by_host: dict[str, set[str]] = {}
    for record in passive_records:
        if not isinstance(record, dict) or not isinstance(record.get("hostname"), str):
            continue
        raw_hostname = record["hostname"]
        if not scope.permits_hostname(raw_hostname):
            results.append({
                "hostname": raw_hostname, "status": ObservationStatus.BLOCKED,
                "classification": "ACCESS_RESTRICTED", "error": "Passive input is outside the authorized scope.",
            })
            continue
        discovered_hosts.add(scope.require_hostname(raw_hostname))
        source_values = record.get("sources", [])
        if isinstance(source_values, list):
            sources_by_host.setdefault(scope.require_hostname(raw_hostname), set()).update(str(value) for value in source_values)
    dns_by_host = {
        scope.require_hostname(record["hostname"]): record
        for record in dns_records
        if isinstance(record, dict) and isinstance(record.get("hostname"), str)
        and scope.permits_hostname(record["hostname"])
    }
    eligible: dict[str, set[str]] = {}
    for host in sorted(discovered_hosts):
        record = dns_by_host.get(host)
        if record is None or str(record.get("status", "")) != str(ObservationStatus.SUCCESS):
            error = "No successful DNSx result for this discovered hostname."
            results.append({"hostname": host, "status": ObservationStatus.SKIPPED, "classification": "ACCESS_RESTRICTED", "error": error})
            continue
        try:
            answers = _public_answers(scope, record)
        except ScopeViolation as exc:
            results.append({"hostname": host, "status": ObservationStatus.BLOCKED, "classification": "ACCESS_RESTRICTED", "error": str(exc)})
            continue
        if not answers:
            results.append({"hostname": host, "status": ObservationStatus.SKIPPED, "classification": "ACCESS_RESTRICTED", "error": "No validated public DNS address."})
            continue
        eligible[host] = answers

    def with_sources(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for observation in items:
            host = observation.get("hostname")
            if isinstance(host, str) and host in sources_by_host:
                observation["sources"] = sorted(sources_by_host[host])
        return items

    if not eligible:
        return with_sources(results)

    check_httpx_pinning(executable)
    ipv6_status = "not_needed"
    if any(":" in address for addresses in eligible.values() for address in addresses):
        try:
            check_httpx_pinning(executable, ipv6=True)
            ipv6_status = "verified"
        except (OSError, RuntimeError) as exc:
            ipv6_status = f"not_verified: {exc}"
            for host, addresses in sorted(eligible.items()):
                for address in sorted(a for a in addresses if ":" in a):
                    results.append({
                        "hostname": host, "ip": address, "final_url": None, "status": ObservationStatus.SKIPPED, "classification": "IPV6_NOT_PROBED",
                        "error": "The HTTPX binary did not pass the IPv6 loopback pinning gate; this IPv6 answer was recorded but not probed.",
                    })
            eligible = {host: {a for a in addresses if ":" not in a} for host, addresses in eligible.items()}
    revalidated: dict[str, set[str]] = {}
    for host, addresses in eligible.items():
        try:
            revalidated[host] = {scope.require_httpx_ip(address) for address in addresses}
        except ScopeViolation as exc:
            results.append({
                "hostname": host, "status": ObservationStatus.BLOCKED,
                "classification": "ACCESS_RESTRICTED", "error": f"Pre-execution IP revalidation failed: {exc}",
            })
    eligible = {host: addresses for host, addresses in revalidated.items() if addresses}
    if not eligible:
        return with_sources(results)

    target_index: dict[tuple[str, str, str], str] = {}
    input_lines: list[str] = []
    for host, addresses in sorted(eligible.items()):
        for address in sorted(addresses):
            for scheme in ("https", "http"):
                target = f"{scheme}://{host}/"
                key = (scheme, host, address)
                target_index[key] = host
                input_lines.append(json.dumps({"target": target, "ip": address}, separators=(",", ":")))

    threads = max(1, min(int(threads), 2))
    rate_limit = max(1, min(int(rate_limit), 2))
    # Budget: one request per target at the configured rate plus the 5 s per-request timeout, bounded to one hour.
    run_timeout = min(3600, max(300, len(input_lines) // rate_limit + 6 * len(input_lines) // threads + 60))
    timed_out = False
    input_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".jsonl", delete=False) as handle:
            input_name = handle.name
            os.chmod(input_name, 0o600)
            handle.write("\n".join(input_lines) + "\n")
        command = [
            str(executable), "-l", input_name, *_HTTP_FLAGS, "-x", "GET",
            "-threads", str(threads), "-rate-limit", str(rate_limit), "-timeout", "5", "-retries", "0",
            "-no-fallback-scheme", "-no-stdin", "-duc",
        ]
        try:
            run = subprocess.run(
                command, shell=False, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=run_timeout, check=False,
                env=_clean_environment(),
            )
            stdout_text, stderr_text = run.stdout, run.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            partial = exc.stdout or ""
            stdout_text = partial.decode("utf-8", "replace") if isinstance(partial, bytes) else partial
            stderr_text = f"HTTPX exceeded the {run_timeout}s batch limit; observations returned before the limit were kept."
        except OSError as exc:
            return with_sources(results + [
                {"hostname": host, "final_url": None, "status": ObservationStatus.FAILED, "classification": "ACCESS_RESTRICTED", "error": str(exc)}
                for host in eligible
            ])
    finally:
        if input_name:
            try:
                Path(input_name).unlink(missing_ok=True)
            except OSError:
                pass

    seen: set[tuple[str, str, str]] = set()
    for line in stdout_text.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        key = _target_key(item)
        if key is None:
            continue
        host = target_index.get(key)
        if host is None:
            continue
        result = _normalise_observation(scope, item, key, discovered_hosts, eligible)
        result["ip_version"] = 6 if ":" in key[2] else 4
        results.append(result)
        seen.add(key)

    stderr = stderr_text.strip()
    for key, host in target_index.items():
        if key in seen:
            continue
        message = stderr or "HTTPX returned no per-target JSON observation."
        classification = "TIMEOUT" if timed_out else _classify_error(message)
        results.append({
            "hostname": host, "url": f"{key[0]}://{host}/", "final_url": None,
            "ip": key[2], "status": ObservationStatus.TIMEOUT if timed_out else ObservationStatus.FAILED, "classification": classification,
            "error": message, "ipv6_pinning": ipv6_status if ":" in key[2] else None,
        })
    return with_sources(results)
