"""Authorized, IP-pinned TLS certificate collection (single handshake per endpoint, no HTTP).

Each connection is made to a literal, ScopePolicy-validated IPv4/IPv6 address (so no DNS lookup
or rebinding can occur) with the in-scope hostname as TLS SNI. Certificates are retrieved without
validation so that invalid certificates can be reported. Optional protocol-version testing uses one
handshake per version. Connections are sequential and rate limited.
"""
from __future__ import annotations

import base64
import socket
import ssl
import time
import warnings
from typing import Any, Callable

from domainrecon.core.errors import AuthorizationRequired, ScopeViolation
from domainrecon.core.scope import ScopePolicy

TLS_ACK = "I AUTHORIZE TLS INSPECTION"
MAX_TARGETS = 512
with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)  # legacy versions are referenced only to detect server support
    _VERSIONS = (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1), ("TLSv1.2", ssl.TLSVersion.TLSv1_2), ("TLSv1.3", ssl.TLSVersion.TLSv1_3))


def _context(version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # evidence collection: invalid certificates must be observable
    if version is not None:
        context.set_ciphers("ALL:@SECLEVEL=0")  # client-side only, so legacy server support can be detected
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)  # TLS 1.0/1.1 are tested deliberately to report server support
            context.minimum_version = version
            context.maximum_version = version
    return context


def _handshake(ip: str, port: int, hostname: str, timeout: float, version: ssl.TLSVersion | None = None) -> dict[str, Any]:
    with socket.create_connection((ip, port), timeout=timeout) as raw:
        with _context(version).wrap_socket(raw, server_hostname=hostname) as tls:
            der = tls.getpeercert(binary_form=True)
            chain = getattr(tls, "get_unverified_chain", None)
            chain_der = [base64.b64encode(cert if isinstance(cert, bytes) else cert.public_bytes()).decode() for cert in (chain() or [])] if callable(chain) else None
            return {"der": der, "version": tls.version(), "cipher": (tls.cipher() or [None])[0], "chain": chain_der}


def probe_tls(
    scope: ScopePolicy, targets: list[dict[str, Any]], *, acknowledgement: str, timeout: float = 5.0,
    requests_per_second: float = 2.0, test_protocols: bool = True, progress: Callable[[str], None] | None = None,
) -> list[dict[str, Any]]:
    """Collect certificates from ``[{"hostname", "ip", "port"}]`` targets; validates every target first."""
    if acknowledgement != TLS_ACK:
        raise AuthorizationRequired(f"TLS inspection requires the exact acknowledgement '{TLS_ACK}'.")
    if not 0 < requests_per_second <= 10:
        raise ValueError("TLS requests_per_second must be within (0, 10].")
    if len(targets) > MAX_TARGETS:
        raise ScopeViolation(f"At most {MAX_TARGETS} TLS endpoints may be inspected in one operation.")
    validated: list[tuple[str, str, int]] = []
    results: list[dict[str, Any]] = []
    for target in targets:
        try:
            hostname = scope.require_hostname(str(target.get("hostname", "")))
            ip = scope.require_httpx_ip(str(target.get("ip", "")))
            port = int(target.get("port", 443))
            if not 1 <= port <= 65535:
                raise ScopeViolation("TLS port must be within 1-65535.")
        except (ScopeViolation, ValueError, TypeError) as exc:
            results.append({"hostname": target.get("hostname"), "ip": target.get("ip"), "port": target.get("port"), "status": "blocked", "error": str(exc)})
            continue
        if (hostname, ip, port) not in validated:
            validated.append((hostname, ip, port))
    interval = 1.0 / requests_per_second
    last = 0.0

    def pace() -> None:
        nonlocal last
        wait = interval - (time.monotonic() - last)
        if wait > 0:
            time.sleep(wait)
        last = time.monotonic()

    for hostname, ip, port in validated:
        row: dict[str, Any] = {"hostname": hostname, "ip": ip, "port": port, "source": "tls_probe", "ip_version": 6 if ":" in ip else 4}
        pace()
        try:
            handshake = _handshake(ip, port, hostname, timeout)
        except (OSError, ssl.SSLError) as exc:
            results.append({**row, "status": "failed", "error": f"{type(exc).__name__}: {exc}"})
            continue
        row.update({
            "status": "success", "tls_version": handshake["version"], "cipher": handshake["cipher"],
            "certificate_der_b64": base64.b64encode(handshake["der"]).decode() if handshake["der"] else None,
            "chain_der_b64": handshake["chain"], "chain_status": "collected" if handshake["chain"] else "not_available_in_python_runtime",
        })
        if test_protocols:
            support: dict[str, str] = {}
            for name, version in _VERSIONS:
                pace()
                try:
                    accepted = _handshake(ip, port, hostname, timeout, version)["version"]
                    support[name] = "accepted" if accepted else "rejected"
                except ssl.SSLError as exc:
                    text = str(exc).lower()
                    support[name] = "client_unsupported" if "no protocols available" in text or "unsupported protocol" in text and "server" not in text else "rejected"
                except ValueError:
                    support[name] = "client_unsupported"
                except OSError:
                    support[name] = "connection_failed"
            row["supported_protocols"] = support
        results.append(row)
        if progress:
            progress(f"{hostname} {ip}:{port} {row['tls_version']}")
    return results
