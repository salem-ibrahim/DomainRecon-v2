"""Minimal stdlib DNSSEC indicator query (DNSKEY and DS for the apex only).

Runs only against resolvers explicitly configured in the engagement (``dns.resolvers``); there is
no default resolver. It sends two EDNS0 queries with the DO bit and reports record counts, RRSIG
presence, and the resolver's AD (authenticated data) flag. It does not validate signatures itself.
"""
from __future__ import annotations

import ipaddress
import secrets
import socket
import struct
from typing import Any

from domainrecon.core.scope import ScopePolicy

QTYPE_DS, QTYPE_DNSKEY, QTYPE_RRSIG = 43, 48, 46


def _query(name: str, qtype: int) -> tuple[int, bytes]:
    ident = secrets.randbits(16)
    header = struct.pack("!HHHHHH", ident, 0x0120, 1, 0, 0, 1)  # RD + AD requested, one question, one OPT
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00" + struct.pack("!HH", qtype, 1)
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)  # EDNS0, DO bit
    return ident, header + question + opt


def _skip_name(packet: bytes, offset: int) -> int:
    while True:
        length = packet[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length


def parse_response(packet: bytes, ident: int, qtype: int) -> dict[str, Any]:
    response_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", packet[:12])
    if response_id != ident:
        raise ValueError("DNS response ID mismatch")
    offset = 12
    for _ in range(qdcount):
        offset = _skip_name(packet, offset) + 4
    count = rrsig = 0
    for _ in range(ancount):
        offset = _skip_name(packet, offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
        offset += 10 + rdlength
        count += rtype == qtype
        rrsig += rtype == QTYPE_RRSIG
    return {"rcode": flags & 0x000F, "ad_flag": bool(flags & 0x0020), "truncated": bool(flags & 0x0200), "answers": count, "rrsig": rrsig}


def query_dnssec(scope: ScopePolicy, resolver: str, *, timeout: float = 3.0) -> dict[str, Any]:
    resolver_ip = ipaddress.ip_address(resolver).compressed
    name = scope.require_hostname(scope.root_domain)
    result: dict[str, Any] = {"hostname": name, "resolver": resolver_ip, "source": "dnssec_probe"}
    family = socket.AF_INET6 if ":" in resolver_ip else socket.AF_INET
    try:
        answers = {}
        for label, qtype in (("dnskey", QTYPE_DNSKEY), ("ds", QTYPE_DS)):
            ident, packet = _query(name, qtype)
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                sock.sendto(packet, (resolver_ip, 53))
                data, _peer = sock.recvfrom(4096)
            answers[label] = parse_response(data, ident, qtype)
    except (OSError, ValueError, struct.error, IndexError) as exc:
        return {**result, "status": "failed", "error": f"{type(exc).__name__}: {exc}"}
    return {**result, "status": "success", "dnskey_count": answers["dnskey"]["answers"], "ds_count": answers["ds"]["answers"],
            "rrsig_present": bool(answers["dnskey"]["rrsig"] or answers["ds"]["rrsig"]), "ad_flag": answers["dnskey"]["ad_flag"] or answers["ds"]["ad_flag"],
            "truncated": answers["dnskey"]["truncated"] or answers["ds"]["truncated"]}
