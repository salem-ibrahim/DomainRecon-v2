"""Certificate and TLS intelligence (offline analysis; stdlib-only X.509 DER parsing).

Inputs are TLS observations from the authorized pinned TLS collector (``collectors.tls_probe``,
full DER certificate) and/or stored HTTPX ``tls`` fields (subject/issuer/validity/SANs only).
Certificates are deduplicated by SHA-256 fingerprint (or serial+issuer for HTTPX-only evidence)
and associated with every hostname/IP/port where they were observed. Signatures and chains are
NOT cryptographically verified; "self-signed" means subject == issuer.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

from domainrecon.intelligence.mitre_mapping import techniques_for

SCHEMA_ID = "domainrecon.certificate_intelligence"
SCHEMA_VERSION = 1
_NAME_OIDS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "1.2.840.113549.1.9.1": "emailAddress"}
_SIG_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448",
}
_KEY_OIDS = {"1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC", "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448", "1.2.840.10040.4.1": "DSA"}
_CURVES = {"1.2.840.10045.3.1.7": ("P-256", 256), "1.3.132.0.34": ("P-384", 384), "1.3.132.0.35": ("P-521", 521), "1.3.132.0.10": ("secp256k1", 256)}
_WEAK_SIGNATURES = {"md5WithRSAEncryption", "sha1WithRSAEncryption", "ecdsa-with-SHA1"}
_LEGACY_PROTOCOLS = {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}


class DerError(ValueError):
    pass


def _tlv(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 2 > len(data):
        raise DerError("truncated DER")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise DerError("unsupported DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise DerError("DER value exceeds buffer")
    return tag, offset, offset + length


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    items = []
    while start < end:
        tag, value_start, value_end = _tlv(data, start)
        items.append((tag, value_start, value_end))
        start = value_end
    return items


def _oid(raw: bytes) -> str:
    if not raw:
        raise DerError("empty OID")
    parts = [raw[0] // 40, raw[0] % 40] if raw[0] < 80 else [2, raw[0] - 80]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(part) for part in parts)


def _string(tag: int, raw: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return raw.decode("utf-16-be", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _name(data: bytes, start: int, end: int) -> tuple[str, dict[str, list[str]]]:
    attributes: dict[str, list[str]] = {}
    parts: list[str] = []
    for _set_tag, set_start, set_end in _children(data, start, end):
        for _seq_tag, seq_start, seq_end in _children(data, set_start, set_end):
            items = _children(data, seq_start, seq_end)
            if len(items) < 2:
                continue
            oid = _oid(data[items[0][1]:items[0][2]])
            label = _NAME_OIDS.get(oid, oid)
            value = _string(items[1][0], data[items[1][1]:items[1][2]])
            attributes.setdefault(label, []).append(value)
            parts.append(f"{label}={value}")
    return ", ".join(parts), attributes


def _time(tag: int, raw: bytes) -> str:
    text = raw.decode("ascii")
    if tag == 0x17:  # UTCTime
        year = int(text[:2])
        text = ("19" if year >= 50 else "20") + text
    parsed = datetime.strptime(text.rstrip("Z")[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    return parsed.isoformat()


def parse_certificate_der(der: bytes) -> dict[str, Any]:
    """Parse the fields DomainRecon reports from an X.509 v3 certificate (no signature verification)."""
    _tag, cert_start, cert_end = _tlv(der, 0)
    top = _children(der, cert_start, cert_end)
    if len(top) != 3:
        raise DerError("not an X.509 certificate")
    tbs = _children(der, top[0][1], top[0][2])
    index = 1 if tbs and tbs[0][0] == 0xA0 else 0
    version = 1
    if index:
        _vt, vs, ve = _children(der, tbs[0][1], tbs[0][2])[0]
        version = int.from_bytes(der[vs:ve], "big") + 1
    serial = der[tbs[index][1]:tbs[index][2]].hex().lstrip("0") or "0"
    sig_alg_oid = _oid(der[_children(der, top[1][1], top[1][2])[0][1]:_children(der, top[1][1], top[1][2])[0][2]])
    issuer_start, issuer_end = tbs[index + 2][1], tbs[index + 2][2]
    validity = _children(der, tbs[index + 3][1], tbs[index + 3][2])
    subject_start, subject_end = tbs[index + 4][1], tbs[index + 4][2]
    issuer_dn, _issuer_attrs = _name(der, issuer_start, issuer_end)
    subject_dn, subject_attrs = _name(der, subject_start, subject_end)
    spki = _children(der, tbs[index + 5][1], tbs[index + 5][2])
    alg = _children(der, spki[0][1], spki[0][2])
    key_oid = _oid(der[alg[0][1]:alg[0][2]])
    key_algorithm = _KEY_OIDS.get(key_oid, key_oid)
    key_size: int | None = None
    curve: str | None = None
    if key_algorithm == "RSA":
        bit_string = der[spki[1][1] + 1:spki[1][2]]
        rsa = _children(bit_string, *_tlv(bit_string, 0)[1:])
        modulus = bit_string[rsa[0][1]:rsa[0][2]].lstrip(b"\x00")
        key_size = len(modulus) * 8 - (8 - modulus[0].bit_length()) if modulus else None
    elif key_algorithm == "EC" and len(alg) > 1 and alg[1][0] == 0x06:
        curve, key_size = _CURVES.get(_oid(der[alg[1][1]:alg[1][2]]), (_oid(der[alg[1][1]:alg[1][2]]), None))
    elif key_algorithm in {"Ed25519", "Ed448"}:
        key_size = 256 if key_algorithm == "Ed25519" else 456
    dns_names: list[str] = []
    ip_names: list[str] = []
    is_ca = False
    for tag, start, end in tbs[index + 6:]:
        if tag != 0xA3:
            continue
        for _ext_tag, ext_start, ext_end in _children(der, *_children(der, start, end)[0][1:]):
            fields = _children(der, ext_start, ext_end)
            oid = _oid(der[fields[0][1]:fields[0][2]])
            octets = fields[-1]
            inner = der[octets[1]:octets[2]]
            if oid == "2.5.29.17":
                for name_tag, ns, ne in _children(inner, *_tlv(inner, 0)[1:]):
                    if name_tag == 0x82:
                        dns_names.append(inner[ns:ne].decode("ascii", errors="replace").lower())
                    elif name_tag == 0x87:
                        ip_names.append(str(ipaddress.ip_address(inner[ns:ne])))
            elif oid == "2.5.29.19":
                constraints = _children(inner, *_tlv(inner, 0)[1:])
                is_ca = bool(constraints and constraints[0][0] == 0x01 and inner[constraints[0][1]] != 0)
    return {
        "version": version, "serial": serial, "signature_algorithm": _SIG_OIDS.get(sig_alg_oid, sig_alg_oid),
        "issuer_dn": issuer_dn, "subject_dn": subject_dn, "subject_cn": (subject_attrs.get("CN") or [None])[0],
        "not_before": _time(validity[0][0], der[validity[0][1]:validity[0][2]]), "not_after": _time(validity[1][0], der[validity[1][1]:validity[1][2]]),
        "key_algorithm": key_algorithm, "key_size": key_size, "curve": curve, "dns_names": sorted(set(dns_names)), "ip_addresses": sorted(set(ip_names)),
        "is_ca": is_ca, "self_issued": der[issuer_start:issuer_end] == der[subject_start:subject_end],
        "sha256_fingerprint": hashlib.sha256(der).hexdigest(),
    }


def hostname_matches(hostname: str, dns_names: list[str], subject_cn: str | None, ip_names: list[str] | None = None) -> bool:
    """RFC 6125-style matching: SAN dNSName (single left-most wildcard label); CN only without SANs."""
    host = hostname.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host in (ip_names or [])
    except ValueError:
        pass
    names = dns_names or ([subject_cn.lower()] if subject_cn else [])
    for name in names:
        name = name.rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:] and name.count(".") >= 2:
            return True
    return False


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    for candidate in (value.replace("Z", "+00:00"),):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _certificate_from_observation(observation: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    der_b64 = observation.get("certificate_der_b64")
    if isinstance(der_b64, str):
        try:
            return parse_certificate_der(base64.b64decode(der_b64)), "tls_probe_der"
        except (DerError, ValueError, IndexError) as exc:
            return {"parse_error": str(exc)}, "tls_probe_der"
    tls = observation.get("tls") if isinstance(observation.get("tls"), dict) else observation
    if not any(tls.get(key) for key in ("subject_dn", "issuer_dn", "not_after", "dns_names")):
        return None, "none"
    dns_names = tls.get("dns_names") or tls.get("subject_an") or []
    subject_dn = tls.get("subject_dn")
    cn = tls.get("subject_cn") or (subject_dn.split("CN=", 1)[1].split(",")[0].strip() if isinstance(subject_dn, str) and "CN=" in subject_dn else None)
    return {
        "subject_dn": subject_dn, "issuer_dn": tls.get("issuer_dn"), "subject_cn": cn, "serial": tls.get("serial"),
        "not_before": tls.get("not_before"), "not_after": tls.get("not_after"),
        "dns_names": sorted({str(n).lower() for n in dns_names}) if isinstance(dns_names, list) else [],
        "ip_addresses": [], "key_algorithm": None, "key_size": None, "signature_algorithm": None,
        "self_issued": bool(subject_dn and subject_dn == tls.get("issuer_dn")), "sha256_fingerprint": tls.get("fingerprint_hash", {}).get("sha256") if isinstance(tls.get("fingerprint_hash"), dict) else None,
    }, "httpx_tls_fields"


def _finding(kind: str, category: str, severity: str, asset: str, cert_id: str, evidence: dict[str, Any], confidence: str, remediation: str) -> dict[str, Any]:
    digest = hashlib.sha256(f"{kind}|{asset}|{cert_id}".encode()).hexdigest()[:16]
    return {"finding_id": f"tls-{digest}", "type": kind, "category": category, "severity": severity, "asset_id": asset, "certificate_id": cert_id,
            "evidence": evidence, "confidence": confidence, "recommended_remediation": remediation, "mitre_attack": techniques_for(category), "source": "certificate_intelligence"}


def analyze_certificates(observations: list[dict[str, Any]], *, now: datetime | None = None, expiry_warning_days: int = 30) -> dict[str, Any]:
    current = now or datetime.now(timezone.utc)
    certificates: dict[str, dict[str, Any]] = {}
    findings: list[dict[str, Any]] = []
    protocol_rows: list[dict[str, Any]] = []
    for observation in observations:
        if not isinstance(observation, dict):
            continue
        cert, source = _certificate_from_observation(observation)
        host, ip, port = observation.get("hostname"), observation.get("ip"), observation.get("port", 443)
        asset = f"{host}:{port}" if host else f"{ip}:{port}"
        if observation.get("supported_protocols"):
            protocol_rows.append({"asset": asset, "ip": ip, "supported_protocols": observation["supported_protocols"]})
            accepted = sorted(name for name, state in observation["supported_protocols"].items() if state == "accepted" and name in _LEGACY_PROTOCOLS)
            if accepted:
                findings.append(_finding("legacy_tls_protocol_accepted", "weak_tls", "MEDIUM", asset, "n/a", {"accepted_legacy_protocols": accepted, "ip": ip, "source": "tls_probe"}, "high", "Disable TLS 1.0/1.1 (and SSL) on this endpoint; require TLS 1.2 or newer."))
        if cert is None or "parse_error" in (cert or {}):
            continue
        cert_id = cert.get("sha256_fingerprint") or hashlib.sha256(f"{cert.get('serial')}|{cert.get('issuer_dn')}".encode()).hexdigest()
        entry = certificates.setdefault(cert_id, {**cert, "certificate_id": cert_id, "evidence_source": source, "observed_on": []})
        association = {"hostname": host, "ip": ip, "port": port, "source": source, "tls_version": observation.get("tls_version"), "cipher": observation.get("cipher")}
        if association not in entry["observed_on"]:
            entry["observed_on"].append(association)
        confidence = "high" if source == "tls_probe_der" else "medium"
        not_after, not_before = _parse_time(cert.get("not_after")), _parse_time(cert.get("not_before"))
        evidence = {"subject_dn": cert.get("subject_dn"), "issuer_dn": cert.get("issuer_dn"), "not_before": cert.get("not_before"), "not_after": cert.get("not_after"), "ip": ip, "source": source}
        if not_after and not_after <= current:
            findings.append(_finding("certificate_expired", "certificate_issue", "HIGH", asset, cert_id, evidence, confidence, "Renew and deploy a valid certificate."))
        elif not_after and not_after - current <= timedelta(days=expiry_warning_days):
            findings.append(_finding("certificate_expiring_soon", "certificate_issue", "LOW", asset, cert_id, {**evidence, "days_remaining": (not_after - current).days}, confidence, "Schedule certificate renewal before expiry."))
        if not_before and not_before > current:
            findings.append(_finding("certificate_not_yet_valid", "certificate_issue", "MEDIUM", asset, cert_id, evidence, confidence, "Check the certificate validity period and server clock."))
        if cert.get("self_issued") and not cert.get("is_ca", False):
            findings.append(_finding("self_signed_certificate", "certificate_issue", "MEDIUM", asset, cert_id, evidence, "medium", "Use a certificate issued by a trusted CA for public services."))
        if host and (cert.get("dns_names") or cert.get("subject_cn")) and not hostname_matches(host, cert.get("dns_names", []), cert.get("subject_cn"), cert.get("ip_addresses")):
            findings.append(_finding("certificate_hostname_mismatch", "certificate_issue", "MEDIUM", asset, cert_id, {**evidence, "dns_names": cert.get("dns_names"), "subject_cn": cert.get("subject_cn")}, confidence, "Issue a certificate whose SANs cover this hostname, or stop serving the hostname from this endpoint."))
        if cert.get("key_algorithm") == "RSA" and isinstance(cert.get("key_size"), int) and cert["key_size"] < 2048 or cert.get("key_algorithm") == "EC" and isinstance(cert.get("key_size"), int) and cert["key_size"] < 256:
            findings.append(_finding("weak_certificate_key", "weak_tls", "MEDIUM", asset, cert_id, {**evidence, "key_algorithm": cert.get("key_algorithm"), "key_size": cert.get("key_size")}, "high", "Reissue the certificate with RSA >= 2048 bits or ECDSA P-256 or stronger."))
        if cert.get("signature_algorithm") in _WEAK_SIGNATURES:
            findings.append(_finding("weak_certificate_signature", "weak_tls", "MEDIUM", asset, cert_id, {**evidence, "signature_algorithm": cert.get("signature_algorithm")}, "high", "Reissue the certificate with a SHA-256 or stronger signature."))
        if observation.get("tls_version") in _LEGACY_PROTOCOLS:
            findings.append(_finding("legacy_tls_negotiated", "weak_tls", "MEDIUM", asset, cert_id, {"tls_version": observation.get("tls_version"), "ip": ip}, "high", "Disable legacy TLS versions."))
    unique: dict[str, dict[str, Any]] = {}
    for finding in findings:
        unique.setdefault(finding["finding_id"], finding)
    return {
        "schema_id": SCHEMA_ID, "schema_version": SCHEMA_VERSION, "generated_at": current.isoformat(), "status": "success" if observations else "not_available",
        "certificates": sorted(certificates.values(), key=lambda row: row["certificate_id"]), "protocol_support": protocol_rows,
        "findings": sorted(unique.values(), key=lambda row: row["finding_id"]), "observation_count": len(observations),
        "limitations": [
            "Certificate signatures and chains are not cryptographically validated; 'self-signed' means subject equals issuer.",
            "HTTPX-sourced certificates lack key/signature details; only the pinned TLS collector provides full DER evidence.",
            "Certificate chains are reported only when the Python runtime exposes them (Python 3.13+).",
            "A protocol reported 'client_unsupported' could not be tested by the local TLS library; it is not evidence of server support or absence.",
        ],
    }
