"""The sole host/IP authorization boundary used by every v2 network stage."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .errors import ScopeViolation
from .public_suffix import public_suffix_reason

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.IGNORECASE)
_ALLOWED_PORTS = frozenset({80, 443})
_DKIM_SELECTOR = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))?$")


def canonical_domain(value: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise ScopeViolation("Domain input must be non-empty text without surrounding whitespace.")
    if value.startswith("*.") or any(char in value for char in "/:@\\&|;`$<>'\""):
        raise ScopeViolation("Wildcards, URLs, ports, and command metacharacters are not domain names.")
    candidate = value.rstrip(".")
    if not candidate or len(candidate) > 253 or "." not in candidate:
        raise ScopeViolation("Enter a registrable DNS domain.")
    try:
        result = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeViolation("Domain is not valid IDNA.") from exc
    labels = result.split(".")
    if len(labels[-1]) < 2 or any(not _LABEL.fullmatch(label) for label in labels):
        raise ScopeViolation("Domain contains an invalid DNS label.")
    return result


def canonical_hostname(value: str) -> str:
    """Strictly canonicalize a concrete hostname; wildcard names are rejected."""
    return canonical_domain(value)


@dataclass(frozen=True)
class ScopePolicy:
    root_domain: str
    allow_loopback_for_lab: bool = False
    # Engagement-driven narrowing only: exclusions and optional authorized IP ranges can
    # remove targets from scope, never add targets outside the root domain.
    excluded_hostnames: frozenset[str] = frozenset()
    excluded_networks: tuple[str, ...] = ()
    authorized_networks: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.allow_loopback_for_lab) is not bool:
            raise ScopeViolation("allow_loopback_for_lab must be an explicit boolean.")
        root = canonical_domain(self.root_domain)
        try:
            reason = public_suffix_reason(root)
        except (OSError, ValueError) as exc:
            # An operator-pinned list (DOMAINRECON_PSL_FILE) that is missing or fails integrity checks fails closed.
            raise ScopeViolation(f"Public Suffix List unavailable or failed integrity verification ({exc}); no root can be accepted until it is fixed.") from exc
        if reason is not None:
            raise ScopeViolation(f"{root} is a public/registry suffix and cannot be an authorized root ({reason}). Enter a registrable domain such as example.{root}.")
        object.__setattr__(self, "root_domain", root)
        object.__setattr__(self, "excluded_hostnames", frozenset(canonical_hostname(name) for name in self.excluded_hostnames))
        for field_name in ("excluded_networks", "authorized_networks"):
            networks: list[str] = []
            for value in getattr(self, field_name):
                try:
                    networks.append(str(ipaddress.ip_network(str(value).strip(), strict=False)))
                except ValueError as exc:
                    raise ScopeViolation(f"Invalid network in {field_name}: {value}") from exc
            object.__setattr__(self, field_name, tuple(networks))

    def is_excluded_hostname(self, hostname: str) -> bool:
        return any(hostname == excluded or hostname.endswith("." + excluded) for excluded in self.excluded_hostnames)

    def ip_exclusion_reason(self, address: str) -> str | None:
        """Return why an otherwise-public address is outside the engagement, or None."""
        parsed = ipaddress.ip_address(address)
        for network in self.excluded_networks:
            if parsed in ipaddress.ip_network(network):
                return f"{parsed.compressed} is in excluded network {network}"
        if self.authorized_networks and not any(parsed in ipaddress.ip_network(network) for network in self.authorized_networks if ipaddress.ip_network(network).version == parsed.version):
            return f"{parsed.compressed} is outside the engagement's authorized IP ranges"
        return None

    @staticmethod
    def classify_ip(address: str) -> dict[str, object]:
        """Classify an IPv4/IPv6 address; ``public`` is True only for globally routable unicast space."""
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return {"address": address, "version": None, "category": "invalid", "public": False}
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            category = "ipv4_mapped"
        elif parsed.is_loopback:
            category = "loopback"
        elif parsed.is_unspecified:
            category = "unspecified"
        elif parsed.is_multicast:
            category = "multicast"
        elif parsed.is_link_local:
            category = "link_local"
        elif parsed.version == 4 and parsed in ipaddress.ip_network("100.64.0.0/10"):
            category = "shared_cgnat"
        elif parsed.is_private:
            category = "private_or_documentation"
        elif parsed.is_reserved:
            category = "reserved"
        elif parsed.is_global:
            category = "public"
        else:
            category = "non_global"
        return {"address": parsed.compressed, "version": parsed.version, "category": category, "public": category == "public"}

    def require_dns_policy_name(self, name: str) -> str:
        """Validate the narrow set of underscore DNS policy names DomainRecon may query.

        Only ``_dmarc.<in-scope hostname>`` is accepted. This does not relax hostname
        validation anywhere else: such names are never probed over HTTP or scanned.
        """
        if not isinstance(name, str) or name != name.strip():
            raise ScopeViolation("DNS policy name must be text without surrounding whitespace.")
        candidate = name.rstrip(".").lower()
        label, separator, remainder = candidate.partition(".")
        if label == "_dmarc" and separator:
            return "_dmarc." + self.require_hostname(remainder)
        # DKIM: <operator-supplied selector>._domainkey.<in-scope host>; selectors are never guessed.
        selector, _sep, rest = candidate.partition("._domainkey.")
        if _sep and rest and _DKIM_SELECTOR.fullmatch(selector):
            return f"{selector}._domainkey." + self.require_hostname(rest)
        raise ScopeViolation("Only _dmarc.<host> and <selector>._domainkey.<host> DNS policy names are supported.")

    def permits_dns_policy_name(self, name: str) -> bool:
        try:
            self.require_dns_policy_name(name)
        except ScopeViolation:
            return False
        return True

    def permits_hostname(self, hostname: str, *, include_root: bool = True) -> bool:
        try:
            canonical = canonical_hostname(hostname)
        except ScopeViolation:
            return False
        if self.is_excluded_hostname(canonical):
            return False
        return canonical == self.root_domain or canonical.endswith("." + self.root_domain) if include_root else canonical.endswith("." + self.root_domain)

    def require_hostname(self, hostname: str, *, include_root: bool = True) -> str:
        canonical = canonical_hostname(hostname)
        if self.is_excluded_hostname(canonical):
            raise ScopeViolation(f"Hostname is explicitly excluded by the engagement: {canonical}")
        if not self.permits_hostname(canonical, include_root=include_root):
            raise ScopeViolation(f"Hostname is outside authorized root scope: {canonical}")
        return canonical

    def filter_hostnames(self, hostnames: list[str] | set[str] | tuple[str, ...]) -> list[str]:
        return sorted({name for raw in hostnames if self.permits_hostname(raw) for name in [canonical_hostname(raw)]})

    def require_public_ip(self, address: str) -> str:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ScopeViolation(f"Invalid IP address: {address}") from exc
        if (
            not parsed.is_global
            or parsed.is_loopback
            or parsed.is_private
            or parsed.is_link_local
            or parsed.is_multicast
            or parsed.is_reserved
            or parsed.is_unspecified
            or (isinstance(parsed, ipaddress.IPv6Address) and (parsed.ipv4_mapped is not None or parsed.sixtofour is not None or parsed.teredo is not None))
        ):
            # IPv4-mapped/6to4/Teredo IPv6 forms are blocked so IPv6 cannot tunnel around IPv4 policy.
            raise ScopeViolation(f"Non-public destination is blocked: {parsed.compressed}")
        reason = self.ip_exclusion_reason(parsed.compressed)
        if reason:
            raise ScopeViolation(f"Destination outside engagement scope: {reason}")
        return parsed.compressed

    def require_httpx_ip(self, address: str) -> str:
        """Validate an HTTPX destination; only explicit lab policy permits IPv4 loopback."""
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ScopeViolation(f"Invalid IP address: {address}") from exc
        if self.allow_loopback_for_lab and parsed.version == 4 and parsed.is_loopback and "%" not in address:
            return parsed.compressed
        return self.require_public_ip(parsed.compressed)

    def require_nmap_target(self, target: str) -> str:
        """Require an in-scope hostname; only explicit lab policy accepts loopback literals."""
        try:
            parsed = ipaddress.ip_address(target)
        except ValueError:
            return self.require_hostname(target)
        if self.allow_loopback_for_lab and parsed.version == 4 and parsed.is_loopback and "%" not in target:
            return parsed.compressed
        raise ScopeViolation("Nmap targets must be scoped hostnames; literal IP targets are blocked.")

    def require_nmap_ip(self, address: str) -> str:
        """Validate a resolved Nmap destination, allowing only loopback in explicit lab mode."""
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ScopeViolation(f"Invalid IP address: {address}") from exc
        if self.allow_loopback_for_lab and parsed.version == 4 and parsed.is_loopback and "%" not in address:
            return parsed.compressed
        return self.require_public_ip(parsed.compressed)

    def validate_root_url(self, url: str) -> tuple[str, int]:
        """Validate HTTP(S), default ports, root path, and hostname scope."""
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ScopeViolation("Only clean HTTP(S) root URLs are allowed.")
        if parsed.path not in {"", "/"}:
            raise ScopeViolation("Only the root path is allowed.")
        hostname = self.require_hostname(parsed.hostname or "")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError as exc:
            raise ScopeViolation("URL contains an invalid port.") from exc
        if port not in _ALLOWED_PORTS:
            raise ScopeViolation("Only ports 80 and 443 are allowed.")
        return hostname, port

    def validate_redirect(self, destination: str) -> tuple[str, int]:
        """Redirects are never trusted; callers must explicitly revalidate them."""
        return self.validate_root_url(destination)
