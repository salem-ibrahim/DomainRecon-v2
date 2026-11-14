"""Bounded Nmap TCP discovery with strict scope, immutable evidence and resume data."""
from __future__ import annotations

import hashlib
import ipaddress
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Callable

from domainrecon.core.errors import AuthorizationRequired, ScopeViolation
from domainrecon.core.events import log_event
from domainrecon.core.scope import ScopePolicy


class TcpScanMode(StrEnum):
    COMMON = "common"
    FULL = "full"
    CUSTOM = "custom"


@dataclass(frozen=True)
class NmapScanOptions:
    mode: TcpScanMode = TcpScanMode.COMMON
    ports: str | None = None
    service_detection: bool = True
    max_rate: int = 100
    max_parallelism: int = 2
    timeout_seconds: int = 900

    def validate(self) -> None:
        if not 1 <= self.max_rate <= 1000 or not 1 <= self.max_parallelism <= 10 or not 30 <= self.timeout_seconds <= 7200:
            raise ValueError("Nmap limits must be conservative: rate 1-1000, parallelism 1-10, timeout 30-7200.")
        if self.mode is TcpScanMode.CUSTOM:
            if not self.ports or not _valid_ports(self.ports):
                raise ValueError("Custom TCP ports must be comma-separated ports or ranges within 1-65535.")
        elif self.ports is not None:
            raise ValueError("ports is valid only for custom scan mode.")


def _valid_ports(value: str) -> bool:
    for item in value.split(","):
        if not item or item.strip() != item:
            return False
        bounds = item.split("-")
        if len(bounds) > 2 or not all(bound.isdigit() for bound in bounds):
            return False
        numbers = [int(bound) for bound in bounds]
        if any(number < 1 or number > 65535 for number in numbers) or len(numbers) == 2 and numbers[0] > numbers[1]:
            return False
    return bool(value)


def nmap_version(executable: Path) -> str:
    """Query the local binary version only; this command has no scan target or network probes."""
    resolved = discover_nmap(executable)
    if resolved is None:
        return "not installed"
    try:
        result = subprocess.run([str(resolved), "--version"], shell=False, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable: {exc}"
    return (result.stdout or result.stderr).splitlines()[0].strip() if result.returncode == 0 else f"failed (exit {result.returncode})"


def discover_nmap(configured: Path | None = None) -> Path | None:
    """Find an explicit path, then PATH, then standard Windows installations."""
    candidates = [configured] if configured else []
    path_match = shutil.which("nmap")
    if path_match:
        candidates.append(Path(path_match))
    candidates.extend([Path(r"C:\Program Files (x86)\Nmap\nmap.exe"), Path(r"C:\Program Files\Nmap\nmap.exe")])
    return next((candidate for candidate in candidates if candidate and candidate.is_file()), None)


def _resolve_nmap_targets(scope: ScopePolicy, target: str) -> tuple[str, tuple[str, ...]]:
    """Resolve a scoped hostname to validated IPv4 literals; explicit lab scope allows loopback only."""
    if type(scope) is not ScopePolicy:
        raise ScopeViolation("Nmap requires the built-in ScopePolicy; custom policies are not accepted.")
    canonical_target = scope.require_nmap_target(target)
    try:
        literal = ipaddress.ip_address(canonical_target)
    except ValueError:
        try:
            answers = socket.getaddrinfo(canonical_target + ".", None, socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            raise ScopeViolation(f"DNS resolution failed for Nmap target {canonical_target}: {exc}") from exc
        raw_addresses = []
        for answer in answers:
            try:
                raw_addresses.append(answer[4][0])
            except (IndexError, TypeError) as exc:
                raise ScopeViolation("DNS returned a malformed Nmap address record.") from exc
        if not raw_addresses:
            raise ScopeViolation(f"DNS returned no IPv4 addresses for Nmap target {canonical_target}.")
    else:
        raw_addresses = [literal.compressed]

    addresses: set[str] = set()
    for raw_address in raw_addresses:
        address = scope.require_nmap_ip(raw_address)
        parsed = ipaddress.ip_address(address)
        if parsed.version != 4:
            raise ScopeViolation("This Nmap execution path accepts IPv4 targets only.")
        addresses.add(parsed.compressed)
    if not addresses:
        raise ScopeViolation(f"DNS returned no usable IPv4 addresses for Nmap target {canonical_target}.")
    return canonical_target, tuple(sorted(addresses, key=lambda value: int(ipaddress.IPv4Address(value))))


def _command(executable: Path, targets: tuple[str, ...], options: NmapScanOptions, xml_path: Path, normal_path: Path, *, scope: ScopePolicy, ipv6: bool = False) -> list[str]:
    """Build an Nmap command using only validated numeric IPv4 targets (or IPv6 targets with ``-6`` when enabled)."""
    if type(scope) is not ScopePolicy:
        raise ScopeViolation("Nmap requires the built-in ScopePolicy; custom policies are not accepted.")
    options.validate()
    if not targets:
        raise ScopeViolation("Nmap command requires at least one validated target address.")
    pinned_targets: list[str] = []
    for target in targets:
        address = scope.require_nmap_ip(target)
        parsed = ipaddress.ip_address(address)
        if address != target or parsed.version == 6 and not ipv6 or parsed.version not in (4, 6):
            raise ScopeViolation("Nmap command targets must be canonical IPv4 literals (IPv6 only when explicitly enabled).")
        pinned_targets.append(address)
    if len(set(pinned_targets)) != len(pinned_targets):
        raise ScopeViolation("Nmap command target list must not contain duplicate addresses.")
    families = {ipaddress.ip_address(address).version for address in pinned_targets}
    if len(families) > 1:
        raise ScopeViolation("IPv4 and IPv6 targets must be scanned in separate Nmap invocations.")
    command = [str(executable), *(["-6"] if families == {6} else []), "-sT", "-n", "--reason", "--max-rate", str(options.max_rate), "--max-parallelism", str(options.max_parallelism), "--host-timeout", f"{options.timeout_seconds}s", "-oX", str(xml_path), "-oN", str(normal_path)]
    if options.mode is TcpScanMode.COMMON:
        command.extend(["--top-ports", "100"])
    elif options.mode is TcpScanMode.FULL:
        command.append("-p-")
    else:
        command.extend(["-p", options.ports or ""])
    if options.service_detection:
        command.extend(["-sV", "--version-light"])
    command.extend(pinned_targets)
    return command


def _resume_targets(resume_file: Path, scope: ScopePolicy) -> tuple[str, ...]:
    """Extract only literal IPv4 targets from the single Nmap command header; fail closed otherwise."""
    return _parse_resume_command(resume_file, scope)[0]


def _resume_output_paths(resume_file: Path, values: dict[str, str]) -> dict[str, Path]:
    """Resolve the native output files Nmap will append to; they must sit beside the resume log."""
    base = resume_file.resolve().parent
    outputs: dict[str, Path] = {}
    for option in ("-oX", "-oN"):
        raw = Path(values[option])
        resolved = (raw if raw.is_absolute() else base / raw).resolve()
        if resolved.parent != base:
            raise ScopeViolation("Nmap resume output files must be located beside the resume log; resume cancelled.")
        outputs[option] = resolved
    return outputs


def _file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    except OSError:
        return None


def _parse_resume_command(resume_file: Path, scope: ScopePolicy) -> tuple[tuple[str, ...], dict[str, str]]:
    """Parse and validate the single Nmap command header; return pinned targets and option values."""
    try:
        content = resume_file.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise ScopeViolation(f"Unable to read Nmap resume evidence: {exc}") from exc
    headers = [line for line in content.splitlines() if line.startswith("# Nmap ") and " as:" in line]
    if len(headers) != 1:
        raise ScopeViolation("Nmap resume evidence must contain exactly one original command header.")
    try:
        tokens = shlex.split(headers[0].split(" as:", 1)[1].strip(), posix=True)
    except ValueError as exc:
        raise ScopeViolation("Nmap resume command header is malformed.") from exc
    if len(tokens) < 2:
        raise ScopeViolation("Nmap resume command header contains no target list.")

    flag_options = {"-sT", "-n", "--reason", "-sV", "--version-light", "-p-"}
    value_options = {"--max-rate", "--max-parallelism", "--host-timeout", "-oX", "-oN", "--top-ports", "-p"}
    command_tokens = tokens[1:]  # Ignore the executable path recorded by Nmap.
    targets: list[str] = []
    seen_flags: set[str] = set()
    seen_values: dict[str, str] = {}
    targets_started = False
    index = 0
    while index < len(command_tokens):
        token = command_tokens[index]
        if token in flag_options:
            if targets_started or token in seen_flags:
                raise ScopeViolation("Nmap resume command contains misplaced or duplicate options.")
            seen_flags.add(token)
            index += 1
            continue
        if token in value_options:
            if targets_started or token in seen_values:
                raise ScopeViolation("Nmap resume command contains misplaced or duplicate options.")
            if index + 1 >= len(command_tokens):
                raise ScopeViolation(f"Nmap resume command has no value for {token}.")
            value = command_tokens[index + 1]
            if not value or token in {"-oX", "-oN"} and value.startswith("-"):
                raise ScopeViolation(f"Nmap resume command has an invalid value for {token}.")
            if token == "--max-rate" and (not value.isdigit() or not 1 <= int(value) <= 1000):
                raise ScopeViolation("Nmap resume rate exceeds the bounded scan policy.")
            if token == "--max-parallelism" and (not value.isdigit() or not 1 <= int(value) <= 10):
                raise ScopeViolation("Nmap resume parallelism exceeds the bounded scan policy.")
            if token == "--host-timeout" and (not value.endswith("s") or not value[:-1].isdigit() or not 30 <= int(value[:-1]) <= 7200):
                raise ScopeViolation("Nmap resume timeout exceeds the bounded scan policy.")
            if token == "--top-ports" and value != "100":
                raise ScopeViolation("Nmap resume top-port count is outside the supported scan policy.")
            if token == "-p" and not _valid_ports(value):
                raise ScopeViolation("Nmap resume custom ports are outside the supported TCP policy.")
            seen_values[token] = value
            index += 2
            continue
        if token.startswith("-"):
            raise ScopeViolation(f"Nmap resume command contains unsupported option {token}.")
        targets_started = True
        try:
            parsed = ipaddress.ip_address(token)
        except ValueError as exc:
            raise ScopeViolation("Nmap resume targets must be pinned IPv4 literals.") from exc
        if parsed.version != 4:
            raise ScopeViolation("Nmap resume targets must be IPv4 literals.")
        address = scope.require_nmap_ip(parsed.compressed)
        if address != token:
            raise ScopeViolation("Nmap resume target is not a canonical IPv4 literal.")
        targets.append(address)
        index += 1
    required_flags = {"-sT", "-n", "--reason"}
    required_values = {"--max-rate", "--max-parallelism", "--host-timeout", "-oX", "-oN"}
    selectors = int("--top-ports" in seen_values) + int("-p" in seen_values) + int("-p-" in seen_flags)
    if (
        not targets
        or len(set(targets)) != len(targets)
        or not required_flags.issubset(seen_flags)
        or not required_values.issubset(seen_values)
        or selectors != 1
        or ("-sV" in seen_flags) != ("--version-light" in seen_flags)
    ):
        raise ScopeViolation("Nmap resume target list is empty or contains duplicates.")
    return tuple(sorted(targets, key=lambda value: int(ipaddress.IPv4Address(value)))), seen_values


def _parse_cpe(value: str) -> dict:
    """Preserve Nmap CPE evidence; parse fields only from the supplied string."""
    entry = {"original": value, "part": None, "vendor": None, "product": None, "version": None, "parse_status": "unparsed"}
    if value.startswith("cpe:/"):
        pieces = value[5:].split(":")
    elif value.startswith("cpe:2.3:"):
        pieces = value.split(":")[2:]
    else:
        return entry
    if len(pieces) < 4 or any(not piece for piece in pieces[:4]):
        return entry
    entry.update({"part": pieces[0], "vendor": pieces[1], "product": pieces[2], "version": pieces[3], "parse_status": "parsed"})
    return entry


def parse_nmap_xml(xml_path: Path, target: str) -> dict:
    root = ET.parse(xml_path).getroot()
    hosts: list[dict] = []
    for host in root.findall("host"):
        address = host.find("address")
        ports: list[dict] = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            cpes = [_parse_cpe(cpe.text) for cpe in service.findall("cpe") if cpe.text] if service is not None else []
            ports.append({
                "port": int(port.attrib["portid"]), "protocol": port.attrib.get("protocol", "tcp"),
                "state": state.attrib.get("state", "unknown") if state is not None else "unknown",
                "reason": state.attrib.get("reason") if state is not None else None,
                "service": service.attrib.get("name") if service is not None else None,
                "product": service.attrib.get("product") if service is not None else None,
                "version": service.attrib.get("version") if service is not None else None,
                "extrainfo": service.attrib.get("extrainfo") if service is not None else None,
                "ostype": service.attrib.get("ostype") if service is not None else None,
                "cpes": cpes,
            })
        hosts.append({"address": address.attrib.get("addr") if address is not None else None, "ports": ports})
    return {"schema_version": 1, "scanner": "nmap", "target": target, "hosts": hosts}


def run_nmap(
    executable: Path,
    scope: ScopePolicy,
    target: str,
    options: NmapScanOptions,
    evidence_directory: Path,
    *,
    active_acknowledgement: str,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """Run Nmap only when explicit active authorization and root scope both hold.

    XML is parsed into JSON-compatible data. Normal Nmap output remains as the
    resume token; Nmap itself accepts only that format for `--resume`.
    """
    if active_acknowledgement != "I AUTHORIZE PORT SCANNING":
        raise AuthorizationRequired("Nmap requires I AUTHORIZE PORT SCANNING.")
    if type(scope) is not ScopePolicy:
        raise ScopeViolation("Nmap requires the built-in ScopePolicy; custom policies are not accepted.")
    target = scope.require_nmap_target(target)
    options.validate()
    discovered = discover_nmap(executable)
    if discovered is None:
        return {"schema_version": 1, "scanner": "nmap", "target": target, "status": "failed", "error": "nmap is not installed"}
    executable = discovered
    target, pinned_targets = _resolve_nmap_targets(scope, target)
    evidence_directory.mkdir(parents=True, exist_ok=True)
    stamp = str(time.time_ns())
    xml_path = evidence_directory / f"nmap-{stamp}.xml"
    normal_path = evidence_directory / f"nmap-{stamp}.nmap"
    command = _command(executable, pinned_targets, options, xml_path, normal_path, scope=scope)
    event_log = evidence_directory / f"nmap-{stamp}.events.jsonl"
    log_event(event_log, "started", target=target, mode=options.mode, max_rate=options.max_rate, max_parallelism=options.max_parallelism)
    if progress:
        progress("started")
    try:
        revalidated_target, revalidated_addresses = _resolve_nmap_targets(scope, target)
        if revalidated_target != target or revalidated_addresses != pinned_targets:
            raise ScopeViolation("Nmap target DNS answers changed during preflight; scan cancelled.")
    except ScopeViolation as exc:
        log_event(event_log, "scope_revalidation_failed", target=target, error=str(exc))
        if progress:
            progress("blocked")
        raise
    try:
        completed = subprocess.run(command, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=options.timeout_seconds + 30, check=False)
    except subprocess.TimeoutExpired:
        log_event(event_log, "timeout", target=target)
        if progress:
            progress("timeout")
        return {"schema_version": 1, "scanner": "nmap", "target": target, "status": "timeout", "resume_file": str(normal_path) if normal_path.exists() else None}
    except OSError as exc:
        log_event(event_log, "failed", target=target, error=str(exc))
        return {"schema_version": 1, "scanner": "nmap", "target": target, "status": "failed", "error": str(exc)}
    if completed.returncode != 0 or not xml_path.is_file():
        log_event(event_log, "failed", target=target, exit_code=completed.returncode)
        return {"schema_version": 1, "scanner": "nmap", "target": target, "status": "failed", "error": completed.stderr.strip() or f"nmap exit {completed.returncode}", "resume_file": str(normal_path) if normal_path.exists() else None}
    try:
        result = parse_nmap_xml(xml_path, target)
    except (ET.ParseError, OSError, ValueError) as exc:
        log_event(event_log, "parse_failed", target=target, error=str(exc))
        return {"schema_version": 1, "scanner": "nmap", "target": target, "status": "failed", "error": f"XML parse failed: {exc}", "resume_file": str(normal_path)}
    result.update({"status": "success", "xml_file": str(xml_path), "resume_file": str(normal_path), "mode": options.mode, "service_detection": options.service_detection})
    result["event_log"] = str(event_log)
    log_event(event_log, "completed", target=target, host_count=len(result["hosts"]))
    if progress:
        progress("completed")
    return result


def resume_nmap(
    executable: Path,
    resume_file: Path,
    *,
    scope: ScopePolicy | None = None,
    target: str | None = None,
    active_acknowledgement: str = "",
    evidence_directory: Path | None = None,
    timeout_seconds: int = 7200,
) -> dict:
    """Resume only a scoped, explicitly authorized run whose native log pins validated IPv4 targets.

    Nmap appends to the native ``-oX``/``-oN`` files named in the original command. Before
    the resume starts, byte-exact copies of those files are preserved in ``evidence_directory``
    (when supplied) using exclusive creation, and SHA-256 digests are recorded before and after.
    A resume is reported as ``success`` only when Nmap exits 0 *and* its XML parses.
    """
    if active_acknowledgement != "I AUTHORIZE PORT SCANNING":
        raise AuthorizationRequired("Nmap resume requires I AUTHORIZE PORT SCANNING.")
    if type(scope) is not ScopePolicy or target is None:
        raise AuthorizationRequired("Nmap resume requires a built-in ScopePolicy and an explicit target.")
    if not 30 <= timeout_seconds <= 7200:
        raise ValueError("Nmap resume timeout must be between 30 and 7200 seconds.")
    target = scope.require_nmap_target(target)
    if not executable.is_file():
        return {"schema_version": 1, "scanner": "nmap", "target": target, "status": "failed", "error": "nmap is not installed; install Nmap or select its executable before resuming."}
    if not resume_file.is_file() or resume_file.suffix not in {".nmap", ".gnmap"}:
        raise ValueError("Nmap resume requires an existing .nmap or .gnmap file.")
    target, pinned_targets = _resolve_nmap_targets(scope, target)
    file_hash = hashlib.sha256(resume_file.read_bytes()).hexdigest()
    recorded_targets, recorded_values = _parse_resume_command(resume_file, scope)
    if recorded_targets != pinned_targets:
        raise ScopeViolation("Nmap resume targets do not match the authorized, validated target addresses.")
    outputs = _resume_output_paths(resume_file, recorded_values)
    if hashlib.sha256(resume_file.read_bytes()).hexdigest() != file_hash:
        raise ScopeViolation("Nmap resume evidence changed during preflight; resume cancelled.")
    revalidated_target, revalidated_addresses = _resolve_nmap_targets(scope, target)
    if revalidated_target != target or revalidated_addresses != pinned_targets:
        raise ScopeViolation("Nmap resume target DNS answers changed during preflight; resume cancelled.")

    native_files = {"resume_log": resume_file.resolve(), "xml": outputs["-oX"], "normal": outputs["-oN"]}
    before = {label: _file_sha256(path) for label, path in native_files.items()}
    preserved: list[str] = []
    if evidence_directory is not None:
        evidence_directory.mkdir(parents=True, exist_ok=True)
        for label, path in native_files.items():
            if not path.is_file() or (label == "normal" and path == native_files["resume_log"]):
                continue
            copy_path = evidence_directory / f"pre-resume-{path.name}"
            with copy_path.open("xb") as handle:  # exclusive: never overwrite earlier evidence
                handle.write(path.read_bytes())
            preserved.append(str(copy_path))
    base = {
        "schema_version": 1, "scanner": "nmap", "target": target, "operation": "resume",
        "resume_file": str(resume_file), "xml_file": str(outputs["-oX"]), "pre_resume_copies": preserved,
        "artifact_hashes_before": before,
    }

    def _finish(status: str, error: str | None, **extra: object) -> dict:
        after = {label: _file_sha256(path) for label, path in native_files.items()}
        changed = sorted(label for label in native_files if before[label] != after[label])
        return {**base, "status": status, "error": error, "artifact_hashes_after": after, "native_files_modified_by_nmap": changed, **extra}

    try:
        result = subprocess.run(
            [str(executable), "--resume", str(resume_file)], shell=False, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout_seconds, check=False,
        )
    except subprocess.TimeoutExpired:
        return _finish(
            "timeout",
            f"Nmap resume exceeded {timeout_seconds} seconds and was stopped. Partial progress may be in {resume_file.name}; "
            + ("pre-resume copies are preserved in the new operation folder. " if preserved else "")
            + "Select 'Resume Previous Scan' again to continue, or start a new scan with a narrower port range.",
        )
    except OSError as exc:
        return _finish("failed", f"Nmap could not be started for resume ({exc}). Check the Nmap installation and file permissions.")
    if result.returncode != 0:
        detail = result.stderr.strip() or f"nmap exit {result.returncode}"
        return _finish("failed", f"{detail}. Nmap resumes only interrupted scans; a completed or corrupted log cannot be resumed.")
    try:
        parsed = parse_nmap_xml(outputs["-oX"], target)
    except (ET.ParseError, OSError, ValueError, KeyError) as exc:
        return _finish("completed_unparsed", f"Nmap exited successfully but the resumed XML could not be parsed ({exc}); results were not recorded as a successful scan.")
    return _finish("success", None, hosts=parsed["hosts"])


MAX_NMAP_HOSTS = 256
MAX_NMAP_CONCURRENCY = 4


def _ip_sort_key(value: str) -> tuple[int, int]:
    parsed = ipaddress.ip_address(value)
    return parsed.version, int(parsed)


def _resolve_all(scope: ScopePolicy, host: str, ipv6: bool) -> list[str]:
    """Validated IPv4 answers, plus validated IPv6 answers when IPv6 scanning was explicitly enabled."""
    _canonical, addresses = _resolve_nmap_targets(scope, host)
    result = list(addresses)
    if ipv6:
        try:
            answers = socket.getaddrinfo(host + ".", None, socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            answers = []
        v6 = set()
        for answer in answers:
            try:
                parsed = ipaddress.ip_address(str(answer[4][0]).split("%")[0])
            except (ValueError, IndexError, TypeError):
                continue
            if parsed.version == 6:
                v6.add(scope.require_nmap_ip(parsed.compressed))  # non-public/excluded IPv6 blocks the host
        result += sorted(v6, key=_ip_sort_key)
    return result


def _scan_units(provenance: dict[str, list[str]], per_hostname: bool) -> list[dict]:
    """Build scan units: one per unique IP (default) or one per hostname when explicitly requested."""
    if per_hostname:
        units = []
        for hostname, addresses in sorted(provenance.items()):
            for family in (4, 6):  # Nmap cannot mix IPv4 and IPv6 targets in one invocation
                selected = [a for a in addresses if ipaddress.ip_address(a).version == family]
                if selected:
                    units.append({"unit_id": f"host-{len(units) + 1:03d}", "addresses": selected, "hostnames": [hostname]})
        return units
    by_ip: dict[str, set[str]] = {}
    for hostname, addresses in provenance.items():
        for address in addresses:
            by_ip.setdefault(address, set()).add(hostname)
    return [
        {"unit_id": f"ip-{index:03d}", "addresses": [address], "hostnames": sorted(by_ip[address])}
        for index, address in enumerate(sorted(by_ip, key=_ip_sort_key), 1)
    ]


def plan_nmap_hosts(scope: ScopePolicy, hostnames: list[str], *, per_hostname: bool = False, max_hosts: int = MAX_NMAP_HOSTS, ipv6: bool = False) -> dict:
    """Validate, deduplicate and resolve explicitly selected hostnames; never broadens scope."""
    if type(scope) is not ScopePolicy:
        raise ScopeViolation("Nmap requires the built-in ScopePolicy; custom policies are not accepted.")
    accepted: list[str] = []
    rejected: list[dict] = []
    seen: set[str] = set()
    for raw in hostnames:
        try:
            host = scope.require_nmap_target(raw)
        except ScopeViolation as exc:
            rejected.append({"hostname": str(raw)[:253], "reason": str(exc)})
            continue
        if host not in seen:
            seen.add(host)
            accepted.append(host)
    if len(accepted) > max_hosts:
        raise ScopeViolation(f"{len(accepted)} hosts selected; at most {max_hosts} hosts may be scanned in one authorized operation.")
    provenance: dict[str, list[str]] = {}
    for host in accepted:
        try:
            provenance[host] = _resolve_all(scope, host, ipv6)
        except ScopeViolation as exc:
            rejected.append({"hostname": host, "reason": str(exc)})
            continue
    return {"hostname_provenance": provenance, "rejected_hostnames": rejected, "units": _scan_units(provenance, per_hostname)}


def run_nmap_hosts(
    executable: Path,
    scope: ScopePolicy,
    hostnames: list[str],
    options: NmapScanOptions,
    evidence_directory: Path,
    *,
    active_acknowledgement: str,
    per_hostname: bool = False,
    max_concurrency: int = 2,
    max_hosts: int = MAX_NMAP_HOSTS,
    progress: Callable[[str], None] | None = None,
    ipv6: bool = False,
) -> dict:
    """Scan explicitly selected, in-scope discovered hostnames with pinned public IPv4 (and opt-in IPv6) targets.

    Each hostname is validated by ScopePolicy, resolved, restricted to public IPv4 answers, and
    re-resolved immediately before execution (hosts whose answers change are skipped). By default
    every unique IP is scanned once and mapped back to all hostnames that resolved to it. Units run
    with bounded concurrency; the per-unit ``--max-rate`` is divided so the aggregate stays bounded.
    """
    if active_acknowledgement != "I AUTHORIZE PORT SCANNING":
        raise AuthorizationRequired("Nmap requires I AUTHORIZE PORT SCANNING.")
    if type(scope) is not ScopePolicy:
        raise ScopeViolation("Nmap requires the built-in ScopePolicy; custom policies are not accepted.")
    options.validate()
    if not 1 <= max_concurrency <= MAX_NMAP_CONCURRENCY:
        raise ValueError(f"Nmap host concurrency must be between 1 and {MAX_NMAP_CONCURRENCY}.")
    base = {
        "schema_version": 1, "scanner": "nmap", "target": scope.root_domain, "scan_scope": "selected_discovered_hostnames",
        "mode": options.mode, "service_detection": options.service_detection, "dedupe_by_ip": not per_hostname,
    }
    discovered = discover_nmap(executable)
    if discovered is None:
        return {**base, "status": "failed", "error": "nmap is not installed", "hosts": []}
    executable = discovered
    plan = plan_nmap_hosts(scope, hostnames, per_hostname=per_hostname, max_hosts=max_hosts, ipv6=ipv6)
    provenance: dict[str, list[str]] = plan["hostname_provenance"]
    rejected: list[dict] = list(plan["rejected_hostnames"])
    if not provenance:
        return {**base, "status": "failed", "error": "No selected hostname resolved to an authorized public IPv4 address; nothing was scanned.", "hosts": [], "hostname_provenance": {}, "rejected_hostnames": rejected, "units": []}
    evidence_directory.mkdir(parents=True, exist_ok=True)
    stamp = str(time.time_ns())
    event_log = evidence_directory / f"nmap-hosts-{stamp}.events.jsonl"
    log_event(event_log, "started", target=scope.root_domain, hostnames=sorted(provenance), mode=options.mode, per_hostname=per_hostname)
    for hostname in sorted(provenance):
        try:
            again = _resolve_all(scope, hostname, ipv6)
        except ScopeViolation as exc:
            rejected.append({"hostname": hostname, "reason": f"Pre-execution revalidation failed: {exc}"})
            del provenance[hostname]
            continue
        if again != provenance[hostname]:
            rejected.append({"hostname": hostname, "reason": "DNS answers changed during preflight; host skipped."})
            del provenance[hostname]
    units = _scan_units(provenance, per_hostname)
    if not units:
        log_event(event_log, "scope_revalidation_failed", target=scope.root_domain)
        return {**base, "status": "failed", "error": "All hosts failed pre-execution DNS revalidation; nothing was scanned.", "hosts": [], "hostname_provenance": provenance, "rejected_hostnames": rejected, "units": [], "event_log": str(event_log)}
    workers = min(max_concurrency, len(units))
    unit_options = NmapScanOptions(options.mode, options.ports, options.service_detection, max(1, options.max_rate // workers), options.max_parallelism, options.timeout_seconds)

    def execute(unit: dict) -> dict:
        xml_path = evidence_directory / f"nmap-{stamp}-{unit['unit_id']}.xml"
        normal_path = evidence_directory / f"nmap-{stamp}-{unit['unit_id']}.nmap"
        summary = {**unit, "xml_file": str(xml_path), "resume_file": str(normal_path)}
        command = _command(executable, tuple(unit["addresses"]), unit_options, xml_path, normal_path, scope=scope, ipv6=ipv6)
        try:
            completed = subprocess.run(command, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=unit_options.timeout_seconds * len(unit["addresses"]) + 30, check=False)
        except subprocess.TimeoutExpired:
            return {**summary, "status": "timeout", "error": "Nmap unit exceeded its time limit; the native .nmap log is preserved for resume."}
        except OSError as exc:
            return {**summary, "status": "failed", "error": str(exc)}
        if completed.returncode != 0 or not xml_path.is_file():
            return {**summary, "status": "failed", "error": completed.stderr.strip() or f"nmap exit {completed.returncode}"}
        try:
            parsed = parse_nmap_xml(xml_path, scope.root_domain)
        except (ET.ParseError, OSError, ValueError, KeyError) as exc:
            return {**summary, "status": "failed", "error": f"XML parse failed: {exc}"}
        return {**summary, "status": "success", "error": None, "parsed_hosts": parsed["hosts"]}

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(execute, unit): unit["unit_id"] for unit in units}
        for future in as_completed(futures):
            unit_result = future.result()
            results.append(unit_result)
            if progress:
                progress(f"{unit_result['unit_id']} {unit_result['status']}")
    results.sort(key=lambda item: item["unit_id"])
    hosts: list[dict] = []
    for unit_result in results:
        for host in unit_result.pop("parsed_hosts", []):
            address = host.get("address")
            associated = sorted(name for name, addresses in provenance.items() if address in addresses) if not per_hostname else unit_result["hostnames"]
            hosts.append({**host, "hostnames": associated, "unit_id": unit_result["unit_id"]})
    statuses = {item["status"] for item in results}
    status = "success" if statuses == {"success"} else "partial" if "success" in statuses else "timeout" if statuses == {"timeout"} else "failed"
    log_event(event_log, "completed", target=scope.root_domain, status=status, unit_count=len(results))
    return {
        **base, "status": status, "hosts": hosts, "hostname_provenance": provenance, "rejected_hostnames": rejected,
        "units": results, "max_concurrency": workers, "per_unit_max_rate": unit_options.max_rate, "event_log": str(event_log),
        "error": None if status == "success" else "One or more scan units did not complete; see units for per-host status.",
    }
