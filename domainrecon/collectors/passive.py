"""V1-compatible passive Subfinder and Certificate Transparency collection."""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from domainrecon.core.scope import ScopePolicy


def collect_subfinder(executable: Path, scope: ScopePolicy) -> tuple[list[str], str | None]:
    if not executable.is_file():
        return [], "subfinder is not installed"
    command = [str(executable), "-d", scope.root_domain, "-silent", "-timeout", "30", "-max-time", "5", "-rl", "10", "-duc"]
    try:
        result = subprocess.run(command, shell=False, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=360, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], str(exc)
    if result.returncode != 0:
        return [], result.stderr.strip() or f"subfinder exit {result.returncode}"
    return scope.filter_hostnames(result.stdout.splitlines()), None


def collect_crtsh(scope: ScopePolicy, *, timeout: int = 20, retries: int = 2) -> tuple[list[str], str | None]:
    request = Request("https://crt.sh/?" + urlencode({"q": f"%.{scope.root_domain}", "output": "json"}), headers={"User-Agent": "DomainRecon/2.0 (authorized passive reconnaissance)"})
    for attempt in range(retries + 1):
        try:
            with urlopen(request, timeout=timeout) as response:  # fixed HTTPS endpoint
                payload = response.read(10 * 1024 * 1024 + 1)
            if len(payload) > 10 * 1024 * 1024:
                return [], "crt.sh response exceeds 10 MiB limit"
            data = json.loads(payload.decode("utf-8"))
            names = [name for row in data if isinstance(row, dict) and isinstance(row.get("name_value"), str) for name in row["name_value"].splitlines()]
            return scope.filter_hostnames(names), None
        except HTTPError as exc:
            if exc.code == 429 and attempt < retries:
                time.sleep(2)
                continue
            return [], f"crt.sh HTTP {exc.code}"
        except (URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            if attempt < retries:
                time.sleep(1 + attempt)
                continue
            return [], str(exc)
    return [], "crt.sh failed"


def enumerate_passive(executable: Path, scope: ScopePolicy) -> dict:
    result, _ = enumerate_passive_detailed(executable, scope)
    return result


def enumerate_passive_detailed(executable: Path, scope: ScopePolicy) -> tuple[dict, dict]:
    """Collect both passive sources and return timing/counts separately from the stable artifact payload."""
    started = time.perf_counter()
    source_stats: dict[str, dict] = {}
    source_names: dict[str, list[str]] = {}
    for source_name, collector in (
        ("subfinder", lambda: collect_subfinder(executable, scope)),
        ("crt.sh", lambda: collect_crtsh(scope)),
    ):
        source_started = time.perf_counter()
        names, error = collector()
        source_names[source_name] = names
        source_stats[source_name] = {
            "status": "failed" if error else "success",
            "discovered_count": len(names),
            "elapsed_seconds": round(time.perf_counter() - source_started, 6),
            "error": error,
        }
    subfinder = source_names["subfinder"]
    crtsh = source_names["crt.sh"]
    subfinder_error = source_stats["subfinder"]["error"]
    crtsh_error = source_stats["crt.sh"]["error"]
    sources: dict[str, set[str]] = {}
    for name in subfinder:
        sources.setdefault(name, set()).add("subfinder")
    for name in crtsh:
        sources.setdefault(name, set()).add("crtsh")
    result = {
        "root_domain": scope.root_domain,
        "status": "success" if not (subfinder_error and crtsh_error) else "failed",
        "errors": [error for error in (subfinder_error, crtsh_error) if error],
        "records": [{"hostname": name, "sources": sorted(values)} for name, values in sorted(sources.items())],
    }
    stats = {
        "elapsed_seconds": round(time.perf_counter() - started, 6),
        "unique_subdomains": len(result["records"]),
        "sources": source_stats,
    }
    return result, stats
