"""Static, escaped HTML report generation.

DEPRECATED compatibility helper (retained, not used by any DomainRecon workflow). Superseded by
``domainrecon.reporting.unified_report`` (20-section JSON/CSV/HTML with redaction). It produced the
repository's ``example-report.html``. Kept for existing imports and its escaping/immutability
regression test; scheduled for removal in the next major version.
"""
from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

from domainrecon.core.errors import ArtifactExists


def render_report(summary: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    title = escape(str(summary.get("title", "DomainRecon v2 Report")))
    root = escape(str(summary.get("root_domain", "unknown")))
    body_rows = "".join(
        "<tr>" + "".join(f"<td>{escape(str(row.get(key, '')))}</td>" for key in ("hostname", "dns", "http", "tls")) + "</tr>"
        for row in rows
    )
    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{title}</title><style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #bbb;padding:.4rem;text-align:left}}</style></head>
<body><h1>{title}</h1><p>Authorized root scope: <code>{root}</code></p><table><thead><tr><th>Hostname</th><th>DNS</th><th>HTTP</th><th>TLS</th></tr></thead><tbody>{rows}</tbody></table></body></html>""".format(title=title, root=root, rows=body_rows)


def write_report(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> Path:
    if path.exists():
        raise ArtifactExists(f"Report already exists: {path}")
    path.write_text(render_report(summary, rows), encoding="utf-8", newline="")
    return path
