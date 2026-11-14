"""Centralized spreadsheet-safe CSV serialization.

Spreadsheet applications (Excel, LibreOffice, Google Sheets) evaluate a cell as a
formula when its text starts with ``=``, ``+``, ``-``, ``@`` (and full-width variants),
or when such a character follows leading whitespace/control characters, a tab, or a
carriage return. Every exported cell that could carry remote or imported text is
neutralized by prefixing a single quote, which spreadsheets render as literal text.
Plain numbers such as ``-12`` or ``+3.5`` are left unchanged so legitimate data survives.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Iterable

_TRIGGERS = frozenset("=+-@＝＋－＠")
_LEADING_NOISE = re.compile(r"^[\s\x00-\x1f\x7f-\x9f​-‏  ﻿]+")
_PLAIN_NUMBER = re.compile(r"^[+-]?(?:\d+(?:\.\d+)?|\.\d+)(?:[eE][+-]?\d+)?$")


def neutralize_cell(value: Any) -> Any:
    """Return a value that a spreadsheet will not interpret as a formula."""
    if value is None:
        return ""
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return value
    if isinstance(value, (list, dict, tuple)):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    text = str(value)
    if not text:
        return text
    if _PLAIN_NUMBER.fullmatch(text):
        return text
    stripped = _LEADING_NOISE.sub("", text)
    # Formula trigger after any amount of leading whitespace/control/zero-width noise,
    # or a leading tab/CR/LF/NUL/other C0 control (OWASP treats these as triggers too).
    if stripped[:1] in _TRIGGERS or (text[:1] != " " and _LEADING_NOISE.match(text[:1])):
        return "'" + text
    return text


def safe_row(row: dict[str, Any]) -> dict[str, Any]:
    return {key: neutralize_cell(value) for key, value in row.items()}


def render_csv(fieldnames: list[str], rows: Iterable[dict[str, Any]]) -> str:
    """Render rows with ``\\n`` line endings, quoting as needed, every cell neutralized."""
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n", extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(safe_row({key: row.get(key) for key in fieldnames}))
    return buffer.getvalue()
