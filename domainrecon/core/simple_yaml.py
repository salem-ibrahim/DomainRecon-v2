"""Strict, dependency-free parser for the small YAML subset used by engagement files.

Supported: nested block mappings, block sequences (``- item``), inline lists (``[a, b]``),
quoted/unquoted scalars, booleans, integers, floats, null, and ``#`` comments. Anchors,
aliases, tags, multi-document streams, and multi-line scalars are rejected rather than guessed.
"""
from __future__ import annotations

import re
from typing import Any


class YamlSubsetError(ValueError):
    pass


def _scalar(text: str, line: int) -> Any:
    value = text.strip()
    if not value:
        return None
    if value[0] in "&*!|>" or value.startswith("---"):
        raise YamlSubsetError(f"line {line}: unsupported YAML feature {value[:10]!r}")
    if value[0] in "'\"":
        quote = value[0]
        if len(value) < 2 or value[-1] != quote:
            raise YamlSubsetError(f"line {line}: unterminated quoted string")
        inner = value[1:-1]
        return inner.replace("''", "'") if quote == "'" else inner.replace('\\"', '"').replace("\\\\", "\\")
    if value.startswith("[") :
        if not value.endswith("]"):
            raise YamlSubsetError(f"line {line}: unterminated inline list")
        body = value[1:-1].strip()
        return [] if not body else [_scalar(part, line) for part in _split_inline(body, line)]
    if value.startswith("{"):
        if value == "{}":
            return {}
        raise YamlSubsetError(f"line {line}: inline mappings are not supported")
    lowered = value.lower()
    if lowered in {"true", "yes", "on"}:
        return True
    if lowered in {"false", "no", "off"}:
        return False
    if lowered in {"null", "~"}:
        return None
    if re.fullmatch(r"[+-]?\d+", value):
        return int(value)
    if re.fullmatch(r"[+-]?\d+\.\d+", value):
        return float(value)
    return value


def _split_inline(body: str, line: int) -> list[str]:
    parts, current, quote = [], "", ""
    for char in body:
        if quote:
            current += char
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
            current += char
        elif char == ",":
            parts.append(current)
            current = ""
        else:
            current += char
    if quote:
        raise YamlSubsetError(f"line {line}: unterminated quoted string in list")
    parts.append(current)
    return [part for part in parts if part.strip()]


def _strip_comment(text: str) -> str:
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == "#" and (index == 0 or text[index - 1].isspace()):
            return text[:index]
    return text


def loads(text: str) -> Any:
    lines: list[tuple[int, int, str]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlSubsetError(f"line {number}: tabs are not allowed for indentation")
        content = _strip_comment(raw).rstrip()
        if content.strip():
            lines.append((number, len(content) - len(content.lstrip(" ")), content.strip()))
    if not lines:
        return {}
    value, index = _block(lines, 0, lines[0][1])
    if index != len(lines):
        raise YamlSubsetError(f"line {lines[index][0]}: unexpected indentation")
    return value


def _block(lines: list[tuple[int, int, str]], index: int, indent: int) -> tuple[Any, int]:
    if lines[index][2].startswith("- ") or lines[index][2] == "-":
        result: list[Any] = []
        while index < len(lines) and lines[index][1] == indent and (lines[index][2].startswith("- ") or lines[index][2] == "-"):
            number, _, content = lines[index]
            item = content[1:].strip()
            index += 1
            if not item:
                if index < len(lines) and lines[index][1] > indent:
                    value, index = _block(lines, index, lines[index][1])
                    result.append(value)
                else:
                    result.append(None)
            elif re.match(r"^[^'\"\[{][^:]*:(\s|$)", item):
                raise YamlSubsetError(f"line {number}: mappings inside sequence items are not supported; use nested keys")
            else:
                result.append(_scalar(item, number))
        return result, index
    mapping: dict[str, Any] = {}
    while index < len(lines) and lines[index][1] == indent:
        number, _, content = lines[index]
        match = re.match(r"^([A-Za-z0-9_.-]+|\"[^\"]+\"|'[^']+')\s*:(?:\s+(.*))?$", content)
        if not match:
            raise YamlSubsetError(f"line {number}: expected 'key: value'")
        key = match.group(1).strip("'\"")
        if key in mapping:
            raise YamlSubsetError(f"line {number}: duplicate key {key!r}")
        rest = match.group(2)
        index += 1
        if rest is None or not rest.strip():
            if index < len(lines) and lines[index][1] > indent:
                mapping[key], index = _block(lines, index, lines[index][1])
            elif index < len(lines) and lines[index][1] == indent and lines[index][2].startswith("- "):
                mapping[key], index = _block(lines, index, indent)  # sequence at same indent as key
            else:
                mapping[key] = None
        else:
            mapping[key] = _scalar(rest, number)
    if index < len(lines) and lines[index][1] > indent:
        raise YamlSubsetError(f"line {lines[index][0]}: unexpected indentation")
    return mapping, index
