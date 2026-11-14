"""Secret redaction applied to imported evidence and every report before it is written."""
from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"
# Key names that hold secrets (whole name or final word), e.g. "password", "db_password", "Set-Cookie", "x-api-key".
_SENSITIVE_KEY = re.compile(
    r"(?i)^(?:.*[_-])?(pass(word|wd)?|pwd|secret|token|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|authorization|proxy-authorization|"
    r"cookie|set-cookie|sessionid|session[_-]?token|private[_-]?key|credentials?|bearer|x-auth-token|nthash|lmhash|ntlm[_-]?hash|cpassword)$"
)
_SAFE_KEYS = frozenset({"token_type", "password_policy", "password_policy_indicator", "min_password_length", "session_id", "file_hashes", "hashes", "ioc_value", "sha256", "feed_sha256"})
_VALUE_PATTERNS = (
    (re.compile(r"(?i)\b(bearer|basic|ntlm|negotiate)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), REDACTED),  # JWT
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),  # AWS access key id
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), REDACTED),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*[^\s,;&\"']{3,}"), r"\1=" + REDACTED),
    (re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1" + REDACTED + "@"),  # credentials in URLs
)


def redact_text(value: str) -> str:
    for pattern, replacement in _VALUE_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def redact(value: Any, *, _key: str | None = None) -> Any:
    """Return a deep copy with sensitive keys and secret-looking values replaced."""
    if _key is not None and _key not in _SAFE_KEYS and _SENSITIVE_KEY.search(_key) and not isinstance(value, (dict, list, bool)) and value not in (None, ""):
        return REDACTED
    if isinstance(value, dict):
        return {key: redact(item, _key=str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item, _key=_key) for item in value]
    if isinstance(value, tuple):
        return [redact(item, _key=_key) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value
