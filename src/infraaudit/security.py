"""Redacción de credenciales conocidas y estructuras sensibles, por ejecución."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from enum import Enum
from typing import Any
from urllib.parse import quote, quote_plus

_VALUES: ContextVar[tuple[str, ...]] = ContextVar("infraaudit_secrets", default=())
MASK = "[REDACTED]"
_KEY = re.compile(
    r"password|passphrase|secret|token|authorization|cookie|api.?key|private.?key", re.I
)
_ASSIGNMENT = re.compile(
    r"(?i)((?:password|passphrase|secret|token|api[_-]?key)\s*[=:]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s&,;]+)"
)


def sensitive_key(key: str) -> bool:
    return _KEY.search(key) is not None


@contextmanager
def secret_scope(values: list[str]) -> Iterator[None]:
    variants = {
        variant
        for value in values
        if value
        for variant in (value, quote(value, safe=""), quote_plus(value))
    }
    token = _VALUES.set(tuple(sorted(variants, key=len, reverse=True)))
    try:
        yield
    finally:
        _VALUES.reset(token)


def redact_text(value: str) -> str:
    value = re.sub(r"(https?://)[^/@\s]+@", r"\1" + MASK + "@", value)
    value = _ASSIGNMENT.sub(lambda match: match[1] + MASK, value)
    value = re.sub(
        r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*", lambda m: m[1] + " " + MASK, value
    )
    for secret in _VALUES.get():
        value = value.replace(secret, MASK)
    return value


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: MASK if sensitive_key(str(key)) else redact(item) for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str) and not isinstance(value, Enum):
        return redact_text(value)
    return value
