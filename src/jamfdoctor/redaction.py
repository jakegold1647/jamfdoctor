"""Redact identifying details before a log leaves the building.

The substitutions are fixed regular expressions applied in a fixed order, so
the same input always redacts the same way. Redaction is best effort: read
the output before sharing it.
"""

from __future__ import annotations

import re

_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[REDACTED_EMAIL]"),
    (re.compile(r"https?://[^\s\"'>]+"), "[REDACTED_URL]"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[REDACTED_IP]"),
    (
        re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:org|com|net|edu|local|school|io|gov)\b"),
        "[REDACTED_HOST]",
    ),
    (re.compile(r"(console|user|username|login)=('?)[^'\s)]+(\2)"), r"\1=\2[REDACTED_USER]\3"),
    (re.compile(r"(for user \")[^\"]+(\")"), r"\1[REDACTED_USER]\2"),
    (re.compile(r"/Users/[^/\s]+"), "/Users/[REDACTED_USER]"),
    (re.compile(r"\b[A-Z0-9]{10,12}\b"), "[REDACTED_SERIAL]"),
]


def redact(text: str) -> str:
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text
