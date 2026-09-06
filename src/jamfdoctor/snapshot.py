"""Pull a policy log out of a browser accessibility snapshot.

When a policy log is captured from Jamf Pro's web interface with a browser
automation tool, it arrives as an accessibility tree: every node is a line
that starts with "- ", and the log itself is a table whose cells carry the
text. This adapter recognizes that shape and returns the cell text in order,
one line per cell, so the normal parser can read it. Anything that is not a
snapshot is returned unchanged by the caller.
"""

from __future__ import annotations

import re

_NODE = re.compile(r"^\s*- ")
# A cell node looks like `- cell "text"`; YAML wraps the whole node in single
# quotes when the text contains a colon: `- 'cell "Script exit code: 1"'`.
_CELL = re.compile(
    r"""^\s*- (?P<q>'?)cell "(?P<text>(?:[^"\\]|\\.)*)"(?P=q)\s*(?:\[[^\]]*\])?\s*:?\s*$"""
)


def looks_like_snapshot(text: str) -> bool:
    lines = [line for line in text.splitlines() if line.strip()]
    return bool(lines) and all(_NODE.match(line) for line in lines)


def extract_policy_log(text: str) -> str | None:
    """Return the policy-log text hidden in a snapshot, or None if this is not one."""
    if not looks_like_snapshot(text):
        return None
    cells = []
    for line in text.splitlines():
        match = _CELL.match(line)
        if match:
            cell = match.group("text").replace('\\"', '"').replace("\\\\", "\\")
            if match.group("q"):
                # Inside a YAML single-quoted scalar, a literal ' is written as ''.
                cell = cell.replace("''", "'")
            cells.append(cell)
    if not cells:
        return None
    return "\n".join(cells) + "\n"
