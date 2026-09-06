"""Parse the text of a Jamf Pro policy log into typed events.

The parser is intentionally conservative: it recognizes the line shapes the
Jamf binary writes (Executing Policy, Mounting, Could not mount, Running
script, Script exit code, Script result, Error running script, package
download/install lines, and JSS connectivity errors) and leaves everything
else untouched as plain lines. Line numbers are 1-based and refer to the
input exactly as given, so findings can cite them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Line:
    number: int
    text: str


@dataclass
class ScriptRun:
    name: str
    start_line: int
    exit_code: int | None = None
    exit_line: int | None = None
    error_line: int | None = None
    result: list[Line] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return self.exit_code is not None and self.exit_code != 0

    def result_text(self) -> str:
        return "\n".join(line.text for line in self.result)

    def error_lines(self) -> list[Line]:
        """Lines of the script's own output that announce an error."""
        pattern = re.compile(
            r"\b(ERROR|error:|fatal|failed|command not found|No such file)\b", re.I
        )
        return [line for line in self.result if pattern.search(line.text)]


@dataclass
class PackageEvent:
    kind: str  # download | install | installed | not_found | install_failed
    line: Line
    name: str


@dataclass
class ParsedLog:
    lines: list[Line]
    policy_name: str | None = None
    policy_line: int | None = None
    mount_attempts: list[Line] = field(default_factory=list)
    mount_failures: list[Line] = field(default_factory=list)
    packages: list[PackageEvent] = field(default_factory=list)
    scripts: list[ScriptRun] = field(default_factory=list)
    jss_errors: list[Line] = field(default_factory=list)
    submitted: bool = False

    @property
    def has_failure_words(self) -> bool:
        pattern = re.compile(r"\b(error|failed|could not|cannot|unable)\b", re.I)
        return any(pattern.search(line.text) for line in self.lines)


_POLICY = re.compile(r"^Executing Policy (?P<name>.+?)\s*$")
_MOUNT = re.compile(r"^Mounting (?P<dp>.+?)\.{0,3}\s*$")
_MOUNT_FAIL = re.compile(r"^Could not mount distribution point \"?(?P<dp>[^\"]+)\"?")
_SCRIPT_START = re.compile(r"^Running script (?P<name>.+?)\.\.\.\s*$")
_SCRIPT_EXIT = re.compile(r"^Script exit code: (?P<code>-?\d+)")
_SCRIPT_RESULT = re.compile(r"^Script result:\s?(?P<rest>.*)$")
_SCRIPT_ERROR = re.compile(r"^Error running script: return code was (?P<code>-?\d+)")
_PKG_DOWNLOAD = re.compile(r"^Downloading (?P<name>.+?)\.\.\.\s*$")
_PKG_INSTALL = re.compile(r"^Installing (?P<name>.+?)\.\.\.\s*$")
_PKG_INSTALLED = re.compile(r"^Successfully installed (?P<name>.+?)\.?\s*$")
_PKG_NOT_FOUND = re.compile(
    r"package\b.*could not be found|could not be found on the distribution point", re.I
)
_PKG_FAILED = re.compile(r"Installation failed|installer: Error|The installer reported", re.I)
_JSS_ERROR = re.compile(
    r"Could not connect to the JSS|error communicating with the JSS|Device Signature Error|"
    r"certificate (?:is not|isn't) trusted|Unable to connect to the JSS",
    re.I,
)
_SUBMIT = re.compile(r"^Submitting log to ")

# Any of these begins a new event and therefore ends a "Script result:" block.
_MARKERS = (
    _POLICY,
    _MOUNT,
    _MOUNT_FAIL,
    _SCRIPT_START,
    _SCRIPT_EXIT,
    _SCRIPT_RESULT,
    _SCRIPT_ERROR,
    _PKG_DOWNLOAD,
    _PKG_INSTALL,
    _PKG_INSTALLED,
    _SUBMIT,
    re.compile(r"^Running command "),
    re.compile(r"^Checking for policies triggered by "),
)


def _is_marker(text: str) -> bool:
    return any(marker.match(text) for marker in _MARKERS)


def parse(text: str) -> ParsedLog:
    """Parse policy-log text. Never raises on unknown lines."""
    raw_lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    lines = [Line(number, raw.rstrip()) for number, raw in enumerate(raw_lines, start=1)]
    log = ParsedLog(lines=lines)
    current: ScriptRun | None = None
    in_result = False

    for line in lines:
        text_ = line.text
        if in_result and not _is_marker(text_):
            if current is not None and text_.strip():
                current.result.append(line)
            continue
        in_result = False

        if match := _POLICY.match(text_):
            if log.policy_name is None:
                log.policy_name = match.group("name")
                log.policy_line = line.number
            continue
        if _MOUNT_FAIL.match(text_):
            log.mount_failures.append(line)
            continue
        if _MOUNT.match(text_):
            log.mount_attempts.append(line)
            continue
        if match := _SCRIPT_START.match(text_):
            current = ScriptRun(name=match.group("name"), start_line=line.number)
            log.scripts.append(current)
            continue
        if match := _SCRIPT_EXIT.match(text_):
            if current is not None:
                current.exit_code = int(match.group("code"))
                current.exit_line = line.number
            continue
        if match := _SCRIPT_RESULT.match(text_):
            in_result = True
            rest = match.group("rest").strip()
            if current is not None and rest:
                current.result.append(Line(line.number, rest))
            continue
        if match := _SCRIPT_ERROR.match(text_):
            if current is not None:
                current.error_line = line.number
                if current.exit_code is None:
                    current.exit_code = int(match.group("code"))
                    current.exit_line = line.number
            continue
        if match := _PKG_DOWNLOAD.match(text_):
            log.packages.append(PackageEvent("download", line, match.group("name")))
            continue
        if match := _PKG_INSTALL.match(text_):
            log.packages.append(PackageEvent("install", line, match.group("name")))
            continue
        if match := _PKG_INSTALLED.match(text_):
            log.packages.append(PackageEvent("installed", line, match.group("name")))
            continue
        if _PKG_NOT_FOUND.search(text_):
            log.packages.append(PackageEvent("not_found", line, _package_name(text_)))
            continue
        if _PKG_FAILED.search(text_):
            log.packages.append(PackageEvent("install_failed", line, _package_name(text_)))
            continue
        if _JSS_ERROR.search(text_):
            log.jss_errors.append(line)
            continue
        if _SUBMIT.match(text_):
            log.submitted = True
            continue

    return log


def _package_name(text: str) -> str:
    match = re.search(r"([\w.\-]+\.(?:pkg|dmg|mpkg|zip))\b", text)
    return match.group(1) if match else ""
