"""The policy-log rule catalog.

Every rule is a pure function of the parsed log. Rules run in catalog order,
findings are then sorted by (first evidence line, rule id), so the same log
always produces the same report. A rule that explains a script failure claims
that script; later, more generic rules skip claimed scripts.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .policylog import Line, ParsedLog, ScriptRun


@dataclass(frozen=True)
class Evidence:
    line: int
    text: str


@dataclass
class Finding:
    rule_id: str
    title: str
    confidence: str  # high | medium | low | info
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    next_checks: list[str] = field(default_factory=list)
    related: list[str] = field(default_factory=list)

    @property
    def first_line(self) -> int:
        return min((e.line for e in self.evidence), default=10**9)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "confidence": self.confidence,
            "summary": self.summary,
            "evidence": [{"line": e.line, "text": e.text} for e in self.evidence],
            "next_checks": list(self.next_checks),
            "related": list(self.related),
        }


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    description: str
    confidence: str
    run: Callable[[ParsedLog, set[int]], list[Finding]]


def _ev(line: Line) -> Evidence:
    return Evidence(line.number, line.text)


def _script_evidence(script: ScriptRun, limit: int = 3) -> list[Evidence]:
    evidence: list[Evidence] = []
    if script.exit_line is not None:
        evidence.append(Evidence(script.exit_line, f"Script exit code: {script.exit_code}"))
    for line in script.error_lines()[:limit]:
        evidence.append(_ev(line))
    return evidence


_DEFERRED = re.compile(r"retry|retries|off campus|unreachable|next check-in|defer", re.I)
_MISSING_DEP = re.compile(
    r"command not found|No such file or directory|not installed|is required", re.I
)


def rule_dp_mount_failed(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    findings = []
    for line in log.mount_failures:
        name = re.search(r'"([^"]+)"', line.text)
        dp = name.group(1) if name else "the distribution point"
        findings.append(
            Finding(
                rule_id="JD001",
                title="Distribution point could not be mounted",
                confidence="high",
                summary=(
                    f'Jamf could not mount the file-share distribution point "{dp}", '
                    "so no package in this policy was installed on this run."
                ),
                evidence=[_ev(line)],
                next_checks=[
                    "Confirm whether the Mac was on the network that can reach the share; "
                    "off-network laptops cannot mount an SMB or AFP distribution point.",
                    "Open the policy's Packages payload and check which distribution point it "
                    "uses; a cloud distribution point serves Macs anywhere.",
                    "If the share should have been reachable, confirm it still exists under "
                    "Settings > Server and that its read-only credentials are valid.",
                ],
            )
        )
    return findings


def rule_script_failed_after_mount_failure(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    if not log.mount_failures:
        return []
    findings = []
    mount_line = log.mount_failures[0]
    for index, script in enumerate(log.scripts):
        if index in claimed or not script.failed:
            continue
        if script.exit_code == 10 and _DEFERRED.search(script.result_text()):
            continue  # JD011 owns deferred retries
        claimed.add(index)
        evidence = [_ev(mount_line)] + _script_evidence(script)
        findings.append(
            Finding(
                rule_id="JD002",
                title="Script failed after the distribution point mount failed",
                confidence="high",
                summary=(
                    f'Script "{script.name}" exited with code {script.exit_code} after the '
                    "distribution point mount failed. The package it expected was never "
                    "installed, so treat this as a consequence, not a separate bug."
                ),
                evidence=evidence,
                next_checks=[
                    "Fix the distribution point problem first (see JD001), then flush this "
                    "computer's entry in the policy log and let it re-run.",
                    "If the script still fails once the package is installed, its own ERROR "
                    "line above becomes the new lead.",
                ],
                related=["JD001"],
            )
        )
    return findings


def rule_script_deferred_retry(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    findings = []
    for index, script in enumerate(log.scripts):
        if index in claimed or script.exit_code != 10:
            continue
        reason = next((ln for ln in script.result if _DEFERRED.search(ln.text)), None)
        if reason is None:
            continue
        claimed.add(index)
        evidence = [_ev(reason)]
        if script.exit_line is not None:
            evidence.insert(0, Evidence(script.exit_line, f"Script exit code: {script.exit_code}"))
        findings.append(
            Finding(
                rule_id="JD011",
                title="Script deferred itself for a later run",
                confidence="high",
                summary=(
                    f'Script "{script.name}" exited with code 10 on purpose and expects Jamf '
                    "to run the policy again later; the reason it logged is quoted below."
                ),
                evidence=evidence,
                next_checks=[
                    "Confirm the policy will actually run again: 'Retry on failure' applies "
                    "only to Once per computer and Once per user frequencies; a recurring "
                    "frequency waits out its full interval after any run.",
                    "Nothing to fix on this Mac until the condition in the reason line "
                    "changes, for example being back on the required network.",
                ],
            )
        )
    return findings


def rule_missing_dependency(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    findings = []
    for index, script in enumerate(log.scripts):
        if index in claimed or not script.failed:
            continue
        hit = next((ln for ln in script.result if _MISSING_DEP.search(ln.text)), None)
        if hit is None:
            continue
        claimed.add(index)
        evidence = []
        if script.exit_line is not None:
            evidence.append(Evidence(script.exit_line, f"Script exit code: {script.exit_code}"))
        evidence.append(_ev(hit))
        findings.append(
            Finding(
                rule_id="JD012",
                title="Script hit a missing command or file",
                confidence="high",
                summary=(
                    f'Script "{script.name}" failed because something it calls or reads is '
                    "not on this Mac; the quoted line names it."
                ),
                evidence=evidence,
                next_checks=[
                    "Check the spelling and PATH of the command, or the path of the file, on "
                    "the affected Mac; Jamf scripts run as root with a minimal PATH.",
                    "If the dependency is installed by a package, order that package before "
                    "the script and give the script priority After.",
                ],
            )
        )
    return findings


def rule_script_nonzero_exit(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    findings = []
    for index, script in enumerate(log.scripts):
        if index in claimed or not script.failed:
            continue
        claimed.add(index)
        evidence = _script_evidence(script)
        if script.error_line is not None and all(e.line != script.error_line for e in evidence):
            evidence.append(
                Evidence(
                    script.error_line,
                    f"Error running script: return code was {script.exit_code}.",
                )
            )
        findings.append(
            Finding(
                rule_id="JD010",
                title="Script exited with a non-zero code",
                confidence="medium",
                summary=f'Script "{script.name}" exited with code {script.exit_code}.',
                evidence=evidence,
                next_checks=[
                    "Read the script's own ERROR line above if there is one; it names the "
                    "failing step.",
                    "Run the script by hand on the affected Mac with the same parameter "
                    "values the policy passes ($4 through $11) to reproduce it.",
                    "Check that the script's parameters in the policy are filled in and in "
                    "the order the script expects.",
                ],
            )
        )
    return findings


def rule_package_not_found(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    findings = []
    for event in log.packages:
        if event.kind != "not_found":
            continue
        name = event.name or "the package"
        findings.append(
            Finding(
                rule_id="JD020",
                title="Package not found on the distribution point",
                confidence="high",
                summary=f"Jamf reached the distribution point but {name} was not there.",
                evidence=[_ev(event.line)],
                next_checks=[
                    "Open Settings > Computer management > Packages and confirm the package "
                    "record's file name matches the file on the distribution point exactly.",
                    "If the package was uploaded to the principal distribution point only, "
                    "replicate it to the distribution point this Mac uses.",
                ],
            )
        )
    return findings


def rule_package_install_failed(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    findings = []
    for event in log.packages:
        if event.kind != "install_failed":
            continue
        name = event.name or "the package"
        findings.append(
            Finding(
                rule_id="JD021",
                title="Package installer reported a failure",
                confidence="high",
                summary=(
                    f"The installer failed while installing {name}; the quoted line is "
                    "its report."
                ),
                evidence=[_ev(event.line)],
                next_checks=[
                    "Install the package by hand on the affected Mac with "
                    "'sudo installer -pkg <file> -target /' and read /var/log/install.log.",
                    "Confirm the package is signed and built for this macOS version and "
                    "architecture.",
                ],
            )
        )
    return findings


def rule_jss_connectivity(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    findings = []
    for line in log.jss_errors:
        signature = "Device Signature Error" in line.text
        findings.append(
            Finding(
                rule_id="JD030",
                title="Jamf binary could not talk to Jamf Pro",
                confidence="high",
                summary=(
                    "The management framework on this Mac needs to be re-enrolled or its "
                    "device signature renewed before policies can run."
                    if signature
                    else "The Mac could not reach or authenticate to the Jamf Pro server."
                ),
                evidence=[_ev(line)],
                next_checks=(
                    [
                        "Re-enroll the Mac (Recon, a user-initiated enrollment, or "
                        "'sudo jamf enroll' with a valid invitation) to issue a new device "
                        "certificate.",
                        "Check the computer record in Jamf Pro for a duplicate or wiped "
                        "management framework.",
                    ]
                    if signature
                    else [
                        "From the Mac, confirm the Jamf Pro URL answers: "
                        "'curl -I https://<jamf-pro-url>/' and check the certificate chain.",
                        "Check the Mac's date and time; an unsynced clock breaks TLS.",
                    ]
                ),
            )
        )
    return findings


def rule_policy_completed(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    failed_scripts = any(s.failed for s in log.scripts)
    failed_packages = any(e.kind in {"not_found", "install_failed"} for e in log.packages)
    if log.mount_failures or failed_scripts or failed_packages or log.jss_errors:
        return []
    ran_something = any(s.exit_code == 0 for s in log.scripts) or any(
        e.kind == "installed" for e in log.packages
    )
    if not ran_something:
        return []
    evidence = []
    for script in log.scripts:
        if script.exit_line is not None:
            evidence.append(Evidence(script.exit_line, f"Script exit code: {script.exit_code}"))
    for event in log.packages:
        if event.kind == "installed":
            evidence.append(_ev(event.line))
    return [
        Finding(
            rule_id="JD040",
            title="No failure pattern in this policy log",
            confidence="info",
            summary="Every package installed and every script exited 0.",
            evidence=evidence[:4],
            next_checks=[
                "If the outcome on the Mac still looks wrong, the problem is in what the "
                "script does when it succeeds, not in Jamf; read the script's SUCCESS lines.",
            ],
        )
    ]


def rule_no_supported_pattern(log: ParsedLog, claimed: set[int]) -> list[Finding]:
    return []  # placeholder; diagnose() emits JD050 when nothing else matched


RULES: list[Rule] = [
    Rule("JD001", "Distribution point could not be mounted",
         "Jamf logged 'Could not mount distribution point'.", "high", rule_dp_mount_failed),
    Rule("JD011", "Script deferred itself for a later run",
         "A script exited 10 and its output says why it wants a retry.", "high",
         rule_script_deferred_retry),
    Rule("JD002", "Script failed after the distribution point mount failed",
         "A non-zero script exit that follows a mount failure in the same run.", "high",
         rule_script_failed_after_mount_failure),
    Rule("JD012", "Script hit a missing command or file",
         "A failed script whose output says 'command not found' or 'No such file'.", "high",
         rule_missing_dependency),
    Rule("JD010", "Script exited with a non-zero code",
         "Any remaining non-zero script exit.", "medium", rule_script_nonzero_exit),
    Rule("JD020", "Package not found on the distribution point",
         "Jamf logged that a package could not be found.", "high", rule_package_not_found),
    Rule("JD021", "Package installer reported a failure",
         "Jamf logged 'Installation failed' or an installer error.", "high",
         rule_package_install_failed),
    Rule("JD030", "Jamf binary could not talk to Jamf Pro",
         "JSS connection, communication, or device-signature errors.", "high",
         rule_jss_connectivity),
    Rule("JD040", "No failure pattern in this policy log",
         "Everything installed and every script exited 0.", "info", rule_policy_completed),
    Rule("JD050", "No supported pattern matched",
         "The log mentions an error but no catalog rule recognizes it.", "info",
         rule_no_supported_pattern),
]


def diagnose(log: ParsedLog) -> list[Finding]:
    claimed: set[int] = set()
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.run(log, claimed))
    if not findings:
        if log.has_failure_words or any(s.failed for s in log.scripts):
            findings.append(
                Finding(
                    rule_id="JD050",
                    title="No supported pattern matched",
                    confidence="info",
                    summary=(
                        "The log mentions an error, but no rule in this catalog recognizes it. "
                        "That is a gap in jamfdoctor, not proof the log is fine."
                    ),
                    evidence=[
                        Evidence(ln.number, ln.text)
                        for ln in log.lines
                        if re.search(r"\b(error|failed|could not)\b", ln.text, re.I)
                    ][:3],
                    next_checks=[
                        "Read the quoted lines directly, then add a rule with this log as a "
                        "sanitized fixture so the next run is covered.",
                    ],
                )
            )
        else:
            findings.append(
                Finding(
                    rule_id="JD050",
                    title="No supported pattern matched",
                    confidence="info",
                    summary="Nothing in this text looks like a Jamf policy log event.",
                    next_checks=[
                        "Paste the full policy log from the policy's Logs tab (Show details), "
                        "including the 'Executing Policy' line.",
                    ],
                )
            )
    findings.sort(key=lambda f: (f.first_line, f.rule_id))
    return findings
