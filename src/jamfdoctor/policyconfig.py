"""Deterministic checks on a Jamf Pro policy exported as JSON.

Accepts the Classic API shape ({"policy": {"general": ..., "scope": ...,
"package_configuration": ..., "scripts": ...}}) or the inner policy object.
Every check reads fields defensively: a missing field is never an error, it
just means the check has nothing to say.
"""

from __future__ import annotations

from dataclasses import dataclass

from .rules import Evidence, Finding


@dataclass(frozen=True)
class ConfigRule:
    rule_id: str
    title: str
    description: str
    confidence: str


CONFIG_RULES: list[ConfigRule] = [
    ConfigRule("JC001", "Policy is disabled", "general.enabled is false.", "high"),
    ConfigRule("JC002", "Nothing triggers this policy",
               "No trigger is enabled and it is not in Self Service.", "medium"),
    ConfigRule("JC003", "Once-per policy without retry",
               "A Once per computer/user policy with retry off never re-runs a failure.",
               "medium"),
    ConfigRule("JC004", "Retry set on a recurring policy",
               "Retry on failure only applies to Once per frequencies.", "low"),
    ConfigRule("JC005", "Packages use each computer's default distribution point",
               "Off-network Macs default to a file share they cannot mount.", "medium"),
    ConfigRule("JC006", "Script runs Before the packages",
               "A script with priority Before runs before any package installs.", "low"),
    ConfigRule("JC007", "Policy has no payload", "No packages, scripts, or other payloads.",
               "low"),
    ConfigRule("JC040", "No configuration pattern matched", "Nothing to flag.", "info"),
]


def _policy(data: dict) -> dict:
    return data.get("policy", data) if isinstance(data, dict) else {}


def _truthy(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"true", "1", "yes"}
    return bool(value)


def check(data: dict) -> list[Finding]:
    policy = _policy(data)
    general = policy.get("general", {}) or {}
    scope = policy.get("scope", {}) or {}
    pkg_conf = policy.get("package_configuration", {}) or {}
    packages = pkg_conf.get("packages", []) or []
    scripts = policy.get("scripts", []) or []
    self_service = policy.get("self_service", {}) or {}
    name = general.get("name", "this policy")
    frequency = str(general.get("frequency", "") or "")
    retry_event = str(general.get("retry_event", "none") or "none").lower()
    retry_attempts = general.get("retry_attempts")
    findings: list[Finding] = []

    if "enabled" in general and not _truthy(general.get("enabled")):
        findings.append(Finding("JC001", "Policy is disabled", "high",
                                f'"{name}" is disabled, so it never runs on any Mac.',
                                [Evidence(0, "general.enabled = false")],
                                ["Enable it under General once it is ready, or delete it if it "
                                 "is a leftover."]))

    triggers = [key for key in general if key.startswith("trigger") and _truthy(general.get(key))]
    if general and not triggers and not _truthy(self_service.get("use_for_self_service")):
        findings.append(Finding("JC002", "Nothing triggers this policy", "medium",
                                f'"{name}" has no trigger and is not in Self Service, so it only '
                                "runs when someone calls it by hand.",
                                [Evidence(0, "general.trigger_* all false; "
                                             "self_service.use_for_self_service = false")],
                                ["Tick Recurring Check-in (or the event you mean) under General, "
                                 "or make it available in Self Service."]))

    once = frequency.lower().startswith("once per")
    retry_off = retry_event in {"none", ""} or retry_attempts in (0, "0", None, -1, "-1")
    if once and retry_off:
        findings.append(Finding("JC003", "Once-per policy without retry", "medium",
                                f'"{name}" runs {frequency} with retry off; a Mac that fails once '
                                "(for example off campus) never gets another attempt.",
                                [Evidence(0, f"general.frequency = {frequency}; "
                                             f"general.retry_event = {retry_event}")],
                                ["Under General, enable 'Automatically re-run policy on failure' "
                                 "with the retry event set to Recurring Check-in.",
                                 "Or scope with a smart group that drops the Mac once the work is "
                                 "done and switch the frequency to Ongoing."]))
    if frequency and not once and retry_event not in {"none", ""}:
        findings.append(Finding("JC004", "Retry set on a recurring policy", "low",
                                f'"{name}" runs {frequency}; Jamf only honours retry on failure '
                                "for Once per frequencies, so a failed run waits out the full "
                                "interval.",
                                [Evidence(0, f"general.frequency = {frequency}; "
                                             f"general.retry_event = {retry_event}")],
                                ["Either accept the interval as the retry, or change the frequency "
                                 "to Once per computer with retry enabled and a smart-group "
                                 "scope."]))

    dp = str(pkg_conf.get("distribution_point", "default") or "default").lower()
    segments = ((scope.get("limitations") or {}).get("network_segments")) or []
    if packages and dp == "default" and not segments:
        names = ", ".join(str(p.get("name", "?")) for p in packages)
        findings.append(Finding("JC005", "Packages use each computer's default distribution point",
                                "medium",
                                f'"{name}" installs {names} from each computer\'s default '
                                "distribution point with no network-segment limitation. Where the "
                                "default is a file share, off-network Macs log 'Could not mount "
                                "distribution point' every time.",
                                [Evidence(0, "package_configuration.distribution_point = default; "
                                             "scope.limitations.network_segments = []")],
                                ["In the Packages payload, pick the cloud distribution point "
                                 "explicitly, or limit scope to the on-site network segment."],
                                related=["JD001"]))

    before = [s for s in scripts if str(s.get("priority", "")).lower() == "before"]
    if packages and before:
        names = ", ".join(str(s.get("name", "?")) for s in before)
        findings.append(Finding("JC006", "Script runs Before the packages", "low",
                                f"{names} run(s) before the packages install. If a script needs a "
                                "package, it fails on the first run and only works on the retry.",
                                [Evidence(0, "scripts[].priority = Before")],
                                ["Set the script's priority to After unless it must prepare the "
                                 "Mac for the package."]))

    other_payloads = [key for key in ("files_processes", "maintenance", "account_maintenance",
                                      "printers", "dock_items", "disk_encryption", "reboot",
                                      "user_interaction") if policy.get(key)]
    if policy and not packages and not scripts and not other_payloads:
        findings.append(Finding("JC007", "Policy has no payload", "low",
                                f'"{name}" has nothing to do when it runs.',
                                [Evidence(0, "no packages, scripts, or other payloads")],
                                ["Add the payload or delete the policy so its logs stop "
                                 "cluttering the fleet view."]))

    if not findings:
        findings.append(Finding("JC040", "No configuration pattern matched", "info",
                                f'Nothing in "{name}" matches a known misconfiguration.'))
    findings.sort(key=lambda f: f.rule_id)
    return findings
