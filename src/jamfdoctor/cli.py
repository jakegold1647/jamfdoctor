"""Command-line entry point.

    jamfdoctor diagnose policy.log            # a policy log pasted from Jamf Pro
    jamfdoctor diagnose - < policy.log        # from stdin
    jamfdoctor policy policy-82.json          # a policy exported as JSON
    jamfdoctor rules                          # the catalog
    jamfdoctor demo                           # a bundled, sanitized example

Exit codes: 0 diagnosis produced (findings or not), 2 bad input or usage.
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib import resources
from pathlib import Path

from . import __version__, policyconfig, policylog, report, rules, snapshot
from .redaction import redact


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def cmd_diagnose(args: argparse.Namespace) -> int:
    try:
        text = _read(args.file)
    except OSError as error:
        print(f"jamfdoctor: cannot read {args.file}: {error}", file=sys.stderr)
        return 2
    extracted = snapshot.extract_policy_log(text)
    kind = "policy log"
    if extracted is not None:
        text = extracted
        kind = "policy log from snapshot"
    if args.redact:
        text = redact(text)
    parsed = policylog.parse(text)
    findings = rules.diagnose(parsed)
    label = "stdin" if args.file == "-" else Path(args.file).name
    sys.stdout.write(report.render(findings, args.format, label, kind))
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    try:
        data = json.loads(_read(args.file))
    except OSError as error:
        print(f"jamfdoctor: cannot read {args.file}: {error}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as error:
        print(f"jamfdoctor: {args.file} is not valid JSON: {error}", file=sys.stderr)
        return 2
    findings = policyconfig.check(data)
    label = "stdin" if args.file == "-" else Path(args.file).name
    sys.stdout.write(report.render(findings, args.format, label, "policy export"))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    rows = [(r.rule_id, r.confidence, r.title, r.description) for r in rules.RULES]
    rows += [(r.rule_id, r.confidence, r.title, r.description) for r in policyconfig.CONFIG_RULES]
    if args.format == "json":
        payload = [
            {"rule_id": a, "confidence": b, "title": c, "description": d} for a, b, c, d in rows
        ]
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        return 0
    sys.stdout.write("Policy-log rules (JD) and policy-export rules (JC):\n")
    for rule_id, confidence, title, description in rows:
        sys.stdout.write(f"  {rule_id}  {confidence:<6}  {title}\n           {description}\n")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    demo = resources.files("jamfdoctor").joinpath("demo", "dp-mount-failed.log")
    text = demo.read_text(encoding="utf-8")
    parsed = policylog.parse(text)
    findings = rules.diagnose(parsed)
    label = "demo: dp-mount-failed.log"
    sys.stdout.write(report.render(findings, args.format, label, "policy log"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jamfdoctor", description=__doc__.split("\n\n")[0])
    parser.add_argument("--version", action="version", version=f"jamfdoctor {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    diagnose = sub.add_parser("diagnose", help="diagnose a Jamf Pro policy log")
    diagnose.add_argument("file", help="log file, or - for stdin")
    diagnose.add_argument("--format", choices=report.FORMATS, default="text")
    diagnose.add_argument("--redact", action="store_true",
                          help="redact hosts, users, emails, IPs, and URLs first")
    diagnose.set_defaults(func=cmd_diagnose)

    policy = sub.add_parser("policy", help="check a policy exported as JSON")
    policy.add_argument("file", help="JSON file, or - for stdin")
    policy.add_argument("--format", choices=report.FORMATS, default="text")
    policy.set_defaults(func=cmd_policy)

    rules_cmd = sub.add_parser("rules", help="list the rule catalog")
    rules_cmd.add_argument("--format", choices=("text", "json"), default="text")
    rules_cmd.set_defaults(func=cmd_rules)

    demo = sub.add_parser("demo", help="diagnose the bundled sanitized example")
    demo.add_argument("--format", choices=report.FORMATS, default="text")
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
