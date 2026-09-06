"""Render findings as terminal text, Markdown, or JSON. No timestamps, ever."""

from __future__ import annotations

import json

from .rules import Finding

FORMATS = ("text", "markdown", "json")


def render(findings: list[Finding], fmt: str, source: str, kind: str) -> str:
    if fmt == "json":
        payload = {
            "source": source,
            "kind": kind,
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if fmt == "markdown":
        return _markdown(findings, source, kind)
    return _text(findings, source, kind)


def _count(findings: list[Finding]) -> str:
    real = [f for f in findings if f.confidence != "info"]
    if not real:
        return "no failure findings"
    return f"{len(real)} finding{'s' if len(real) != 1 else ''}"


def _text(findings: list[Finding], source: str, kind: str) -> str:
    out = [f"jamfdoctor: {_count(findings)} in {source} ({kind})", ""]
    for index, f in enumerate(findings, start=1):
        out.append(f"{index}. {f.title} [{f.rule_id}, {f.confidence} confidence]")
        out.append(f"   {f.summary}")
        if f.evidence:
            out.append("   Evidence:")
            for e in f.evidence:
                label = f"line {e.line}" if e.line else "config"
                out.append(f"     {label}: {e.text}")
        if f.next_checks:
            out.append("   Next checks:")
            for check in f.next_checks:
                out.append(f"     - {check}")
        if f.related:
            out.append(f"   Related: {', '.join(f.related)}")
        out.append("")
    return "\n".join(out)


def _markdown(findings: list[Finding], source: str, kind: str) -> str:
    out = [f"# jamfdoctor: {_count(findings)} in {source} ({kind})", ""]
    for f in findings:
        out.append(f"## {f.title} ({f.rule_id}, {f.confidence} confidence)")
        out.append("")
        out.append(f.summary)
        out.append("")
        if f.evidence:
            out.append("**Evidence**")
            out.append("")
            for e in f.evidence:
                label = f"line {e.line}" if e.line else "config"
                out.append(f"- {label}: `{e.text}`")
            out.append("")
        if f.next_checks:
            out.append("**Next checks**")
            out.append("")
            for check in f.next_checks:
                out.append(f"- {check}")
            out.append("")
        if f.related:
            out.append(f"Related: {', '.join(f.related)}")
            out.append("")
    return "\n".join(out)
