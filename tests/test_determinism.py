"""Same input, same bytes: the property everything else depends on."""

import json
from pathlib import Path

from jamfdoctor import cli, policyconfig, policylog, report, rules

FIXTURES = Path(__file__).parent / "fixtures"
DEMO = Path(__file__).parents[1] / "src" / "jamfdoctor" / "demo" / "dp-mount-failed.log"


def render_all(text: str) -> list[str]:
    findings = rules.diagnose(policylog.parse(text))
    return [report.render(findings, fmt, "x", "policy log") for fmt in report.FORMATS]


def test_every_fixture_renders_identically_twice():
    for path in sorted(FIXTURES.glob("*.log")) + [DEMO]:
        text = path.read_text(encoding="utf-8")
        assert render_all(text) == render_all(text), path.name


def test_json_output_has_sorted_keys_and_no_timestamps():
    findings = rules.diagnose(policylog.parse(DEMO.read_text(encoding="utf-8")))
    out = report.render(findings, "json", "demo", "policy log")
    payload = json.loads(out)
    assert list(payload) == sorted(payload)
    for finding in payload["findings"]:
        assert list(finding) == sorted(finding)
    assert "generated" not in out and "timestamp" not in out


def test_findings_order_is_by_line_then_rule_id():
    findings = rules.diagnose(policylog.parse(DEMO.read_text(encoding="utf-8")))
    keys = [(f.first_line, f.rule_id) for f in findings]
    assert keys == sorted(keys)


def test_policy_check_is_pure():
    data = json.loads((FIXTURES / "policy-neglected.json").read_text(encoding="utf-8"))
    before = json.dumps(data, sort_keys=True)
    first = [f.to_dict() for f in policyconfig.check(data)]
    second = [f.to_dict() for f in policyconfig.check(data)]
    assert first == second
    assert json.dumps(data, sort_keys=True) == before


def test_cli_demo_is_byte_stable(capsys):
    cli.main(["demo", "--format", "json"])
    first = capsys.readouterr().out
    cli.main(["demo", "--format", "json"])
    assert capsys.readouterr().out == first
