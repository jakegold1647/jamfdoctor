import json
from pathlib import Path

import pytest

from jamfdoctor import __version__, cli

FIXTURES = Path(__file__).parent / "fixtures"


def run(capsys, *argv):
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_demo_text_and_json(capsys):
    code, out, _ = run(capsys, "demo")
    assert code == 0
    assert out.startswith("jamfdoctor: 3 findings in demo: dp-mount-failed.log (policy log)")
    assert "[JD001, high confidence]" in out
    code, out, _ = run(capsys, "demo", "--format", "json")
    payload = json.loads(out)
    assert [f["rule_id"] for f in payload["findings"]] == ["JD001", "JD002", "JD011"]
    assert list(payload) == sorted(payload)


def test_diagnose_file_markdown_and_redact(capsys):
    path = FIXTURES / "policy-log-success.log"
    code, out, _ = run(capsys, "diagnose", str(path), "--format", "markdown")
    assert code == 0
    assert out.startswith("# jamfdoctor: no failure findings in policy-log-success.log")
    code, out, _ = run(capsys, "diagnose", str(path), "--format", "json", "--redact")
    assert code == 0
    assert "example.org" not in out


def test_diagnose_stdin(capsys, monkeypatch):
    import io

    text = "Executing Policy P\nRunning script S...\nScript exit code: 4\n"
    monkeypatch.setattr("sys.stdin", io.StringIO(text))
    code, out, _ = run(capsys, "diagnose", "-", "--format", "json")
    assert code == 0
    assert json.loads(out)["findings"][0]["rule_id"] == "JD010"


def test_policy_command(capsys):
    code, out, _ = run(capsys, "policy", str(FIXTURES / "policy-fleet.json"), "--format", "json")
    assert code == 0
    assert [f["rule_id"] for f in json.loads(out)["findings"]] == ["JC005"]


def test_bad_inputs_exit_2(capsys, tmp_path):
    code, _, err = run(capsys, "diagnose", str(tmp_path / "missing.log"))
    assert code == 2 and "cannot read" in err
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    code, _, err = run(capsys, "policy", str(bad))
    assert code == 2 and "not valid JSON" in err


def test_rules_listing_and_version(capsys):
    code, out, _ = run(capsys, "rules")
    assert code == 0 and "JD001" in out and "JC005" in out
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--version"])
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out
