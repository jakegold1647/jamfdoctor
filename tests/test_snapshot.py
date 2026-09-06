import json
from pathlib import Path

from jamfdoctor import cli, policylog, rules, snapshot

FIXTURES = Path(__file__).parent / "fixtures"
SNAPSHOT = FIXTURES / "snapshot-dp-mount-failed.txt"


def test_extracts_cells_including_single_quoted_nodes_and_escaped_quotes():
    text = snapshot.extract_policy_log(SNAPSHOT.read_text(encoding="utf-8"))
    assert text is not None
    lines = text.splitlines()
    assert lines[0] == "Executing Policy Printer Driver Update (Macs)"
    assert lines[2] == 'Could not mount distribution point "File Share"'
    assert lines[4] == "Script exit code: 1"
    assert lines[-1] == "Error running script: return code was 10."
    assert len(lines) == 11


def test_snapshot_diagnoses_like_plain_text():
    text = snapshot.extract_policy_log(SNAPSHOT.read_text(encoding="utf-8"))
    findings = rules.diagnose(policylog.parse(text))
    assert [f.rule_id for f in findings] == ["JD001", "JD002", "JD011"]


def test_plain_logs_and_prose_are_not_snapshots():
    assert snapshot.extract_policy_log("Executing Policy X\nScript exit code: 0\n") is None
    assert snapshot.extract_policy_log("- generic: menu\n- button \"Save\"\n") is None
    assert snapshot.looks_like_snapshot("") is False


def test_cli_labels_snapshot_input(capsys):
    assert cli.main(["diagnose", str(SNAPSHOT), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "policy log from snapshot"
    assert [f["rule_id"] for f in payload["findings"]] == ["JD001", "JD002", "JD011"]
