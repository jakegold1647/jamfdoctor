from pathlib import Path

from jamfdoctor import policylog, rules

FIXTURES = Path(__file__).parent / "fixtures"
DEMO = Path(__file__).parents[1] / "src" / "jamfdoctor" / "demo" / "dp-mount-failed.log"


def diagnose(path: Path):
    return rules.diagnose(policylog.parse(path.read_text(encoding="utf-8")))


def test_dp_mount_failure_chain():
    findings = diagnose(DEMO)
    assert [f.rule_id for f in findings] == ["JD001", "JD002", "JD011"]
    mount, consequence, deferred = findings
    assert mount.evidence[0].line == 3
    assert [e.line for e in consequence.evidence] == [3, 5, 7]
    assert "consequence" in consequence.summary
    assert consequence.related == ["JD001"]
    assert [e.line for e in deferred.evidence] == [10, 12]
    assert deferred.confidence == "high"


def test_success_log_reports_no_failure():
    findings = diagnose(FIXTURES / "policy-log-success.log")
    assert [f.rule_id for f in findings] == ["JD040"]
    assert findings[0].confidence == "info"


def test_package_not_found_owns_the_run_and_script_is_generic():
    findings = diagnose(FIXTURES / "policy-log-package-not-found.log")
    assert [f.rule_id for f in findings] == ["JD020", "JD010"]
    assert findings[0].evidence[0].line == 4
    assert findings[1].evidence[0].text == "Script exit code: 1"


def test_jss_errors():
    findings = diagnose(FIXTURES / "policy-log-jss-error.log")
    assert [f.rule_id for f in findings] == ["JD030", "JD030"]
    assert "re-enrolled" in findings[1].summary


def test_missing_command():
    findings = diagnose(FIXTURES / "policy-log-missing-command.log")
    assert [f.rule_id for f in findings] == ["JD012"]
    assert findings[0].evidence[1].line == 4


def test_unrecognized_error_reports_gap():
    findings = rules.diagnose(policylog.parse("Executing Policy Z\nSomething failed badly\n"))
    assert [f.rule_id for f in findings] == ["JD050"]
    assert findings[0].evidence[0].line == 2


def test_plain_text_reports_nothing_to_diagnose():
    findings = rules.diagnose(policylog.parse("just some notes\n"))
    assert [f.rule_id for f in findings] == ["JD050"]
    assert findings[0].evidence == []


def test_catalog_ids_are_unique_and_ordered():
    ids = [r.rule_id for r in rules.RULES]
    assert len(ids) == len(set(ids))
    assert ids[0] == "JD001"
