from pathlib import Path

from jamfdoctor import policylog

FIXTURES = Path(__file__).parent / "fixtures"
DEMO = Path(__file__).parents[1] / "src" / "jamfdoctor" / "demo" / "dp-mount-failed.log"


def test_parses_mount_failure_and_two_scripts():
    log = policylog.parse(DEMO.read_text(encoding="utf-8"))
    assert log.policy_name == "Printer Driver Update (Macs)"
    assert [ln.number for ln in log.mount_attempts] == [2]
    assert [ln.number for ln in log.mount_failures] == [3]
    assert [s.name for s in log.scripts] == [
        "Install Vendor Find-Me Printer",
        "Vendor Find-Me Fallback (online link)",
    ]
    first, second = log.scripts
    assert (first.exit_code, first.exit_line, first.error_line) == (1, 5, 8)
    assert [ln.number for ln in first.result] == [6, 7]
    assert first.error_lines()[0].number == 7
    assert (second.exit_code, second.exit_line, second.error_line) == (10, 10, 13)
    assert [ln.number for ln in second.result] == [11, 12]


def test_result_block_ends_at_next_marker():
    text = (
        "Running script A...\nScript exit code: 2\nScript result: first\nsecond\n"
        "Running script B...\nScript exit code: 0\nScript result: ok\n"
    )
    log = policylog.parse(text)
    assert [ln.text for ln in log.scripts[0].result] == ["first", "second"]
    assert [ln.text for ln in log.scripts[1].result] == ["ok"]


def test_package_events_and_submit():
    log = policylog.parse((FIXTURES / "policy-log-success.log").read_text(encoding="utf-8"))
    assert [e.kind for e in log.packages] == ["download", "install", "installed"]
    assert log.packages[2].name == "Vendor_IM_C4510_Driver.pkg"
    assert log.submitted is True
    assert log.scripts[0].exit_code == 0


def test_package_not_found_and_jss_errors():
    log = policylog.parse(
        (FIXTURES / "policy-log-package-not-found.log").read_text(encoding="utf-8")
    )
    assert [e.kind for e in log.packages] == ["download", "not_found"]
    assert log.packages[1].name == "Vendor_IM_C4510_Driver.pkg"
    jss = policylog.parse((FIXTURES / "policy-log-jss-error.log").read_text(encoding="utf-8"))
    assert [ln.number for ln in jss.jss_errors] == [2, 3]


def test_crlf_and_blank_lines_keep_numbering():
    text = "Executing Policy X\r\n\r\nRunning script S...\r\nScript exit code: 3\r\n"
    log = policylog.parse(text)
    assert log.policy_line == 1
    assert log.scripts[0].start_line == 3
    assert log.scripts[0].exit_line == 4


def test_unknown_text_is_harmless():
    log = policylog.parse("hello\nworld\n")
    assert log.policy_name is None
    assert log.scripts == [] and log.packages == [] and log.mount_failures == []
