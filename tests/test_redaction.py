from jamfdoctor.redaction import redact


def test_redacts_hosts_users_emails_ips_urls():
    text = (
        "server='print-01.example.org' console='jdoe' user=jsmith "
        "Submitting log to https://jamf.example.org:8443/ ip 10.1.2.3 "
        "mail jdoe@example.org home /Users/jdoe/Desktop for user \"jdoe\""
    )
    out = redact(text)
    assert "print-01.example.org" not in out and "[REDACTED_HOST]" in out
    assert "console='[REDACTED_USER]'" in out
    assert "user=[REDACTED_USER]" in out
    assert "[REDACTED_URL]" in out and "8443" not in out
    assert "[REDACTED_IP]" in out
    assert "[REDACTED_EMAIL]" in out
    assert "/Users/[REDACTED_USER]/Desktop" in out
    assert 'for user "[REDACTED_USER]"' in out


def test_redacts_yaml_doubled_single_quotes_from_snapshots():
    out = redact("server=''print-01.example.org'' console=''fs25-someone'' auth=''negotiate''")
    assert "fs25-someone" not in out
    assert "console=''[REDACTED_USER]''" in out
    assert "[REDACTED_HOST]" in out


def test_redaction_is_idempotent_and_deterministic():
    text = "console='jdoe' at 10.0.0.5 on host.example.org"
    once = redact(text)
    assert redact(once) == once
    assert redact(text) == once
