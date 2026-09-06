# jamfdoctor

Local, deterministic, evidence-first diagnostics for Jamf Pro. Paste a policy log or
export a policy as JSON, and jamfdoctor tells you which known failure pattern it
matched, quotes the exact lines, and names the next read-only check. It never
talks to a Jamf Pro server, never uploads anything, and gives the same answer for
the same input every time.

It is the Jamf counterpart to [SAM Doctor](https://github.com/jakegold1647/sam-doctor)
and follows the same rules: a supported finding beats a guess, every finding cites
its evidence, and when nothing matches it says so instead of inventing a cause.

## Install

```
python -m pip install -e ".[dev]"
jamfdoctor demo
```

Python 3.10 or newer, no third-party runtime dependencies.

## Use

```
jamfdoctor diagnose policy.log                 # a log copied from a policy's Logs tab
jamfdoctor diagnose - < policy.log             # from stdin
jamfdoctor diagnose policy.log --redact        # scrub hosts, users, emails, IPs, URLs first
jamfdoctor diagnose policy.log --format json   # text (default), markdown, or json
jamfdoctor policy policy-82.json               # a policy exported from the Classic API
jamfdoctor rules                               # the catalog
```

`diagnose` accepts the log as plain text, or as the accessibility-tree snapshot a
browser automation tool produces when it captures the log's Details view in Jamf
Pro (lines that start with `- `, with the log in `cell "..."` nodes). Snapshots are
detected by shape and unwrapped before parsing; the report says so in its header.

The demo is a sanitized real case: a laptop that checked in from home, could not
mount the file-share distribution point, and then watched two scripts fail for
that one reason.

```
jamfdoctor: 3 findings in demo: dp-mount-failed.log (policy log)

1. Distribution point could not be mounted [JD001, high confidence]
   Jamf could not mount the file-share distribution point "File Share", so no package in this policy was installed on this run.
   Evidence:
     line 3: Could not mount distribution point "File Share"
   ...
2. Script failed after the distribution point mount failed [JD002, high confidence]
   ... treat this as a consequence, not a separate bug.
3. Script deferred itself for a later run [JD011, high confidence]
   ...
```

## Rules

Policy-log rules read the text the Jamf binary writes. A rule that explains a
script failure claims that script, so a later, more generic rule does not report
it twice.

| Rule | Confidence | Matches |
|---|---|---|
| JD001 | high | `Could not mount distribution point` |
| JD011 | high | A script exited 10 and its output says why it wants a retry |
| JD002 | high | A non-zero script exit after a mount failure in the same run |
| JD012 | high | A failed script whose output says `command not found` or `No such file` |
| JD010 | medium | Any remaining non-zero script exit |
| JD020 | high | A package could not be found on the distribution point |
| JD021 | high | `Installation failed` or an installer error |
| JD030 | high | JSS connection, communication, or device-signature errors |
| JD040 | info | Everything installed and every script exited 0 |
| JD050 | info | An error is mentioned but no rule recognizes it |

Policy-export rules read a policy's JSON (Classic API shape, or the inner object).

| Rule | Confidence | Flags |
|---|---|---|
| JC001 | high | Policy disabled |
| JC002 | medium | No trigger and not in Self Service |
| JC003 | medium | Once per computer/user with retry off |
| JC004 | low | Retry set on a recurring frequency, where Jamf ignores it |
| JC005 | medium | Packages on each computer's default distribution point with no network-segment limit |
| JC006 | low | A script with priority Before alongside packages |
| JC007 | low | No payload |
| JC040 | info | Nothing to flag |

## Determinism

- No timestamps, hostnames, or environment details are added to output.
- Findings sort by first evidence line, then rule id.
- JSON output has sorted keys.
- `python scripts/check.py` runs ruff, pytest, and renders the demo twice to prove
  the bytes match. CI should run the same command.

## Boundaries

- Input is text you already have. jamfdoctor does not hold credentials and does not
  call the Jamf Pro API. A read-only API mode is a possible later addition and would
  be a separate, explicit command.
- Redaction is best effort. Read the output before sharing a log outside your team.
- Fixtures in `tests/fixtures` and the demo are sanitized: example hosts, example
  users, vendor-neutral package names. Keep them that way.

## Adding a rule

1. Add a sanitized log that shows the pattern to `tests/fixtures`.
2. Add a rule function in `src/jamfdoctor/rules.py` and register it in `RULES` in the
   position that gives it the right precedence.
3. Add a test in `tests/test_rules.py` asserting the exact rule ids and evidence lines.
4. Run `python scripts/check.py`.
