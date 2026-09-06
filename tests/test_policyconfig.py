import json
from pathlib import Path

from jamfdoctor import policyconfig

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_fleet_policy_flags_default_distribution_point_only():
    findings = policyconfig.check(load("policy-fleet.json"))
    assert [f.rule_id for f in findings] == ["JC005"]
    assert "Vendor_IM_C4510_Driver.pkg" in findings[0].summary
    assert findings[0].related == ["JD001"]


def test_neglected_policy_flags_everything_in_id_order():
    findings = policyconfig.check(load("policy-neglected.json"))
    assert [f.rule_id for f in findings] == ["JC001", "JC002", "JC003", "JC005", "JC006"]


def test_recurring_with_retry_is_low_confidence_note():
    data = load("policy-fleet.json")
    data["policy"]["general"]["retry_event"] = "check-in"
    data["policy"]["general"]["retry_attempts"] = 3
    findings = policyconfig.check(data)
    assert [f.rule_id for f in findings] == ["JC004", "JC005"]


def test_network_segment_limitation_silences_dp_warning():
    data = load("policy-fleet.json")
    data["policy"]["scope"]["limitations"]["network_segments"] = [{"id": 1, "name": "Campus"}]
    assert [f.rule_id for f in policyconfig.check(data)] == ["JC040"]


def test_inner_policy_object_and_missing_fields_are_fine():
    assert [f.rule_id for f in policyconfig.check({"general": {"name": "x"}})] == ["JC002", "JC007"]
    assert [f.rule_id for f in policyconfig.check({})] == ["JC040"]
