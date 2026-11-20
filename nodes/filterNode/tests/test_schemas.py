from phishfilter.schemas import ParsedEmail, FilterResult


def test_parsed_email_can_be_created_by_hand():
    m = ParsedEmail(sender_domain="evil.com")
    assert m.sender_domain == "evil.com"


def test_parsed_email_default_is_empty():
    assert ParsedEmail().sender_domain == ""


def test_filter_result_defaults():
    r = FilterResult(decision="not_detected")
    assert r.decision == "not_detected"
    assert r.findings == [] and r.sources == [] and r.checked == [] and r.limitations == []


def test_filter_result_lists_are_independent():
    a = FilterResult(decision="phishing")
    b = FilterResult(decision="phishing")
    a.findings.append("x")
    assert b.findings == []
