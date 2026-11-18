from phishfilter.schemas import ParsedEmail, FilterResult


def test_parsed_email_can_be_created_by_hand():
    m = ParsedEmail(
        urls=["http://evil.com/login"],
        sender_address="a@evil.com",
        attachment_hashes=[("invoice.pdf", "ab" * 32)],
    )
    assert m.urls == ["http://evil.com/login"]
    assert m.attachment_hashes[0][0] == "invoice.pdf"


def test_parsed_email_defaults_are_independent():
    a, b = ParsedEmail(), ParsedEmail()
    a.urls.append("x")
    assert b.urls == []


def test_filter_result_defaults():
    r = FilterResult(decision="no_hit")
    assert r.decision == "no_hit"
    assert r.findings == [] and r.sources == [] and r.checked == [] and r.limitations == []
