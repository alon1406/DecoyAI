import time
from datetime import datetime, timedelta, timezone

import pytest

from phishfilter import db
from phishfilter.filter import Filter
from phishfilter.schemas import ParsedEmail

LAST_UPDATE = "2026-11-20T10:00:00Z"


def make_filter(*domains, source="phishing_database"):
    """A Filter built by hand from a small list (no database, no network)."""
    return Filter([(d, source) for d in domains], LAST_UPDATE)


def run_check(the_filter, sender_domain):
    return the_filter.check(ParsedEmail(sender_domain=sender_domain))


# --- The seven cases the plan requires ---

def test_exact_listed_domain_is_phishing():
    result = run_check(make_filter("evil.com"), "evil.com")
    assert result.decision == "phishing"
    assert result.sources == ["phishing_database"]
    assert "evil.com" in result.findings[0]


def test_subdomain_of_listed_domain_is_phishing():
    result = run_check(make_filter("evil.com"), "mail.evil.com")
    assert result.decision == "phishing"
    assert "matches listed phishing domain evil.com" in result.findings[0]


def test_no_match_is_not_detected():
    result = run_check(make_filter("evil.com"), "good.com")
    assert result.decision == "not_detected"
    assert result.findings == [] and result.sources == []


def test_only_longer_subdomain_listed_is_not_detected():
    assert run_check(make_filter("login.bad.net"), "bad.net").decision == "not_detected"


def test_free_mail_sender_is_not_detected():
    result = run_check(make_filter("gmail.com"), "gmail.com")
    assert result.decision == "not_detected"
    assert any("free mail or shared hosting" in note for note in result.limitations)


def test_shared_hosting_sender_is_not_detected():
    result = run_check(make_filter("x.github.io"), "x.github.io")
    assert result.decision == "not_detected"
    assert any("free mail or shared hosting" in note for note in result.limitations)


@pytest.mark.parametrize("bad", ["", "   ", "not a domain", "1.2.3.4", "evil", None])
def test_empty_or_invalid_sender_is_not_detected(bad):
    result = run_check(make_filter("evil.com"), bad)
    assert result.decision == "not_detected"
    assert any("empty or invalid" in note for note in result.limitations)


# --- Registered-domain rule, normalization and limitations ---

def test_public_suffix_in_list_never_matches():
    assert run_check(make_filter("co.il"), "good.co.il").decision == "not_detected"


def test_subdomain_with_country_suffix_is_phishing():
    result = run_check(make_filter("evil.co.il"), "a.evil.co.il")
    assert result.decision == "phishing"
    assert "evil.co.il" in result.findings[0]


def test_uppercase_and_trailing_dot_are_normalized():
    assert run_check(make_filter("evil.com"), "MAIL.Evil.com.").decision == "phishing"


def test_domain_from_two_sources_reports_both():
    the_filter = Filter([("evil.com", "phishing_database"), ("evil.com", "analyst")], LAST_UPDATE)
    assert run_check(the_filter, "evil.com").sources == ["analyst", "phishing_database"]


@pytest.mark.parametrize("sender", ["evil.com", "good.com", "gmail.com", ""])
def test_checked_and_limitations_are_always_filled(sender):
    result = run_check(make_filter("evil.com"), sender)
    assert result.checked == ["sender domain against the local phishing-domain list"]
    assert any("only the sender domain is checked" in note for note in result.limitations)
    assert any(LAST_UPDATE in note for note in result.limitations)


def test_list_never_downloaded_is_reported():
    result = run_check(Filter([], None), "a.com")
    assert result.decision == "not_detected"
    assert any("never downloaded" in note for note in result.limitations)


# --- Building from the database ---

def test_from_db_loads_active_domains_and_last_update():
    conn = db.connect(":memory:")
    now = datetime.now(timezone.utc)
    db.store_update(conn, [("phishing_database", {"evil.com"}, 30)], now)
    db.insert(conn, "old.com", "analyst", 1, now=now - timedelta(days=5))  # already expired
    the_filter = Filter.from_db(conn)
    conn.close()
    assert run_check(the_filter, "evil.com").decision == "phishing"
    assert run_check(the_filter, "old.com").decision == "not_detected"
    assert any(db._fmt(now) in note for note in run_check(the_filter, "a.com").limitations)


# --- Speed ---

def test_lookup_takes_less_than_a_millisecond():
    the_filter = make_filter(*(f"d{i}.com" for i in range(361_000)))
    emails = [ParsedEmail(sender_domain=f"mail.x{i}.com") for i in range(1000)]
    start = time.perf_counter()
    for email in emails:
        the_filter.check(email)
    per_check = (time.perf_counter() - start) / len(emails)
    assert per_check < 0.001
