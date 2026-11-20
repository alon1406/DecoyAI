import pytest

from phishfilter.domains import normalize_domain


def test_lowercase_and_strip_spaces():
    assert normalize_domain("  Evil.COM  ") == "evil.com"


def test_removes_trailing_dot():
    assert normalize_domain("evil.com.") == "evil.com"


def test_removes_leading_www():
    assert normalize_domain("www.evil.com") == "evil.com"


def test_keeps_other_subdomains():
    assert normalize_domain("mail.evil.com") == "mail.evil.com"


def test_all_cleanups_together():
    assert normalize_domain("  WWW.Evil.COM. ") == "evil.com"


def test_works_with_country_domains():
    assert normalize_domain("PayPal.co.il") == "paypal.co.il"


def test_international_name_becomes_punycode():
    assert normalize_domain("bücher.example") == "xn--bcher-kva.example"


def test_same_result_for_different_spellings():
    assert normalize_domain("EVIL.com") == normalize_domain("www.evil.com.")


@pytest.mark.parametrize("bad", [
    "",
    "   ",
    ".",
    "localhost",              # no dot
    "not a domain",           # space inside
    "evil.com/login",         # a URL, not a domain
    "http://evil.com",        # has a scheme
    "user@evil.com",          # an address, not a domain
    "evil.com:8080",          # has a port
    "-evil.com",              # label starts with a hyphen
    "evil..com",              # empty label
    "1.2.3.4",                # IP address
    "evil.com\x00",           # control character
    "a" * 64 + ".com",        # label too long
    ("a" * 60 + ".") * 5 + "com",  # whole name too long
])
def test_bad_input_returns_empty(bad):
    assert normalize_domain(bad) == ""


@pytest.mark.parametrize("not_text", [None, 123, ["evil.com"], b"evil.com"])
def test_non_string_returns_empty(not_text):
    assert normalize_domain(not_text) == ""
