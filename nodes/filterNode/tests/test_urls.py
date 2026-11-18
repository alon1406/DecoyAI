import pytest

from phishfilter.urls import normalize_url, host_of, registered_domain


# ---- the same link written in different ways must give the same value ----

def test_case_www_fragment_trailing_slash_are_ignored():
    a = normalize_url("https://WWW.Evil.com/Login/#x")
    b = normalize_url("http://evil.com/Login")
    assert a == b == "evil.com/Login"


def test_query_string_is_removed():
    assert normalize_url("https://evil.com/a?utm_source=mail&id=7") == "evil.com/a"


def test_port_and_user_info_are_removed():
    assert normalize_url("http://user:pw@evil.com:8080/a") == "evil.com/a"


def test_path_case_is_preserved():
    assert normalize_url("http://evil.com/Login") == "evil.com/Login"


def test_url_without_scheme():
    assert normalize_url("evil.com/login") == "evil.com/login"
    assert normalize_url("//evil.com/login") == "evil.com/login"


def test_root_url_has_no_trailing_slash():
    assert normalize_url("https://evil.com/") == "evil.com"


def test_internationalized_domain_becomes_punycode():
    assert normalize_url("http://Bücher.de/x") == "xn--bcher-kva.de/x"


# ---- redirect wrappers ----

def test_outlook_safelinks_is_unwrapped():
    wrapped = ("https://eur01.safelinks.protection.outlook.com/"
               "?url=https%3A%2F%2Fevil.com%2Flogin&data=abc&reserved=0")
    assert normalize_url(wrapped) == "evil.com/login"


def test_google_redirect_is_unwrapped():
    assert normalize_url("https://www.google.com/url?q=https://evil.com/x&sa=D") == "evil.com/x"


def test_normal_google_link_is_not_unwrapped():
    assert normalize_url("https://www.google.com/search?q=cats") == "google.com/search"


def test_nested_wrappers_are_unwrapped():
    inner = "https://www.google.com/url?q=https://evil.com/x"
    outer = "https://eur01.safelinks.protection.outlook.com/?url=" + inner.replace(":", "%3A").replace("/", "%2F").replace("?", "%3F").replace("=", "%3D")
    assert normalize_url(outer) == "evil.com/x"


def test_wrapper_loop_does_not_crash():
    loop = "https://google.com/url?q=https://google.com/url?q=https://google.com/url?q=https://google.com/url?q=https://evil.com"
    assert isinstance(normalize_url(loop), str)


# ---- bad input must never crash ----

@pytest.mark.parametrize("bad", ["", "   ", "http://", "http://[bad", "http://a\x00b.com", "\n", None, 123])
def test_bad_input_returns_empty_string(bad):
    assert normalize_url(bad) == ""


# ---- helpers ----

def test_host_of():
    assert host_of("evil.com/a/b") == "evil.com"
    assert host_of("evil.com") == "evil.com"


def test_registered_domain():
    assert registered_domain("login.secure.evil.co.uk") == "evil.co.uk"
    assert registered_domain("mail.evil.co.il") == "evil.co.il"
    assert registered_domain("a.b.example.com") == "example.com"


def test_registered_domain_of_ip_is_the_ip():
    assert registered_domain("192.168.0.1") == "192.168.0.1"


def test_registered_domain_works_offline_for_shared_hosting():
    assert registered_domain("user.github.io") == "user.github.io"
