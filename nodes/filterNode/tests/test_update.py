"""Tests for the update job (Stage 3). No test uses the network.

Most tests replace the download with FakeFetch, a tiny in-memory "server" that
records every URL it is asked for and fails on any URL it does not know.
The download() tests replace requests.get with FakeGet in the same spirit.
"""
import ast
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import pytest
import requests

from offline import update
from offline.update import FeedError, download, parse_feed, run_update
from phishfilter import db
from phishfilter.lists import is_excluded

NOW = datetime(2026, 11, 20, 8, 0, tzinfo=timezone.utc)
SOURCE = update.SOURCES[0]
DATA = Path(__file__).parent / "data"
GOOD_FEED = (DATA / "feed_good.txt").read_bytes()
GOOD_DOMAINS = {"evil-bank.example", "paypa1-login.example",
                "secure.evil-bank.example", "fakegmail.example"}


def checksum_file(content: bytes) -> bytes:
    return (hashlib.sha256(content).hexdigest() + "  phishing-domains-ACTIVE.txt\n").encode()


class FakeFetch:
    """Stands in for download(): serves fixed bytes per URL and records every request."""

    def __init__(self, feed: bytes, checksum: bytes | None = None, error: Exception | None = None):
        self.files = {SOURCE.url: feed,
                      SOURCE.checksum_url: checksum if checksum is not None else checksum_file(feed)}
        self.error = error
        self.requested: list[str] = []

    def __call__(self, url, dest, max_bytes):
        self.requested.append(url)
        if self.error:
            raise self.error
        assert url in self.files, "the update job asked for a URL that is not a source"
        Path(dest).write_bytes(self.files[url])


@pytest.fixture
def conn():
    c = db.connect(":memory:")
    yield c
    c.close()


def active_domains(conn, now=NOW):
    return {domain for domain, _ in db.load_active(conn, now=now)}


# --- Plan tests ---

def test_good_feed_stores_only_valid_domains(conn):
    report = run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED))
    assert report.updated and report.error == ""
    assert report.stored == len(GOOD_DOMAINS)
    assert report.last_update == "2026-11-20T08:00:00Z"
    assert active_domains(conn) == GOOD_DOMAINS


def test_empty_feed_is_refused_and_old_data_kept(conn):
    run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED))
    later = NOW + timedelta(hours=13)
    report = run_update(conn, now=later, fetch=FakeFetch(b"# nothing here\n\n"))
    assert not report.updated and "empty" in report.error
    assert report.last_update == "2026-11-20T08:00:00Z"
    assert active_domains(conn, later) == GOOD_DOMAINS


def test_shrunk_feed_is_refused_and_old_data_kept(conn):
    run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED))
    later = NOW + timedelta(hours=13)
    report = run_update(conn, now=later, fetch=FakeFetch(b"evil-bank.example\n"))
    assert not report.updated and "shrank" in report.error
    assert active_domains(conn, later) == GOOD_DOMAINS


def test_corrupted_lines_are_skipped_without_crashing(conn):
    feed = b"\xff\xfe\x00garbage\n" + b"x" * 400 + b".example\n" + b"good-one.example\n\x00\x01\n"
    report = run_update(conn, now=NOW, fetch=FakeFetch(feed))
    assert report.updated
    assert active_domains(conn) == {"good-one.example"}


def test_running_twice_adds_no_duplicates(conn):
    run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED))
    report = run_update(conn, now=NOW + timedelta(hours=1), force=True, fetch=FakeFetch(GOOD_FEED))
    assert report.updated
    count = conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
    assert count == len(GOOD_DOMAINS)


def test_update_is_skipped_within_12_hours_without_network(conn):
    run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED))
    fetch = FakeFetch(GOOD_FEED)
    report = run_update(conn, now=NOW + timedelta(hours=1), fetch=fetch)
    assert not report.updated and report.error == ""
    assert report.last_update == "2026-11-20T08:00:00Z"
    assert fetch.requested == []          # no network at all

    report = run_update(conn, now=NOW + timedelta(hours=13), fetch=fetch)
    assert report.updated
    assert fetch.requested == [SOURCE.url, SOURCE.checksum_url]


@pytest.mark.parametrize("error", [requests.ConnectionError("no network"),
                                   requests.Timeout("too slow"),
                                   requests.exceptions.SSLError("bad certificate")])
def test_network_failure_keeps_old_data_and_does_not_raise(conn, error):
    run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED))
    later = NOW + timedelta(hours=13)
    report = run_update(conn, now=later, fetch=FakeFetch(GOOD_FEED, error=error))
    assert not report.updated
    assert type(error).__name__ in report.error
    assert report.last_update == "2026-11-20T08:00:00Z"
    assert active_domains(conn, later) == GOOD_DOMAINS


def test_first_run_with_no_network_reports_no_update(conn):
    report = run_update(conn, now=NOW, fetch=FakeFetch(b"", error=requests.ConnectionError("x")))
    assert not report.updated and report.last_update is None
    assert active_domains(conn) == set()


def test_domain_missing_for_31_days_is_removed(conn):
    run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED))
    smaller = GOOD_FEED.replace(b"fakegmail.example\n", b"")
    later = NOW + timedelta(days=31)
    report = run_update(conn, now=later, fetch=FakeFetch(smaller))
    assert report.updated and report.removed == 1
    assert active_domains(conn, later) == GOOD_DOMAINS - {"fakegmail.example"}


# --- Checksum ---

def test_checksum_mismatch_touches_nothing(conn):
    report = run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED, checksum=checksum_file(b"other")))
    assert not report.updated and "checksum does not match" in report.error
    assert active_domains(conn) == set()
    assert db.last_update(conn) is None


@pytest.mark.parametrize("bad", [b"", b"not-a-hash", b"z" * 64, b"<html>error page</html>"])
def test_invalid_checksum_file_is_refused(conn, bad):
    report = run_update(conn, now=NOW, fetch=FakeFetch(GOOD_FEED, checksum=bad))
    assert not report.updated and "checksum file is not valid" in report.error


# --- Parsing and exclusions ---

def test_parse_feed_never_keeps_urls_ips_or_injections(tmp_path):
    path = tmp_path / "feed.txt"
    path.write_bytes(GOOD_FEED)
    domains = parse_feed(path)
    assert domains == GOOD_DOMAINS
    assert not any(c in d for d in domains for c in ":/?'; ")


@pytest.mark.parametrize("domain, excluded", [
    ("gmail.com", True), ("mail.outlook.com", True), ("someone.github.io", True),
    ("a.b.netlify.app", True), ("fakegmail.com", False), ("evil-bank.com", False),
    ("github.io.evil.com", False),
])
def test_is_excluded(domain, excluded):
    assert is_excluded(domain) is excluded


# --- Security: no listed link is ever visited ---

class FakeResponse:
    def __init__(self, status=200, body=b"", location=None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self._body = body

    @property
    def is_redirect(self):
        return self.status_code in (301, 302, 303, 307, 308) and "Location" in self.headers

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeGet:
    """Replaces requests.get. Records every URL and its options; knows only given URLs."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url, **kwargs):
        self.calls.append((url, kwargs))
        assert url in self.responses, "a request was made to a URL that is not a source"
        return self.responses[url]

    @property
    def urls(self):
        return [url for url, _ in self.calls]


def test_full_update_requests_only_the_two_source_urls(conn, monkeypatch):
    """Runs the REAL download() on a feed full of domains and URLs.
    The only requests made must be the list file and its checksum."""
    fake = FakeGet({SOURCE.url: FakeResponse(body=GOOD_FEED),
                    SOURCE.checksum_url: FakeResponse(body=checksum_file(GOOD_FEED))})
    monkeypatch.setattr(update.requests, "get", fake)

    report = run_update(conn, now=NOW)            # real download()
    assert report.updated
    assert fake.urls == [SOURCE.url, SOURCE.checksum_url]
    for url in fake.urls:                         # no listed domain appears in any request
        assert not any(domain in url for domain in GOOD_DOMAINS | {"visit-me.example",
                                                                  "never-open-this.example"})


def test_download_uses_safe_request_options(tmp_path, monkeypatch):
    fake = FakeGet({SOURCE.url: FakeResponse(body=b"a.example\n")})
    monkeypatch.setattr(update.requests, "get", fake)
    download(SOURCE.url, tmp_path / "f", 1000)
    _, options = fake.calls[0]
    assert options["verify"] is True             # certificate always checked
    assert options["allow_redirects"] is False   # redirects only by our own rules
    assert options["timeout"] == update.TIMEOUT
    assert options["stream"] is True


@pytest.mark.parametrize("url", ["http://phish.co.za/latest/x.txt", "ftp://phish.co.za/x",
                                 "file:///etc/passwd", "phish.co.za/x"])
def test_download_refuses_non_https_before_any_request(tmp_path, monkeypatch, url):
    fake = FakeGet({})
    monkeypatch.setattr(update.requests, "get", fake)
    with pytest.raises(FeedError, match="https"):
        download(url, tmp_path / "f", 1000)
    assert fake.calls == []


def test_download_refuses_redirect_to_another_host(tmp_path, monkeypatch):
    fake = FakeGet({SOURCE.url: FakeResponse(302, location="https://elsewhere.example/feed.txt")})
    monkeypatch.setattr(update.requests, "get", fake)
    with pytest.raises(FeedError, match="different host"):
        download(SOURCE.url, tmp_path / "f", 1000)
    assert fake.urls == [SOURCE.url]              # the other host was never contacted


def test_download_refuses_redirect_to_http(tmp_path, monkeypatch):
    same_host_http = "http://" + urlparse(SOURCE.url).hostname + "/latest/x.txt"
    fake = FakeGet({SOURCE.url: FakeResponse(302, location=same_host_http)})
    monkeypatch.setattr(update.requests, "get", fake)
    with pytest.raises(FeedError, match="https"):
        download(SOURCE.url, tmp_path / "f", 1000)
    assert fake.urls == [SOURCE.url]


def test_download_follows_redirect_on_the_same_host(tmp_path, monkeypatch):
    moved = "https://" + urlparse(SOURCE.url).hostname + "/latest/moved.txt"
    fake = FakeGet({SOURCE.url: FakeResponse(301, location="/latest/moved.txt"),
                    moved: FakeResponse(body=b"a.example\n")})
    monkeypatch.setattr(update.requests, "get", fake)
    download(SOURCE.url, tmp_path / "f", 1000)
    assert fake.urls == [SOURCE.url, moved]
    assert (tmp_path / "f").read_bytes() == b"a.example\n"


def test_download_stops_after_too_many_redirects(tmp_path, monkeypatch):
    fake = FakeGet({SOURCE.url: FakeResponse(302, location=SOURCE.url)})
    monkeypatch.setattr(update.requests, "get", fake)
    with pytest.raises(FeedError, match="too many redirects"):
        download(SOURCE.url, tmp_path / "f", 1000)
    assert len(fake.calls) == update.MAX_REDIRECTS + 1


def test_download_stops_when_file_is_too_large(tmp_path, monkeypatch):
    fake = FakeGet({SOURCE.url: FakeResponse(body=b"x" * 5000)})
    monkeypatch.setattr(update.requests, "get", fake)
    with pytest.raises(FeedError, match="larger than the limit"):
        download(SOURCE.url, tmp_path / "f", 1000)


def test_download_raises_on_http_error(tmp_path, monkeypatch):
    fake = FakeGet({SOURCE.url: FakeResponse(404)})
    monkeypatch.setattr(update.requests, "get", fake)
    with pytest.raises(requests.HTTPError):
        download(SOURCE.url, tmp_path / "f", 1000)


def test_sources_are_https_only():
    for source in update.SOURCES:
        assert source.url.startswith("https://")
        assert source.checksum_url.startswith("https://")


def test_only_the_update_job_can_use_the_network():
    """Code-reading guard: no Filter module may import a network library, and in
    offline/update.py requests.get is called in exactly one place (download)."""
    root = Path(__file__).resolve().parent.parent
    network = {"requests", "urllib.request", "http.client", "socket", "urllib3",
               "httpx", "aiohttp", "ftplib", "smtplib"}
    update_file = root / "offline" / "update.py"
    for path in list((root / "phishfilter").glob("*.py")) + list((root / "offline").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {alias.name for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        allowed = {"requests"} if path == update_file else set()
        assert not (imported & network) - allowed, f"{path.name} imports a network library"

    tree = ast.parse(update_file.read_text(encoding="utf-8"))
    gets = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == "get"
            and isinstance(n.func.value, ast.Name) and n.func.value.id == "requests"]
    assert len(gets) == 1
    owner = next(f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                 and any(g is n for n in ast.walk(f) for g in gets))
    assert owner.name == "download"
