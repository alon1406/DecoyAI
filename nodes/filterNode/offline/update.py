"""Update job: download the phishing-domain list safely and store it.

Runs at system startup, at most once every 12 hours. It never raises for an
expected failure: the old data stays and the report says why.

Safety rules (the feed is untrusted data):
- The ONLY network requests are to the two fixed URLs in SOURCES (the list file
  and its published checksum). download() is the only function that touches the
  network, and nothing read from a feed is ever passed to it.
- Every line of the feed is treated as plain text. It is only checked and
  normalized with string operations; no listed domain is ever opened, resolved
  or visited.
- HTTPS only, certificate verification always on, time limit, size limit,
  no redirect to another host.
- The file is verified against the published sha256 checksum, then checked for
  sanity, and only then written to the database, in one transaction.
- Feed domains are never printed or logged (only counts).
tests/test_update.py checks these rules.

Manual run (from nodes/filterNode):  python -m offline.update --force
"""
import argparse
import hashlib
import re
import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

from phishfilter import db
from phishfilter.domains import normalize_domain
from phishfilter.lists import is_excluded


@dataclass(frozen=True)
class Source:
    name: str           # stored in the "source" column, e.g. "phishing_database"
    url: str            # the list file (HTTPS only)
    checksum_url: str   # the published sha256 of that file
    ttl_days: int       # how long a domain stays without being seen again


SOURCES = (
    Source(
        name="phishing_database",
        # The project's official GitHub copy (plain text, one domain per line).
        # phish.co.za returned 503 on the first real run (20.11), see CLAUDE.md.
        url="https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
            "refs/heads/master/phishing-domains-ACTIVE.txt",
        # Exists (checked 20.11); whether it matches this file is confirmed by the real run.
        checksum_url="https://raw.githubusercontent.com/Phishing-Database/checksums/"
                     "refs/heads/master/phishing-domains-ACTIVE.txt.sha256",
        ttl_days=30,
    ),
)

UPDATE_EVERY = timedelta(hours=12)       # at most one download per 12 hours
MAX_FEED_BYTES = 50 * 1024 * 1024        # 50 MB
MAX_CHECKSUM_BYTES = 1024                # a checksum file is tiny
TIMEOUT = (10, 60)                       # seconds: (connect, read)
MAX_REDIRECTS = 3
MIN_KEEP_RATIO = 0.5                     # a new list under half the last one is suspicious
MAX_LINE_LENGTH = 300

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "filter.db"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class FeedError(Exception):
    """The feed could not be used. The old data is kept."""


# --- Download (the only network access in the whole Filter) ---

def _require_https(url: str) -> None:
    if urlparse(url).scheme != "https":
        raise FeedError("only https is allowed")


def download(url: str, dest: Path, max_bytes: int) -> None:
    """Download url to dest. HTTPS only, certificate checked, size and time limited.

    Redirects are followed by hand, only to the same host and only over HTTPS.
    """
    for _ in range(MAX_REDIRECTS + 1):
        _require_https(url)
        with requests.get(url, stream=True, timeout=TIMEOUT,
                          verify=True, allow_redirects=False) as resp:
            if resp.is_redirect:
                target = urljoin(url, resp.headers.get("Location", ""))
                if urlparse(target).hostname != urlparse(url).hostname:
                    raise FeedError("redirect to a different host refused")
                url = target
                continue
            resp.raise_for_status()
            size = 0
            with open(dest, "wb") as out:
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    size += len(chunk)
                    if size > max_bytes:
                        raise FeedError("file is larger than the limit")
                    out.write(chunk)
            return
    raise FeedError("too many redirects")


# --- Checksum ---

def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(64 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_expected_sha256(path: Path) -> str:
    """The checksum file holds the hex digest, maybe followed by a file name."""
    words = path.read_text(encoding="ascii", errors="replace").split()
    expected = words[0].lower() if words else ""
    if not _SHA256.match(expected):
        raise FeedError("checksum file is not valid")
    return expected


# --- Parsing (text only, no network) ---

def parse_feed(path: Path) -> set[str]:
    """Return the clean, valid, non-excluded domains in a downloaded list file.

    Each line is plain text. Comments, blank lines, over-long lines, anything that
    is not a valid domain (URLs, IP addresses, odd characters) and shared-hosting /
    free-mail domains are skipped.
    """
    domains: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", "!")) or len(line) > MAX_LINE_LENGTH:
                continue
            domain = normalize_domain(line)
            if not domain or is_excluded(domain):
                continue
            domains.add(domain)
    return domains


def check_sanity(domains: set[str], previous_count: int | None) -> None:
    if not domains:
        raise FeedError("the list is empty")
    if previous_count and len(domains) < previous_count * MIN_KEEP_RATIO:
        raise FeedError("the list shrank to less than half of the last run")


# --- The full update ---

@dataclass
class UpdateReport:
    updated: bool                 # True only if new data was stored now
    last_update: str | None       # last successful update time (for limitations)
    stored: int = 0
    removed: int = 0
    error: str = ""               # why the update failed, if it did


def _parse_time(text: str | None) -> datetime | None:
    try:
        return datetime.strptime(text, _TIME_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _fetch_source(conn, source: Source, tmp: Path, fetch) -> set[str]:
    feed, checksum = tmp / "feed.txt", tmp / "feed.sha256"
    fetch(source.url, feed, MAX_FEED_BYTES)
    fetch(source.checksum_url, checksum, MAX_CHECKSUM_BYTES)
    if sha256_of(feed) != read_expected_sha256(checksum):
        raise FeedError("checksum does not match")
    domains = parse_feed(feed)
    check_sanity(domains, db.last_count(conn, source.name))
    return domains


def run_update(conn: sqlite3.Connection, now: datetime | None = None,
               force: bool = False, fetch=download) -> UpdateReport:
    """Download, verify, parse and store every source. Never raises for expected failures.

    Skips the download if the last successful update is less than 12 hours old
    (unless force=True). On any failure the database is left exactly as it was.
    `fetch` is replaced by a fake in the tests, so they never use the network.
    """
    now = now or datetime.now(timezone.utc)
    previous = db.last_update(conn)
    previous_time = _parse_time(previous)
    if not force and previous_time and now - previous_time < UPDATE_EVERY:
        return UpdateReport(updated=False, last_update=previous)
    try:
        batches = []
        with tempfile.TemporaryDirectory() as tmp:
            for source in SOURCES:
                domains = _fetch_source(conn, source, Path(tmp), fetch)
                batches.append((source.name, domains, source.ttl_days))
        stored, removed = db.store_update(conn, batches, now)
    except (FeedError, requests.RequestException, OSError, sqlite3.Error, ValueError) as exc:
        return UpdateReport(updated=False, last_update=previous,
                            error=type(exc).__name__ + ": " + str(exc))
    return UpdateReport(True, db.last_update(conn), stored, removed)


# --- Manual run ---

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Update the local phishing-domain list.")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="path to the SQLite file")
    parser.add_argument("--force", action="store_true", help="ignore the 12-hour rule")
    args = parser.parse_args(argv)

    conn = db.connect(args.db)
    try:
        report = run_update(conn, force=args.force)
        active = len(db.load_active(conn))
    finally:
        conn.close()

    # Counts only. Feed domains are never printed.
    print("updated:      ", report.updated)
    print("last update:  ", report.last_update)
    print("stored now:   ", report.stored)
    print("removed now:  ", report.removed)
    print("active total: ", active)
    if report.error:
        print("error:        ", report.error)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
