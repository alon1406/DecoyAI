"""SQLite storage of known-phishing domains.

Security rules (feed data is untrusted):
- Every SQL statement is a fixed constant defined below. No query is built at
  run time (no f-strings, no .format(), no % and no string concatenation).
- Every value (domain, source, dates) is passed only through '?' parameters,
  so SQLite always treats it as plain data, never as a command.
- Domain and source are validated before they reach the database.
- executescript() runs only our own schema file from the repo, never outside text.
- store_update() writes a whole update in one transaction: all of it, or nothing.
tests/test_db.py checks these rules, including by reading this file's source.
"""
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from phishfilter.domains import normalize_domain

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "data" / "schema.sql"

# A source name: lowercase letters, digits and underscore only (e.g. "openphish", "analyst").
_SOURCE = re.compile(r"^[a-z0-9_]{1,40}$")

# --- The only SQL statements in this module (fixed text, '?' for every value) ---
_SQL_UPSERT = """
    INSERT INTO indicators (domain, source, first_seen, expires_at)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (domain, source)
    DO UPDATE SET expires_at = excluded.expires_at
"""
_SQL_DELETE_EXPIRED = "DELETE FROM indicators WHERE expires_at <= ?"
_SQL_LOAD_ACTIVE = "SELECT domain, source FROM indicators WHERE expires_at > ?"
_SQL_SET_FEED_STATE = """
    INSERT INTO feed_state (source, last_count, updated_at) VALUES (?, ?, ?)
    ON CONFLICT (source)
    DO UPDATE SET last_count = excluded.last_count, updated_at = excluded.updated_at
"""
_SQL_GET_LAST_COUNT = "SELECT last_count FROM feed_state WHERE source = ?"
_SQL_GET_LAST_UPDATE = "SELECT MAX(updated_at) FROM feed_state"  # takes no values


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _valid_source(source) -> bool:
    return isinstance(source, str) and bool(_SOURCE.match(source))


def _valid_ttl(ttl_days) -> bool:
    return isinstance(ttl_days, int) and ttl_days > 0


def connect(path: str | Path) -> sqlite3.Connection:
    """Open the database and create the table if it does not exist."""
    conn = sqlite3.connect(str(path))
    # Trusted text only: our own schema file from the repo.
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    return conn


def insert(conn: sqlite3.Connection, domain: str, source: str,
           ttl_days: int, now: datetime | None = None) -> bool:
    """Add a domain, or refresh its expiry if it is already there.

    Returns False (and stores nothing) if the domain or source is invalid.
    """
    domain = normalize_domain(domain)
    if not domain:
        return False
    if not _valid_source(source) or not _valid_ttl(ttl_days):
        return False
    now = now or _now()
    conn.execute(
        _SQL_UPSERT,
        (domain, source, _fmt(now), _fmt(now + timedelta(days=ttl_days))),
    )
    conn.commit()
    return True


def delete_expired(conn: sqlite3.Connection, now: datetime | None = None) -> int:
    """Remove expired records. Returns how many were removed."""
    cur = conn.execute(_SQL_DELETE_EXPIRED, (_fmt(now or _now()),))
    conn.commit()
    return cur.rowcount


def load_active(conn: sqlite3.Connection,
                now: datetime | None = None) -> list[tuple[str, str]]:
    """Return (domain, source) for every record that has not expired."""
    rows = conn.execute(_SQL_LOAD_ACTIVE, (_fmt(now or _now()),))
    return list(rows)


def store_update(conn: sqlite3.Connection, batches,
                 now: datetime) -> tuple[int, int]:
    """Write a whole update in ONE transaction: all of it, or nothing.

    batches: list of (source, domains, ttl_days).
    Every domain is normalized again here (defence in depth); invalid ones are dropped.
    New domains are added, known ones get a new expiry, expired records are removed,
    and feed_state records how many domains were stored and when.
    Returns (domains stored, expired records removed).
    """
    stamp = _fmt(now)
    stored = 0
    try:
        for source, domains, ttl_days in batches:
            if not _valid_source(source) or not _valid_ttl(ttl_days):
                raise ValueError("invalid source or ttl")
            expires = _fmt(now + timedelta(days=ttl_days))
            clean = {normalize_domain(d) for d in domains} - {""}
            conn.executemany(_SQL_UPSERT, [(d, source, stamp, expires) for d in clean])
            conn.execute(_SQL_SET_FEED_STATE, (source, len(clean), stamp))
            stored += len(clean)
        removed = conn.execute(_SQL_DELETE_EXPIRED, (stamp,)).rowcount
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return stored, removed


def last_count(conn: sqlite3.Connection, source: str) -> int | None:
    """How many domains the last successful update stored for source, or None."""
    row = conn.execute(_SQL_GET_LAST_COUNT, (source,)).fetchone()
    return row[0] if row else None


def last_update(conn: sqlite3.Connection) -> str | None:
    """Time of the last successful update (UTC text), or None if there was none."""
    return conn.execute(_SQL_GET_LAST_UPDATE).fetchone()[0]
