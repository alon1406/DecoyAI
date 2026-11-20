"""SQLite storage of known-phishing domains.

Security rules (feed data is untrusted):
- Every SQL statement is a fixed constant defined below. No query is built at
  run time (no f-strings, no .format(), no % and no string concatenation).
- Every value (domain, source, dates) is passed only through '?' parameters,
  so SQLite always treats it as plain data, never as a command.
- Domain and source are validated before they reach the database.
- executescript() runs only our own schema file from the repo, never outside text.
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


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _fmt(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    if not isinstance(source, str) or not _SOURCE.match(source):
        return False
    if not isinstance(ttl_days, int) or ttl_days <= 0:
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
