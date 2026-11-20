import ast
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from phishfilter import db
from phishfilter.db import connect, insert, delete_expired, load_active

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def conn():
    c = connect(":memory:")
    yield c
    c.close()


def _count(conn):
    return conn.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]


# --- The three tests the plan requires ---

def test_insert_and_load(conn):
    assert insert(conn, "Evil.com", "phishing_database", 30, now=NOW)
    assert load_active(conn, now=NOW) == [("evil.com", "phishing_database")]


def test_expired_entry_is_not_loaded(conn):
    insert(conn, "evil.com", "openphish", 30, now=NOW)
    later = NOW + timedelta(days=31)
    assert load_active(conn, now=later) == []


def test_duplicate_insert_does_not_duplicate(conn):
    insert(conn, "evil.com", "openphish", 30, now=NOW)
    insert(conn, "evil.com", "openphish", 30, now=NOW + timedelta(days=10))
    assert _count(conn) == 1


# --- Extra behaviour tests ---

def test_duplicate_insert_refreshes_expiry_and_keeps_first_seen(conn):
    insert(conn, "evil.com", "openphish", 30, now=NOW)
    insert(conn, "evil.com", "openphish", 30, now=NOW + timedelta(days=20))
    # day 40: the first expiry (day 30) passed, the refreshed one (day 50) did not
    assert load_active(conn, now=NOW + timedelta(days=40)) == [("evil.com", "openphish")]
    first_seen = conn.execute("SELECT first_seen FROM indicators").fetchone()[0]
    assert first_seen == "2026-11-20T12:00:00Z"


def test_same_domain_from_two_sources_is_two_rows(conn):
    insert(conn, "evil.com", "openphish", 30, now=NOW)
    insert(conn, "evil.com", "analyst", 180, now=NOW)
    assert len(load_active(conn, now=NOW)) == 2


def test_delete_expired(conn):
    insert(conn, "old.com", "openphish", 1, now=NOW)
    insert(conn, "new.com", "openphish", 30, now=NOW)
    removed = delete_expired(conn, now=NOW + timedelta(days=2))
    assert removed == 1
    assert load_active(conn, now=NOW + timedelta(days=2)) == [("new.com", "openphish")]


@pytest.mark.parametrize("bad_ttl", [0, -5, "30", None])
def test_invalid_ttl_is_refused(conn, bad_ttl):
    assert insert(conn, "evil.com", "openphish", bad_ttl, now=NOW) is False
    assert _count(conn) == 0


# --- Security tests ---

INJECTIONS = [
    "evil.com'; DROP TABLE indicators;--",
    "evil.com\"); DELETE FROM indicators;--",
    "x' OR '1'='1",
]


@pytest.mark.parametrize("bad", ["", "not a domain", "192.168.0.1", *INJECTIONS])
def test_invalid_or_malicious_domain_is_refused(conn, bad):
    insert(conn, "keep.com", "openphish", 30, now=NOW)
    assert insert(conn, bad, "openphish", 30, now=NOW) is False
    # the table still exists and still holds exactly the one good row
    assert load_active(conn, now=NOW) == [("keep.com", "openphish")]


@pytest.mark.parametrize("bad_source", ["", "Open Phish", "a" * 41, None, *INJECTIONS])
def test_invalid_or_malicious_source_is_refused(conn, bad_source):
    insert(conn, "keep.com", "openphish", 30, now=NOW)
    assert insert(conn, "evil.com", bad_source, 30, now=NOW) is False
    assert load_active(conn, now=NOW) == [("keep.com", "openphish")]


def test_db_module_never_builds_sql_from_strings():
    """Guard for the future: reads the code of db.py (not its comments) and fails
    if any query could be built from text at run time."""
    tree = ast.parse(Path(db.__file__).read_text(encoding="utf-8"))

    # 1. Every execute() call gets a fixed _SQL_ constant as its query.
    execute_calls = [n for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and n.func.attr == "execute"]
    assert execute_calls, "expected execute() calls in db.py"
    for call in execute_calls:
        query = call.args[0]
        assert isinstance(query, ast.Name) and query.id.startswith("_SQL_"), \
            f"line {call.lineno}: execute() must use a _SQL_ constant"

    # 2. No string building anywhere in the module: no f-strings, no .format(),
    #    no '%' formatting and no '+' on text.
    for node in ast.walk(tree):
        assert not isinstance(node, ast.JoinedStr), f"line {node.lineno}: f-string"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr != "format", f"line {node.lineno}: .format()"
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
            sides = (node.left, node.right)
            assert not any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in sides), \
                f"line {node.lineno}: text built with % or +"

    # 3. Each _SQL_ constant is plain fixed text that takes its values through '?'.
    sql_constants = [n for n in tree.body if isinstance(n, ast.Assign)
                     and n.targets[0].id.startswith("_SQL_")]
    assert len(sql_constants) == 3
    for assign in sql_constants:
        assert isinstance(assign.value, ast.Constant) and isinstance(assign.value.value, str)
        assert "?" in assign.value.value
