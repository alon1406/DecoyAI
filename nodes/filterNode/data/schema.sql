-- Known-phishing domains. One kind of record only: a phishing domain.
-- Dates are UTC text in the form 2026-11-20T12:00:00Z (text order = time order).

CREATE TABLE IF NOT EXISTS indicators (
    domain      TEXT NOT NULL,
    source      TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    PRIMARY KEY (domain, source)
);

CREATE INDEX IF NOT EXISTS idx_indicators_expires ON indicators (expires_at);

-- State of the last successful update of each source:
-- how many domains were stored (for the sanity check) and when (for the 12-hour rule).
CREATE TABLE IF NOT EXISTS feed_state (
    source      TEXT PRIMARY KEY,
    last_count  INTEGER NOT NULL,
    updated_at  TEXT NOT NULL
);
