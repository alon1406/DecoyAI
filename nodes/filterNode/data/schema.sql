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
