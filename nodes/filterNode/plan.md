# Filter Component — Implementation Plan

Final project: multi-agent phishing detection (Afeka). Component owner: Alon.
Status legend: `[ ]` not started · `[x]` done. Work one stage at a time; a stage is done only when its tests pass.

## 1. Goal

A fast, local pre-check that runs **after the Parser and before the Round 1 agents**.
It looks up the email's links, sender and attachment hashes in known-phishing lists.

- `hard_hit` -> classify as Phishing immediately (template explanation, no LLM, no agents)
- `soft_hit` -> continue to agents, pass the finding on as evidence
- `no_hit`   -> continue to agents, pass on "checked, nothing found"

Rules that never change:
- [ ] The Filter only shortcuts toward "Phishing". `no_hit` is never "Legitimate".
- [ ] No allowlist ever shortcuts toward "Legitimate".
- [ ] The Filter never reads the email body (immune to prompt injection).
- [ ] No data from the email is sent to any external service (NFR 4.4.1).

## 2. Decisions already made

- Built first on Alon's own computer, integrated into the main project later.
- The Parser does not exist yet. Daniel builds it in parallel.
- Stack: Python, SQLite, `tldextract`, `requests`, `pytest` (all free / open source).
- Sources: Phishing.Database (MIT) + OpenPhish Community Feed. URLhaus optional later. PhishTank is not used (registration closed).

## 3. Interface agreed with Daniel (Parser output)

The Filter needs only these fields from the Parser:

- [ ] `urls: list[str]` — all links, taken from `<a href>` and plain text
- [ ] `sender_address: str` — real sender address (not the display name)
- [ ] `attachment_hashes: list[tuple[str, str]]` — `(filename, sha256)`
- [ ] Daniel confirmed he will return these three fields
- [ ] Adapter function written if his field names differ

## 4. Stages

### Stage 0 — Skeleton and contracts
- [x] Create project folder and structure (`phishfilter/`, `offline/`, `data/`, `tests/`)
- [ ] (Alon, on Windows) create a virtual environment and run `pip install -r requirements.txt`
- [x] `schemas.py`: `ParsedEmail` (minimal) and `FilterResult` (decision, findings, sources, checked, limitations)
- [x] Test: a `ParsedEmail` and a `FilterResult` can be created by hand
- **Done when:** `pytest` runs and the schema tests pass

### Stage 1 — URL normalization
- [x] `normalize_url(url) -> "host/path"`: lowercase, remove `www.`, remove fragment and query, strip trailing `/`
- [x] Unwrap redirect links (Outlook SafeLinks, `google.com/url?q=`)
- [x] `registered_domain(host)` using `tldextract` (works for `.co.il`, `.co.uk`)
- [x] Handle bad input without crashing (empty string, no scheme, weird characters)
- [x] Tests for every case above
- **Done when:** `https://WWW.Evil.com/Login/#x` and `http://evil.com/Login` return the same value

### Stage 2 — Database
- [ ] `data/schema.sql`: table `indicators(value, type, source, first_seen, expires_at)`, primary key `(value, type, source)`, index on `(type, value)`
- [ ] Functions: `insert`, `delete_expired`, `load_active`
- [ ] All SQL uses `?` parameters only (never string formatting)
- [ ] Tests: insert and fetch, expired entry is not loaded, duplicate insert does not duplicate
- **Done when:** DB tests pass

### Stage 3 — Update job (safe download)
- [ ] Confirm the exact feed URLs on each project's official page before using them
- [ ] Download function with the safety rules from section 5
- [ ] Per-line validation and parsing (skip comments and bad lines)
- [ ] Normalize every URL with the **same** `normalize_url`, store as `url` and as `host`
- [ ] Insert with refresh of `expires_at` when a record appears again; TTL 30 days (analyst records: 180)
- [ ] Remove expired records at the end of each run
- [ ] Sample feed files for tests (no network needed)
- [ ] Tests: good feed, empty feed, shrunk feed, corrupted lines, running twice
- [ ] Manual first real run on the local machine
- **Done when:** a real run fills the DB with thousands of rows, and a second run adds no duplicates

### Stage 4 — Filter class
- [ ] Load active rows into in-memory dicts at startup
- [ ] `check(email) -> FilterResult` with match order: full URL -> host -> registered domain -> sender -> file hash
- [ ] Rules: full URL / normal host / sender / file hash = hard; shared hosting or domain-only = soft
- [ ] `SHARED_HOSTING` list (`github.io`, `sites.google.com`, `blogspot.com`, `netlify.app`, `vercel.app`, `azurewebsites.net`)
- [ ] Fill `checked` and `limitations` (list update date) even when nothing is found
- [ ] Tests: hard hit, soft hit (shared hosting), soft hit (domain only), no hit, sender hit, file-hash hit
- **Done when:** all six test cases pass and a lookup takes milliseconds

### Stage 5 — Integration (after Daniel's Parser exists)
- [ ] `FILTER = Filter()` loaded once at system startup
- [ ] Orchestrator: Parser -> Filter; on `hard_hit` return the template decision
- [ ] `decision_from_template`: Hebrew explanation built from `findings` and `sources`
- [ ] On soft / no hit, pass `filter_result` to the Verification agent and the Supervisor
- [ ] End-to-end test: email with a listed link is stopped; a normal email continues
- **Done when:** both end-to-end cases behave correctly

### Stage 6 — Analyst path
- [ ] `add_from_analyst(email)`: add links and sender with `source='analyst'`, TTL 180 days
- [ ] Test: an analyst-confirmed email is stopped on the next run

### Stage 7 — Measurement
- [ ] Take a snapshot of the lists dated **before** the emails in the test set (avoids data leakage)
- [ ] Run the system with and without the Filter on the same test set
- [ ] Record: % of emails stopped, LLM calls saved, latency p50 / p95, precision / recall / false-positive rate
- [ ] Fill the comparison table for the report

## 5. Safe download rules (apply in Stage 3)

Principle: the feed is untrusted data. Read it as text; never open or visit any URL in it.

- [ ] HTTPS only, certificate verification on (never disable it), request timeout set
- [ ] Maximum download size enforced
- [ ] Do not follow redirects to a different host
- [ ] Download to a temporary file first; touch the database only after validation passes
- [ ] Validate every line: scheme is `http`/`https`, sane length, no control characters; drop bad lines
- [ ] Sanity check: if the feed is empty or much smaller than the previous run, ignore it and keep the old data
- [ ] Verify checksums where the source provides them (Phishing.Database publishes them on GitHub)
- [ ] Parameterized SQL only
- [ ] Do not update more often than every 6-12 hours (OpenPhish refreshes about twice a day)
- [ ] Never log feed URLs as clickable links
- [ ] Optional later: very popular domains (e.g. from the Tranco top list) are always `soft`, never `hard`, to protect against feed mistakes

## 6. Final checklist (project level)

- [ ] All stage tests pass
- [ ] Filter never classifies anything as Legitimate
- [ ] Short path is documented for the supervisor and added to the change table in the initiation document
- [ ] Measurement table is filled
- [ ] Report states clearly that the lists are an external source and what our contribution is (pipeline, hard/soft rules, analyst path, measurement)
