# Filter Component — Implementation Plan

Final project: multi-agent phishing detection (Afeka). Component owner: Alon.
Status legend: `[ ]` not started · `[x]` done. Work one stage at a time; a stage is done only when its tests pass.

## 1. Goal

A fast, local pre-check that runs **after the Parser and before the Round 1 agents**.
It looks up **only the domain the email was sent from** (`sender_domain`) in a list of known-phishing domains. It does not check links or attachments.

The Filter has exactly **two outcomes**:

- `phishing`     -> classify as Phishing immediately (template explanation, no LLM, no agents)
- `not_detected` -> continue to the agents, pass on "checked, nothing found"

A weak match (the listed domain is only a sub-part of the sender, shared hosting, free-mail domain) does **not** stop an email. It counts as `not_detected`, so the agents decide.

Rules that never change:
- [ ] Only two outcomes: `phishing` or `not_detected`. There is no "soft" result.
- [ ] The Filter only shortcuts toward "Phishing". `not_detected` is never "Legitimate".
- [ ] No allowlist ever shortcuts toward "Legitimate".
- [ ] The Filter never reads the email body, links or attachments. Its only input is `sender_domain` (immune to prompt injection).
- [ ] No data from the email is sent to any external service (NFR 4.4.1).

## 2. Decisions already made

- Built first on Alon's own computer, integrated into the main project later.
- The Parser does not exist yet. Daniel builds it in parallel.
- Stack: Python, SQLite, `tldextract`, `requests`, `pytest` (all free / open source).
- Sources: Phishing.Database (MIT) + OpenPhish Community Feed. URLhaus optional later. PhishTank is not used (registration closed).
- (20.11) The Parser gives the Filter the **domain the email was sent from** (`sender_domain`), not the full sender address.
- (20.11) The Filter has only two outcomes: phishing detected, or not detected (then the agents run).
- (20.11) The Filter checks **only the sender domain**. Links and file hashes are not checked by the Filter (the agents still receive them from the Parser).
- (20.11) The feeds (Phishing.Database, OpenPhish) list phishing *websites*. We take the domain of each listed site and compare it to the sender domain. Expect a low hit rate (many phishing emails come from other domains), so the saving may be small. Stage 7 measures it.

## 3. Interface agreed with Daniel (Parser output)

The Filter needs only one field from the Parser:

- [ ] `sender_domain: str` — the domain the email was sent from, lowercase (e.g. `evil.com`)
- [ ] Daniel confirmed he will return this field, and which header it comes from (`From`, or the real sending server)
- [ ] Adapter function written if his field name differs

## 4. Stages

### Stage 0 — Skeleton and contracts
- [x] Create project folder and structure (`phishfilter/`, `offline/`, `data/`, `tests/`)
- [ ] (Alon, on Windows) create a virtual environment and run `pip install -r requirements.txt`
- [x] `schemas.py`: `ParsedEmail` (minimal) and `FilterResult` (decision, findings, sources, checked, limitations)
- [x] Test: a `ParsedEmail` and a `FilterResult` can be created by hand
- [x] (20.11 change) `ParsedEmail`: keep only `sender_domain: str` (remove `sender_address`, `urls`, `attachment_hashes`), update its test
- [x] (20.11 change) `FilterResult.decision` becomes `"phishing" | "not_detected"` (remove `hard_hit` / `soft_hit` / `no_hit`), update its test
- **Done when:** `pytest` runs and the schema tests pass

### Stage 1 — URL and domain normalization
- [x] `normalize_url(url) -> "host/path"`: lowercase, remove `www.`, remove fragment and query, strip trailing `/`
- [x] Unwrap redirect links (Outlook SafeLinks, `google.com/url?q=`)
- [x] `registered_domain(host)` using `tldextract` (works for `.co.il`, `.co.uk`)
- [ ] (20.11 change) `normalize_domain(value) -> str`: lowercase, strip spaces and trailing dot, convert to punycode, return `""` for bad input (used on `sender_domain` and on feed domains)
- [ ] (20.11 change) Tests for `normalize_domain`
- [x] Handle bad input without crashing (empty string, no scheme, weird characters)
- [x] Tests for every case above
- **Done when:** `https://WWW.Evil.com/Login/#x` and `http://evil.com/Login` return the same value

### Stage 2 — Database
- [ ] `data/schema.sql`: table `indicators(domain, source, first_seen, expires_at)`, primary key `(domain, source)`. One kind of record only: a phishing domain
- [ ] Functions: `insert`, `delete_expired`, `load_active`
- [ ] All SQL uses `?` parameters only (never string formatting)
- [ ] Tests: insert and fetch, expired entry is not loaded, duplicate insert does not duplicate
- **Done when:** DB tests pass

### Stage 3 — Update job (safe download)
- [ ] Confirm the exact feed URLs on each project's official page before using them
- [ ] Download function with the safety rules from section 5
- [ ] Per-line validation and parsing (skip comments and bad lines)
- [ ] Domain lists: normalize each line with `normalize_domain`. URL lists (OpenPhish): take the host with `normalize_url` + `host_of`, then store it as a domain
- [ ] Skip hosts that are in `SHARED_HOSTING` / `FREE_MAIL` (they would never count)
- [ ] Insert with refresh of `expires_at` when a record appears again; TTL 30 days (analyst records: 180)
- [ ] Remove expired records at the end of each run
- [ ] Sample feed files for tests (no network needed)
- [ ] Tests: good feed, empty feed, shrunk feed, corrupted lines, running twice
- [ ] Manual first real run on the local machine
- **Done when:** a real run fills the DB with thousands of rows, and a second run adds no duplicates

### Stage 4 — Filter class
- [ ] Load active rows into in-memory dicts at startup
- [ ] `check(email) -> FilterResult`: normalize `sender_domain`, then look it up
- [ ] Rule: the result is `phishing` only if the sender domain is in the list exactly, or is a sub-domain of a listed domain (`mail.evil.com` when `evil.com` is listed). Anything else is `not_detected`
- [ ] The reverse is weak and ignored: sender `evil.com` when only `login.evil.com` is listed (`not_detected`). This is a tuning point, to be measured in Stage 7
- [ ] `SHARED_HOSTING` list (`github.io`, `sites.google.com`, `blogspot.com`, `netlify.app`, `vercel.app`, `azurewebsites.net`)
- [ ] `FREE_MAIL` list (`gmail.com`, `outlook.com`, `hotmail.com`, `yahoo.com`, `icloud.com`). A sender domain in `SHARED_HOSTING` / `FREE_MAIL` never counts as a hit
- [ ] Fill `checked` and `limitations` (list update date) even when nothing is found
- [ ] Tests: phishing for an exact listed domain; phishing for a sub-domain of a listed domain
- [ ] Tests: not_detected when nothing matches, when only a longer sub-domain is listed, when the sender is free mail, when the sender is shared hosting, when `sender_domain` is empty or invalid
- **Done when:** all seven test cases pass and a lookup takes milliseconds

### Stage 5 — Integration (after Daniel's Parser exists)
- [ ] `FILTER = Filter()` loaded once at system startup
- [ ] Orchestrator: Parser -> Filter; on `phishing` return the template decision
- [ ] `decision_from_template`: Hebrew explanation built from `findings` and `sources`
- [ ] On `not_detected`, pass `filter_result` (what was checked + limitations) to the Verification agent and the Supervisor
- [ ] End-to-end test: email from a listed sender domain is stopped; a normal email continues
- **Done when:** both end-to-end cases behave correctly

### Stage 6 — Analyst path
- [ ] `add_from_analyst(email)`: add the sender domain with `source='analyst'`, TTL 180 days
- [ ] Refuse to add a domain from `FREE_MAIL` / `SHARED_HOSTING` (it would never count anyway)
- [ ] Test: an analyst-confirmed email is stopped on the next run

### Stage 7 — Measurement
- [ ] Take a snapshot of the lists dated **before** the emails in the test set (avoids data leakage)
- [ ] Run the system with and without the Filter on the same test set
- [ ] Also measure how many phishing emails in the test set are stopped by sender domain alone (expected to be low)
- [ ] Record: % of emails stopped, LLM calls saved, latency p50 / p95, precision / recall / false-positive rate
- [ ] Fill the comparison table for the report

## 5. Safe download rules (apply in Stage 3)

Principle: the feed is untrusted data. Read it as text; never open or visit any URL in it.

- [ ] HTTPS only, certificate verification on (never disable it), request timeout set
- [ ] Maximum download size enforced
- [ ] Do not follow redirects to a different host
- [ ] Download to a temporary file first; touch the database only after validation passes
- [ ] Validate every line: URL lines have scheme `http`/`https`; domain lines are a valid host name; sane length, no control characters; drop bad lines
- [ ] Sanity check: if the feed is empty or much smaller than the previous run, ignore it and keep the old data
- [ ] Verify checksums where the source provides them (Phishing.Database publishes them on GitHub)
- [ ] Parameterized SQL only
- [ ] Do not update more often than every 6-12 hours (OpenPhish refreshes about twice a day)
- [ ] Never log feed URLs as clickable links
- [ ] Optional later: very popular domains (e.g. from the Tranco top list) never count as a hit (the email goes to the agents), to protect against feed mistakes

## 6. Final checklist (project level)

- [ ] All stage tests pass
- [ ] Filter never classifies anything as Legitimate
- [ ] Short path is documented for the supervisor and added to the change table in the initiation document
- [ ] Measurement table is filled
- [ ] Report states clearly that the lists are an external source and what our contribution is (pipeline, hit rules, analyst path, measurement), and that the Filter checks the sender domain only
