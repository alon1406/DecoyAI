"""The Filter: a fast, local check of the sender domain (Stage 4).

The active phishing domains are loaded into memory once, at startup.
Each email is then checked in milliseconds, without any network call.
Exactly two outcomes: "phishing" or "not_detected" (never "legitimate").
"""
import sqlite3

import tldextract

from phishfilter import db
from phishfilter.domains import normalize_domain
from phishfilter.lists import is_excluded
from phishfilter.schemas import FilterResult, ParsedEmail

# Offline extractor: uses the bundled public-suffix list, never the network.
_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

CHECKED = "sender domain against the local phishing-domain list"
SCOPE = "only the sender domain is checked, not links, attachments or the body"


def _registered(domain: str) -> str:
    """'mail.evil.co.il' -> 'evil.co.il'. Unknown suffix -> the domain itself."""
    parts = _extract(domain)
    if hasattr(parts, "top_domain_under_public_suffix"):
        registered = parts.top_domain_under_public_suffix
    else:
        registered = parts.registered_domain
    return registered or domain


class Filter:
    def __init__(self, rows, last_update: str | None):
        """rows: (domain, source) pairs, as returned by db.load_active."""
        self._sources: dict[str, set[str]] = {}
        for domain, source in rows:
            self._sources.setdefault(domain, set()).add(source)
        self._last_update = last_update

    @classmethod
    def from_db(cls, conn: sqlite3.Connection) -> "Filter":
        """Build the Filter once at startup from the local database."""
        return cls(db.load_active(conn), db.last_update(conn))

    def check(self, email: ParsedEmail) -> FilterResult:
        """Look up the sender domain. Never raises, never reads anything else."""
        result = FilterResult(decision="not_detected", checked=[CHECKED],
                              limitations=self._limitations())
        domain = normalize_domain(email.sender_domain)
        if not domain:
            result.limitations.append("sender domain is empty or invalid, so it was not checked")
            return result
        if is_excluded(domain):
            result.limitations.append(f"{domain} is free mail or shared hosting, so it never counts")
            return result
        listed = self._find(domain)
        if listed:
            result.decision = "phishing"
            result.findings.append(f"sender domain {domain} matches listed phishing domain {listed}")
            result.sources = sorted(self._sources[listed])
        return result

    def _find(self, domain: str) -> str | None:
        """The listed domain that equals domain or is a parent of it, else None.

        Walks up one label at a time and stops at the registered domain,
        so a public suffix such as 'co.il' can never match.
        """
        stop = _registered(domain)
        candidate = domain
        while True:
            if candidate in self._sources:
                return candidate
            if candidate == stop or "." not in candidate:
                return None
            candidate = candidate.split(".", 1)[1]

    def _limitations(self) -> list[str]:
        if self._last_update is None:
            return [SCOPE, "the phishing-domain list was never downloaded, so the list is empty"]
        return [SCOPE, f"phishing-domain list last updated {self._last_update} (UTC)"]
